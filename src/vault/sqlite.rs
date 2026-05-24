/// SQLite-backed vault implementation with WAL mode, TTL-based expiry, and AES-256-GCM
/// encryption of all stored values.
///
/// # Thread safety
///
/// `SqliteVault` wraps the `rusqlite::Connection` in a `Mutex` so that it is
/// `Send + Sync`. SQLite in WAL mode supports concurrent readers but serializes
/// writers; the `Mutex` ensures only one thread accesses the connection at a time.
///
/// For v1, blocking vault I/O is acceptable since operations are bounded at < 1ms.
/// Callers in async contexts should wrap vault calls in `tokio::task::spawn_blocking`.
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

use super::{
    crypto::{decrypt, derive_key, encrypt},
    Vault,
};
use crate::{
    error::VaultError,
    types::{EntityType, Token, TokenRecord},
};

/// SQLite-backed vault.
///
/// Stores encrypted token-to-value mappings in a local SQLite database.
/// Values are encrypted with AES-256-GCM before storage; the key is derived
/// from the installation secret via PBKDF2-HMAC-SHA256.
pub struct SqliteVault {
    conn: Mutex<Connection>,
    /// AES-256-GCM encryption key derived from the installation secret.
    ///
    /// # Security
    /// This key must never be logged. It is derived once at construction and
    /// held in memory for the lifetime of the vault.
    key: [u8; 32],
}

impl SqliteVault {
    /// Opens or creates a vault at `path` and initializes the schema.
    ///
    /// WAL mode is enabled immediately after opening the connection. The schema
    /// is created idempotently (`CREATE TABLE IF NOT EXISTS`).
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Open`] if the file cannot be opened, or
    /// [`VaultError::Database`] if WAL mode or schema setup fails.
    pub fn open(path: &Path, secret: &[u8]) -> Result<Self, VaultError> {
        let path_str = path.display().to_string();
        let conn = Connection::open(path).map_err(|e| VaultError::Open {
            path: path_str.clone(),
            source: e,
        })?;

        // WAL mode MUST be set before any reads or writes.
        // Setting it later silently has no effect (rusqlite gotcha).
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\
             PRAGMA foreign_keys=ON;\
             PRAGMA synchronous=NORMAL;",
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS token_mappings (
                token        TEXT NOT NULL PRIMARY KEY,
                entity_type  TEXT NOT NULL,
                enc_value    BLOB NOT NULL,
                session_id   TEXT NOT NULL,
                created_at   INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_expires_at
                ON token_mappings(expires_at);",
        )?;

        let key = derive_key(secret)?;

        Ok(Self {
            conn: Mutex::new(conn),
            key,
        })
    }

    /// Opens an in-memory SQLite database for testing.
    ///
    /// Uses a fixed test secret. Do NOT use in production.
    #[cfg(test)]
    pub fn open_in_memory(secret: &[u8]) -> Result<Self, VaultError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\
             CREATE TABLE IF NOT EXISTS token_mappings (
                token        TEXT NOT NULL PRIMARY KEY,
                entity_type  TEXT NOT NULL,
                enc_value    BLOB NOT NULL,
                session_id   TEXT NOT NULL,
                created_at   INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_expires_at
                ON token_mappings(expires_at);",
        )?;
        let key = derive_key(secret)?;
        Ok(Self {
            conn: Mutex::new(conn),
            key,
        })
    }
}

impl Vault for SqliteVault {
    fn store(&self, record: &TokenRecord) -> Result<(), VaultError> {
        let enc_value = encrypt(&self.key, record.encrypted_value.as_slice())?;
        let conn = self.conn.lock().expect("vault mutex is not poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO token_mappings
                (token, entity_type, enc_value, session_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.token.as_str(),
                record.entity_type.to_storage_str().as_ref(),
                enc_value,
                record.session_id.to_string(),
                record.created_at,
                record.expires_at,
            ],
        )?;
        Ok(())
    }

    fn lookup(&self, token: &Token) -> Result<Option<String>, VaultError> {
        let now = unix_now();
        let conn = self.conn.lock().expect("vault mutex is not poisoned");
        let result = conn.query_row(
            "SELECT enc_value FROM token_mappings
              WHERE token = ?1 AND expires_at > ?2",
            params![token.as_str(), now],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match result {
            Ok(enc_value) => {
                let plaintext = decrypt(&self.key, &enc_value)?;
                let value = String::from_utf8(plaintext).map_err(|e| {
                    VaultError::Decryption(format!("decrypted value is not valid UTF-8: {e}"))
                })?;
                Ok(Some(value))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(VaultError::Database(e)),
        }
    }

    fn purge_expired(&self) -> Result<usize, VaultError> {
        let now = unix_now();
        let conn = self.conn.lock().expect("vault mutex is not poisoned");
        let deleted = conn.execute(
            "DELETE FROM token_mappings WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(deleted)
    }

    fn stats(&self) -> Result<Vec<(EntityType, usize)>, VaultError> {
        let now = unix_now();
        let conn = self.conn.lock().expect("vault mutex is not poisoned");
        let mut stmt = conn.prepare(
            "SELECT entity_type, COUNT(*) as cnt
               FROM token_mappings
              WHERE expires_at > ?1
              GROUP BY entity_type
              ORDER BY entity_type",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            let type_str: String = row.get(0)?;
            let count: usize = row.get(1)?;
            Ok((type_str, count))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let (type_str, count) = row?;
            let entity_type =
                EntityType::from_storage_str(&type_str).unwrap_or(EntityType::Other(type_str));
            result.push((entity_type, count));
        }
        Ok(result)
    }

    fn clear_all(&self) -> Result<usize, VaultError> {
        let conn = self.conn.lock().expect("vault mutex is not poisoned");
        let deleted = conn.execute("DELETE FROM token_mappings", [])?;
        Ok(deleted)
    }
}

/// Returns the current Unix timestamp in seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Token;
    use uuid::Uuid;

    const SECRET: &[u8] = b"test-vault-secret";

    fn make_record(
        token: &str,
        entity_type: EntityType,
        value: &str,
        ttl_secs: i64,
    ) -> TokenRecord {
        let now = unix_now();
        TokenRecord {
            token: Token::new(token),
            entity_type,
            // encrypted_value is the PLAINTEXT here — SqliteVault.store() re-encrypts it.
            // The field name is a misnomer at the TokenRecord level; the vault receives
            // the plaintext as bytes and handles encryption internally.
            encrypted_value: value.as_bytes().to_vec(),
            session_id: Uuid::new_v4(),
            created_at: now,
            expires_at: now + ttl_secs,
        }
    }

    #[test]
    fn store_and_lookup_roundtrip() {
        let vault = SqliteVault::open_in_memory(SECRET).expect("must open");
        let record = make_record(
            "EMAIL_a1b2c3",
            EntityType::Email,
            "test.user@example.com",
            3600,
        );
        vault.store(&record).expect("store must succeed");
        let result = vault
            .lookup(&Token::new("EMAIL_a1b2c3"))
            .expect("lookup must succeed");
        assert_eq!(
            result,
            Some("test.user@example.com".to_string()),
            "lookup must return the stored value"
        );
    }

    #[test]
    fn lookup_unknown_token_returns_none() {
        let vault = SqliteVault::open_in_memory(SECRET).expect("must open");
        let result = vault
            .lookup(&Token::new("EMAIL_notexist"))
            .expect("lookup must not error for unknown token");
        assert!(result.is_none(), "unknown token must return None");
    }

    #[test]
    fn lookup_expired_entry_returns_none() {
        let vault = SqliteVault::open_in_memory(SECRET).expect("must open");
        // expires_at in the past
        let record = make_record("EMAIL_expired", EntityType::Email, "old@example.com", -1);
        vault.store(&record).expect("store must succeed");
        let result = vault
            .lookup(&Token::new("EMAIL_expired"))
            .expect("lookup must not error");
        assert!(result.is_none(), "expired token must return None");
    }

    #[test]
    fn purge_expired_removes_only_expired_entries() {
        let vault = SqliteVault::open_in_memory(SECRET).expect("must open");
        vault
            .store(&make_record(
                "T_alive",
                EntityType::Email,
                "alive@example.com",
                3600,
            ))
            .expect("store must succeed");
        vault
            .store(&make_record(
                "T_dead",
                EntityType::Ssn,
                "dead@example.com",
                -1,
            ))
            .expect("store must succeed");
        let deleted = vault.purge_expired().expect("purge must succeed");
        assert_eq!(deleted, 1, "exactly one expired entry must be purged");
        assert!(
            vault
                .lookup(&Token::new("T_alive"))
                .expect("lookup must succeed")
                .is_some(),
            "live entry must remain after purge"
        );
    }

    #[test]
    fn stats_counts_by_entity_type() {
        let vault = SqliteVault::open_in_memory(SECRET).expect("must open");
        vault
            .store(&make_record(
                "EMAIL_1",
                EntityType::Email,
                "a@example.com",
                3600,
            ))
            .expect("store");
        vault
            .store(&make_record(
                "EMAIL_2",
                EntityType::Email,
                "b@example.com",
                3600,
            ))
            .expect("store");
        vault
            .store(&make_record("SSN_1", EntityType::Ssn, "555-55-5555", 3600))
            .expect("store");
        let stats = vault.stats().expect("stats must succeed");
        let email_count = stats
            .iter()
            .find(|(et, _)| et == &EntityType::Email)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let ssn_count = stats
            .iter()
            .find(|(et, _)| et == &EntityType::Ssn)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        assert_eq!(email_count, 2, "must count 2 EMAIL entries");
        assert_eq!(ssn_count, 1, "must count 1 SSN entry");
    }

    #[test]
    fn clear_all_removes_everything() {
        let vault = SqliteVault::open_in_memory(SECRET).expect("must open");
        vault
            .store(&make_record("T1", EntityType::Email, "x@x.com", 3600))
            .expect("store");
        vault
            .store(&make_record("T2", EntityType::Phone, "555-1234", 3600))
            .expect("store");
        let removed = vault.clear_all().expect("clear must succeed");
        assert_eq!(
            removed, 2,
            "clear_all must report the number of removed entries"
        );
        assert!(
            vault.lookup(&Token::new("T1")).expect("lookup").is_none(),
            "T1 must be gone after clear"
        );
    }

    #[test]
    fn store_is_idempotent_same_token() {
        let vault = SqliteVault::open_in_memory(SECRET).expect("must open");
        let record = make_record("EMAIL_idem", EntityType::Email, "same@example.com", 3600);
        vault.store(&record).expect("first store");
        vault.store(&record).expect("second store (idempotent)");
        let result = vault.lookup(&Token::new("EMAIL_idem")).expect("lookup");
        assert_eq!(result, Some("same@example.com".to_string()));
    }
}
