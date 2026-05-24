/// Vault public API — the only component in privox that holds plaintext values.
///
/// The [`Vault`] trait abstracts over the storage backend. In production, [`SqliteVault`]
/// is the only implementation. Tests may use a simple in-memory implementation.
///
/// All `original_value` fields are encrypted at rest; decryption occurs inside
/// the vault implementation and the plaintext never leaves via error messages or logs.
pub mod crypto;
pub mod sqlite;

pub use sqlite::SqliteVault;

use crate::{
    error::VaultError,
    types::{EntityType, Token, TokenRecord},
};

/// The vault stores and retrieves encrypted token-to-value mappings.
///
/// Implementations must be thread-safe (`Send + Sync`) and must never log or
/// return original (pre-tokenization) values except as the return value of [`lookup`].
///
/// [`lookup`]: Vault::lookup
pub trait Vault: Send + Sync {
    /// Persists a token record.
    ///
    /// If a record with the same token already exists it is replaced. This makes
    /// `store` idempotent for the same `(entity_type, original_value)` pair,
    /// since the token is deterministic (HMAC-keyed).
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] on database or encryption failure.
    fn store(&self, record: &TokenRecord) -> Result<(), VaultError>;

    /// Looks up the original value for `token` and returns it decrypted.
    ///
    /// Returns `Ok(None)` if the token is not found or has expired — the caller
    /// must leave the token in the output unchanged in that case.
    ///
    /// # Security
    ///
    /// The returned `String` is the only form in which original values exist
    /// outside the vault. The caller must not log it.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] on database or decryption failure.
    fn lookup(&self, token: &Token) -> Result<Option<String>, VaultError>;

    /// Deletes all entries whose `expires_at` timestamp is in the past.
    ///
    /// Returns the number of entries deleted.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] on database failure.
    fn purge_expired(&self) -> Result<usize, VaultError>;

    /// Returns entry counts grouped by entity type.
    ///
    /// Only non-expired entries are counted.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] on database failure.
    fn stats(&self) -> Result<Vec<(EntityType, usize)>, VaultError>;

    /// Removes all vault entries unconditionally.
    ///
    /// Returns the number of entries removed.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] on database failure.
    fn clear_all(&self) -> Result<usize, VaultError>;
}
