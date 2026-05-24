/// Token generation and deterministic replacement of detected entities in text.
///
/// The tokenizer is responsible for:
/// 1. Generating stable tokens for detected entities via HMAC-SHA256.
/// 2. Storing token-to-value mappings in the vault.
/// 3. Replacing detected spans in the source text with their tokens.
///
/// # Token stability
///
/// Tokens are deterministic: the same `(entity_type, original_value)` pair always
/// produces the same token for a given installation (keyed by the installation
/// secret). This means a long-running agent will consistently see the same token
/// for the same value across requests and across proxy restarts.
///
/// # Overlap handling
///
/// When detected spans overlap, the tokenizer processes them longest-first.
/// Spans that are fully contained within an already-replaced span are skipped.
/// This is a best-effort policy; the detector pipeline is responsible for
/// deduplication at the span level.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    error::PrivoxError,
    types::{DetectedEntity, EntityType, Token, TokenRecord, TokenizationResult},
    vault::Vault,
};

type HmacSha256 = Hmac<Sha256>;

/// Generates and applies PII tokens for a given text and set of detected entities.
///
/// Holds a reference to the vault for persisting new token-to-value mappings,
/// the installation secret for HMAC-based token ID generation, and the session
/// and TTL configuration for vault entries.
pub struct Tokenizer {
    vault: Arc<dyn Vault>,
    /// Installation secret used as HMAC key for token short-ID generation.
    /// Never logged.
    secret: Vec<u8>,
    /// Session ID stamped on every vault record created in this session.
    session_id: Uuid,
    /// Vault entry TTL in hours.
    ttl_hours: u64,
}

impl Tokenizer {
    /// Creates a new tokenizer.
    ///
    /// # Arguments
    ///
    /// * `vault` — shared vault for persisting token mappings.
    /// * `secret` — the installation secret (used as HMAC key for token IDs).
    /// * `session_id` — UUID for this proxy session, stamped on vault entries.
    /// * `ttl_hours` — how long vault entries should live.
    pub fn new(vault: Arc<dyn Vault>, secret: Vec<u8>, session_id: Uuid, ttl_hours: u64) -> Self {
        Self {
            vault,
            secret,
            session_id,
            ttl_hours,
        }
    }

    /// Generates the stable token for `(entity_type, original_value)`.
    ///
    /// Token format: `{PREFIX}_{shortid}` where `shortid` is the first 3 bytes
    /// (6 hex chars) of HMAC-SHA256(original_value) keyed with the installation
    /// secret. Example: `EMAIL_a3f2c1`.
    ///
    /// This function is deliberately `pub` so that the detokenizer can use the
    /// same algorithm to verify that a string looks like a token.
    pub fn generate_token(entity_type: &EntityType, original_value: &str, secret: &[u8]) -> Token {
        // SAFETY: HMAC accepts keys of any length.
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
        mac.update(original_value.as_bytes());
        let result = mac.finalize().into_bytes();

        // Take the first 3 bytes (6 hex chars) as the short ID.
        // At 6 hex chars (24 bits) the birthday collision probability at 50 entities
        // per session is ~0.01%, acceptable for v1.
        let shortid: String = result[..3].iter().map(|b| format!("{b:02x}")).collect();
        Token::new(format!(
            "{prefix}_{shortid}",
            prefix = entity_type.token_prefix()
        ))
    }

    /// Tokenizes all detected entities in `text`, stores mappings in the vault, and
    /// returns the sanitized text along with the entity types that were replaced.
    ///
    /// # Overlap handling
    ///
    /// Entities are sorted by span length (longest first). When processing each
    /// entity, spans that overlap with an already-replaced region are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`PrivoxError::Vault`] if a vault write fails.
    pub fn tokenize(
        &self,
        text: &str,
        entities: &[DetectedEntity],
    ) -> Result<TokenizationResult, PrivoxError> {
        if entities.is_empty() {
            return Ok(TokenizationResult {
                sanitized: text.to_string(),
                entity_types_found: vec![],
            });
        }

        // Sort: longest spans first so larger matches take precedence over sub-spans.
        let mut sorted: Vec<&DetectedEntity> = entities.iter().collect();
        sorted.sort_unstable_by(|a, b| {
            let len_a = a.end - a.start;
            let len_b = b.end - b.start;
            len_b.cmp(&len_a).then(a.start.cmp(&b.start))
        });

        let now = unix_now();
        let expires_at = now + (self.ttl_hours as i64) * 3600;

        // Track which byte ranges have already been replaced to handle overlaps.
        let mut replaced_ranges: Vec<(usize, usize)> = Vec::new();
        // Collect (start, end, token_string) for later text substitution.
        let mut replacements: Vec<(usize, usize, String)> = Vec::new();
        let mut entity_types_found: Vec<EntityType> = Vec::new();

        for entity in &sorted {
            if is_overlapping(entity.start, entity.end, &replaced_ranges) {
                continue;
            }

            let token =
                Self::generate_token(&entity.entity_type, &entity.original_value, &self.secret);
            let record = TokenRecord {
                token: token.clone(),
                entity_type: entity.entity_type.clone(),
                // The vault's store() method re-encrypts this; we pass the raw bytes here.
                encrypted_value: entity.original_value.as_bytes().to_vec(),
                session_id: self.session_id,
                created_at: now,
                expires_at,
            };

            self.vault.store(&record).map_err(PrivoxError::Vault)?;
            entity_types_found.push(entity.entity_type.clone());
            replaced_ranges.push((entity.start, entity.end));
            replacements.push((entity.start, entity.end, token.0));
        }

        // Apply substitutions from back to front to preserve byte offsets.
        replacements.sort_unstable_by_key(|r| std::cmp::Reverse(r.0));
        let mut sanitized = text.to_string();
        for (start, end, token) in replacements {
            sanitized.replace_range(start..end, &token);
        }

        Ok(TokenizationResult {
            sanitized,
            entity_types_found,
        })
    }
}

/// Returns `true` if `[start, end)` overlaps with any range in `replaced`.
fn is_overlapping(start: usize, end: usize, replaced: &[(usize, usize)]) -> bool {
    replaced.iter().any(|&(rs, re)| start < re && end > rs)
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
    use crate::vault::sqlite::SqliteVault;

    const SECRET: &[u8] = b"test-tokenizer-secret";

    fn make_vault() -> Arc<dyn Vault> {
        Arc::new(SqliteVault::open_in_memory(SECRET).expect("must open in-memory vault"))
    }

    fn make_tokenizer(vault: Arc<dyn Vault>) -> Tokenizer {
        Tokenizer::new(vault, SECRET.to_vec(), Uuid::new_v4(), 24)
    }

    #[test]
    fn generate_token_is_deterministic() {
        let t1 = Tokenizer::generate_token(&EntityType::Email, "test@example.com", SECRET);
        let t2 = Tokenizer::generate_token(&EntityType::Email, "test@example.com", SECRET);
        assert_eq!(t1, t2, "same input must produce same token");
    }

    #[test]
    fn generate_token_differs_by_value() {
        let t1 = Tokenizer::generate_token(&EntityType::Email, "a@example.com", SECRET);
        let t2 = Tokenizer::generate_token(&EntityType::Email, "b@example.com", SECRET);
        assert_ne!(t1, t2, "different values must produce different tokens");
    }

    #[test]
    fn generate_token_differs_by_entity_type() {
        let value = "test@example.com";
        let t1 = Tokenizer::generate_token(&EntityType::Email, value, SECRET);
        let t2 = Tokenizer::generate_token(&EntityType::Person, value, SECRET);
        // Different entity types have different prefixes so tokens will differ.
        assert_ne!(
            t1, t2,
            "different entity types must produce different tokens"
        );
    }

    #[test]
    fn generate_token_has_correct_prefix() {
        let token = Tokenizer::generate_token(&EntityType::Email, "x@x.com", SECRET);
        assert!(
            token.as_str().starts_with("EMAIL_"),
            "EMAIL token must start with 'EMAIL_', got: {token}"
        );
    }

    #[test]
    fn generate_token_shortid_is_6_hex_chars() {
        let token = Tokenizer::generate_token(&EntityType::CreditCard, "4111111111111111", SECRET);
        let parts: Vec<&str> = token.as_str().splitn(2, '_').collect();
        // For CREDIT_CARD the prefix has underscores; we want the last segment.
        let full = token.as_str();
        let last_underscore = full.rfind('_').expect("token must contain underscore");
        let shortid = &full[last_underscore + 1..];
        assert_eq!(
            shortid.len(),
            6,
            "shortid must be 6 hex characters, got: {shortid}"
        );
        assert!(
            shortid.chars().all(|c| c.is_ascii_hexdigit()),
            "shortid must be lowercase hex, got: {shortid}"
        );
        let _ = parts; // avoid unused warning
    }

    #[test]
    fn tokenize_single_entity() {
        let vault = make_vault();
        let tok = make_tokenizer(Arc::clone(&vault));
        let text = "My email is test@example.com please reply";
        let entities = vec![DetectedEntity {
            start: 12,
            end: 29,
            entity_type: EntityType::Email,
            original_value: "test@example.com".to_string(),
        }];
        let result = tok
            .tokenize(text, &entities)
            .expect("tokenize must succeed");
        assert!(
            !result.sanitized.contains("test@example.com"),
            "sanitized text must not contain original email"
        );
        assert!(
            result.sanitized.starts_with("My email is EMAIL_"),
            "token must be in the correct position, got: {}",
            result.sanitized
        );
        assert_eq!(result.entity_types_found, vec![EntityType::Email]);
    }

    #[test]
    fn tokenize_stores_mapping_in_vault() {
        let vault = make_vault();
        let tok = make_tokenizer(Arc::clone(&vault));
        let email = "stored@example.com";
        let entities = vec![DetectedEntity {
            start: 0,
            end: email.len(),
            entity_type: EntityType::Email,
            original_value: email.to_string(),
        }];
        let result = tok.tokenize(email, &entities).expect("must succeed");
        let token = Token::new(result.sanitized.trim().to_string());
        let recovered = vault.lookup(&token).expect("lookup must succeed");
        assert_eq!(
            recovered,
            Some(email.to_string()),
            "vault must return original value for the generated token"
        );
    }

    #[test]
    fn tokenize_empty_entities_returns_original() {
        let vault = make_vault();
        let tok = make_tokenizer(vault);
        let text = "no pii here";
        let result = tok.tokenize(text, &[]).expect("must succeed");
        assert_eq!(
            result.sanitized, text,
            "text without entities must be unchanged"
        );
        assert!(
            result.entity_types_found.is_empty(),
            "entity_types_found must be empty when no entities detected"
        );
    }

    #[test]
    fn tokenize_multiple_entities_back_to_front() {
        let vault = make_vault();
        let tok = make_tokenizer(vault);
        let text = "email: a@b.com phone: 555-1234";
        let entities = vec![
            DetectedEntity {
                start: 7,
                end: 14,
                entity_type: EntityType::Email,
                original_value: "a@b.com".to_string(),
            },
            DetectedEntity {
                start: 22,
                end: 30,
                entity_type: EntityType::PhoneCa,
                original_value: "555-1234".to_string(),
            },
        ];
        let result = tok.tokenize(text, &entities).expect("must succeed");
        assert!(
            !result.sanitized.contains("a@b.com"),
            "email must be replaced"
        );
        assert!(
            !result.sanitized.contains("555-1234"),
            "phone must be replaced"
        );
        assert_eq!(result.entity_types_found.len(), 2);
    }

    #[test]
    fn tokenize_overlapping_prefers_longer_span() {
        let vault = make_vault();
        let tok = make_tokenizer(vault);
        // Overlapping: "555-1234-5678" (full) and "555" (prefix)
        let text = "Call 555-1234-5678 now";
        let entities = vec![
            DetectedEntity {
                start: 5,
                end: 18,
                entity_type: EntityType::PhoneCa,
                original_value: "555-1234-5678".to_string(),
            },
            DetectedEntity {
                start: 5,
                end: 8,
                entity_type: EntityType::PhoneUs,
                original_value: "555".to_string(),
            },
        ];
        let result = tok.tokenize(text, &entities).expect("must succeed");
        // Only the longer span should be tokenized (1 entity type)
        assert_eq!(
            result.entity_types_found.len(),
            1,
            "overlapping spans must be deduplicated to the longest"
        );
        assert!(
            !result.sanitized.contains("555-1234-5678"),
            "full phone number must be replaced"
        );
    }
}
