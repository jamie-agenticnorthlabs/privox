use std::sync::{Arc, OnceLock};

use regex::Regex;
use tracing::warn;

use crate::{error::DetokenizerError, types::Token, vault::Vault};

// ── Token pattern ─────────────────────────────────────────────────────────────

// Matches tokens of the form PREFIX_shortid, e.g. EMAIL_a3f2c1, CREDIT_CARD_7b9e04.
// PREFIX is one or more uppercase words optionally joined by underscores.
// The shortid is exactly 6 lowercase hex characters.
// Word boundaries prevent partial matches inside longer identifiers.
static TOKEN_RE: OnceLock<Regex> = OnceLock::new();

fn token_re() -> &'static Regex {
    TOKEN_RE.get_or_init(|| Regex::new(r"\b[A-Z_]+_[0-9a-f]{6}\b").unwrap())
}

// ── Core substitution logic ───────────────────────────────────────────────────

/// Scans `text` for privox tokens, looks each one up in `vault`, and returns
/// the text with all recognised tokens replaced by their original values.
///
/// If a token has no vault entry (expired TTL, unknown token), it is left
/// unchanged in the output and a warning is logged. The token identifier is
/// logged but the original value is never logged (it is not available here).
///
/// # Errors
///
/// Returns [`DetokenizerError::VaultLookup`] if the vault itself returns an
/// unexpected error (distinct from a normal cache miss, which is handled
/// gracefully as described above).
fn detokenize_text(text: &str, vault: &dyn Vault) -> Result<String, DetokenizerError> {
    let mut output = String::with_capacity(text.len());
    let mut last_end = 0;

    for m in token_re().find_iter(text) {
        output.push_str(&text[last_end..m.start()]);

        let token = Token::new(m.as_str().to_string());
        match vault.lookup(&token)? {
            Some(original) => output.push_str(&original),
            None => {
                // No vault entry: leave the token as-is and warn. Never log the
                // original value — we don't have it, and that's by design.
                warn!(
                    token = %m.as_str(),
                    "token found in response has no vault entry (expired or unknown) \
                     — leaving token unchanged"
                );
                output.push_str(m.as_str());
            }
        }

        last_end = m.end();
    }

    output.push_str(&text[last_end..]);
    Ok(output)
}

/// Returns the largest index ≤ `pos` that is a valid UTF-8 character boundary
/// in `s`. Required because the sliding-window split point may land inside a
/// multi-byte character.
fn floor_char_boundary(s: &str, mut pos: usize) -> usize {
    if pos >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

// ── Detokenizer ───────────────────────────────────────────────────────────────

/// Detokenizes a complete (non-streaming) response text.
///
/// For streaming responses, use [`StreamingDetokenizer`] instead.
pub struct Detokenizer {
    vault: Arc<dyn Vault>,
}

impl Detokenizer {
    pub fn new(vault: Arc<dyn Vault>) -> Self {
        Self { vault }
    }

    /// Detokenize a complete response body.
    pub fn detokenize(&self, text: &str) -> Result<String, DetokenizerError> {
        detokenize_text(text, self.vault.as_ref())
    }

    /// Returns a new [`StreamingDetokenizer`] backed by the same vault.
    pub fn streaming(&self) -> StreamingDetokenizer {
        StreamingDetokenizer::new(Arc::clone(&self.vault))
    }
}

// ── StreamingDetokenizer ──────────────────────────────────────────────────────

/// Minimum bytes retained in the trailing buffer so that a token split across
/// an SSE chunk boundary is always fully buffered before processing.
///
/// The longest possible token is ACCOUNT_NUMBER_xxxxxx = 21 chars. A wider
/// window prevents partial token-looking text from being released when providers
/// split reasoning/content streams into very small chunks.
const WINDOW: usize = 512;

/// Stateful detokenizer for SSE streaming responses.
///
/// Accumulates incoming chunks in an internal buffer. Each call to
/// [`push_chunk`] returns the portion of the stream that is safe to forward
/// (i.e., far enough from the current tail that no token can be split at the
/// boundary). Call [`flush`] when the upstream stream ends to drain the buffer.
///
/// # Example
///
/// ```rust,ignore
/// let mut sd = detokenizer.streaming();
/// for chunk in stream {
///     let safe = sd.push_chunk(&chunk)?;
///     forward(safe);
/// }
/// forward(sd.flush()?);
/// ```
pub struct StreamingDetokenizer {
    vault: Arc<dyn Vault>,
    buffer: String,
}

impl StreamingDetokenizer {
    fn new(vault: Arc<dyn Vault>) -> Self {
        Self {
            vault,
            buffer: String::new(),
        }
    }

    /// Appends `chunk` to the internal buffer and returns the detokenized text
    /// that is safe to forward to the caller.
    ///
    /// Returns an empty string when the buffer has not yet accumulated enough
    /// data to safely process (i.e., when `buffer.len() ≤ WINDOW`).
    pub fn push_chunk(&mut self, chunk: &str) -> Result<String, DetokenizerError> {
        self.buffer.push_str(chunk);

        if self.buffer.len() <= WINDOW {
            return Ok(String::new());
        }

        let split = floor_char_boundary(&self.buffer, self.buffer.len() - WINDOW);
        let safe = self.buffer[..split].to_string();
        self.buffer = self.buffer[split..].to_string();
        detokenize_text(&safe, self.vault.as_ref())
    }

    /// Processes and returns all remaining buffered content.
    ///
    /// Must be called after the upstream stream closes. The buffer is cleared.
    pub fn flush(&mut self) -> Result<String, DetokenizerError> {
        if self.buffer.is_empty() {
            return Ok(String::new());
        }
        let remaining = std::mem::take(&mut self.buffer);
        detokenize_text(&remaining, self.vault.as_ref())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::{EntityType, TokenRecord},
        vault::sqlite::SqliteVault,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn make_vault() -> Arc<dyn Vault> {
        Arc::new(SqliteVault::open_in_memory(b"test-secret").unwrap())
    }

    fn store_token(vault: &Arc<dyn Vault>, token: &str, entity_type: EntityType, value: &str) {
        let now = unix_now();
        vault
            .store(&TokenRecord {
                token: Token::new(token),
                entity_type,
                encrypted_value: value.as_bytes().to_vec(),
                session_id: Uuid::new_v4(),
                created_at: now,
                expires_at: now + 3600,
            })
            .unwrap();
    }

    // ── Detokenizer (non-streaming) ───────────────────────────────────────────

    #[test]
    fn no_tokens_returns_text_unchanged() {
        let vault = make_vault();
        let det = Detokenizer::new(vault);
        let text = "Hello, no PII here.";
        assert_eq!(det.detokenize(text).unwrap(), text);
    }

    #[test]
    fn single_token_substituted() {
        let vault = make_vault();
        store_token(
            &vault,
            "EMAIL_a1b2c3",
            EntityType::Email,
            "user@example.com",
        );
        let det = Detokenizer::new(vault);
        let result = det.detokenize("Contact EMAIL_a1b2c3 for info").unwrap();
        assert_eq!(result, "Contact user@example.com for info");
    }

    #[test]
    fn multiple_tokens_substituted() {
        let vault = make_vault();
        store_token(
            &vault,
            "EMAIL_a1b2c3",
            EntityType::Email,
            "alice@example.com",
        );
        store_token(&vault, "PERSON_d4e5f6", EntityType::Person, "Alice");
        let det = Detokenizer::new(vault);
        let result = det.detokenize("PERSON_d4e5f6 <EMAIL_a1b2c3>").unwrap();
        assert_eq!(result, "Alice <alice@example.com>");
    }

    #[test]
    fn unknown_token_left_unchanged_no_error() {
        let vault = make_vault();
        let det = Detokenizer::new(vault);
        let text = "Value is EMAIL_ffffff which is unknown";
        let result = det.detokenize(text).unwrap();
        assert_eq!(result, text, "unknown token must be left in place");
    }

    #[test]
    fn token_pattern_does_not_match_partial_hex() {
        // 5-char shortid — should NOT be treated as a token
        let vault = make_vault();
        let det = Detokenizer::new(Arc::clone(&vault));
        let text = "EMAIL_a1b2c is not a token";
        assert_eq!(det.detokenize(text).unwrap(), text);
    }

    #[test]
    fn token_pattern_does_not_match_uppercase_shortid() {
        // shortid must be lowercase hex only
        let vault = make_vault();
        let det = Detokenizer::new(vault);
        let text = "EMAIL_A1B2C3 is not a token";
        assert_eq!(det.detokenize(text).unwrap(), text);
    }

    #[test]
    fn credit_card_token_prefix_substituted() {
        let vault = make_vault();
        store_token(
            &vault,
            "CREDIT_CARD_ff0011",
            EntityType::CreditCard,
            "4111111111111111",
        );
        let det = Detokenizer::new(vault);
        let result = det.detokenize("Card: CREDIT_CARD_ff0011").unwrap();
        assert_eq!(result, "Card: 4111111111111111");
    }

    // ── StreamingDetokenizer ──────────────────────────────────────────────────

    #[test]
    fn streaming_small_chunks_buffered_until_window() {
        let vault = make_vault();
        store_token(
            &vault,
            "EMAIL_a1b2c3",
            EntityType::Email,
            "user@example.com",
        );
        let det = Detokenizer::new(vault);
        let mut sd = det.streaming();

        // Chunks are small; buffer won't exceed WINDOW yet.
        let r1 = sd.push_chunk("Hello ").unwrap();
        let r2 = sd.push_chunk("EMAIL_").unwrap();
        assert!(r1.is_empty(), "small chunk should be buffered");
        assert!(r2.is_empty(), "partial token should be buffered");

        // Complete the token; still under WINDOW — stays buffered.
        let r3 = sd.push_chunk("a1b2c3").unwrap();
        assert!(r3.is_empty());

        // Flush drains the buffer with full token present.
        let final_out = sd.flush().unwrap();
        assert_eq!(final_out, "Hello user@example.com");
    }

    #[test]
    fn streaming_token_split_across_chunk_boundary() {
        let vault = make_vault();
        store_token(&vault, "PERSON_cc00ff", EntityType::Person, "Bob");
        let det = Detokenizer::new(vault);
        let mut sd = det.streaming();

        // Pad with enough data to push the safe region past WINDOW, then split
        // the token mid-token across two chunks.
        // Space before the token so the word boundary \b matches at the token start.
        let prefix = "A".repeat(80); // forces safe region to be flushed
        let r1 = sd.push_chunk(&format!("{prefix} PERSON_")).unwrap();
        // The safe portion (prefix minus last 64 bytes) must not contain the
        // partial token.
        assert!(
            !r1.contains("PERSON_"),
            "partial token must not appear in forwarded output"
        );

        let r2 = sd.push_chunk("cc00ff").unwrap();
        let final_out = sd.flush().unwrap();
        let combined = r1 + &r2 + &final_out;
        assert!(
            combined.contains("Bob"),
            "completed token must be detokenized: got {combined:?}"
        );
        assert!(
            !combined.contains("PERSON_cc00ff"),
            "raw token must not appear in output"
        );
    }

    #[test]
    fn streaming_flush_empty_buffer_is_ok() {
        let vault = make_vault();
        let det = Detokenizer::new(vault);
        let mut sd = det.streaming();
        let result = sd.flush().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn streaming_no_tokens_passthrough() {
        let vault = make_vault();
        let det = Detokenizer::new(vault);
        let mut sd = det.streaming();
        // Enough data to exceed the window.
        let big = "The quick brown fox jumps over the lazy dog. ".repeat(5);
        let mut output = sd.push_chunk(&big).unwrap();
        output.push_str(&sd.flush().unwrap());
        assert_eq!(output, big);
    }
}
