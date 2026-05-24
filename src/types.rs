/// Shared types used across all `privox` modules.
///
/// This module defines the core vocabulary of the system:
/// - [`EntityType`] — the PII/sensitive-entity categories the detector recognizes
/// - [`DetectedEntity`] — a span within a text with its entity type and original value
/// - [`TokenRecord`] — the vault's persisted mapping from token to (encrypted) original value
/// - [`Token`] — the stable, readable token string inserted into sanitized prompts
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// All entity types that `privox` can detect and tokenize.
///
/// Regex-based types are always active. NER-based types require an optional backend.
/// `Other` captures entity types reported by Presidio that have no privox equivalent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityType {
    // ── Regex-based (always active) ────────────────────────────────────────
    /// Email address (RFC 5321 simplified pattern).
    Email,
    /// Canadian phone number in common formats (regex-detected, region-specific).
    PhoneCa,
    /// US phone number in common formats (same pattern as CA for v1).
    PhoneUs,
    /// Credit card number (13–19 digits, Luhn-valid).
    CreditCard,
    /// Canadian Social Insurance Number (9-digit, space/dash separated).
    Sin,
    /// US Social Security Number.
    Ssn,
    /// IBAN bank account number.
    Iban,
    /// IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// API key or authentication token (sk-*, Bearer *, ghp_*, xoxb-*, AIza*).
    ApiKey,
    /// URL containing embedded credentials (`https://user:pass@host`).
    UrlWithCredentials,
    /// UUID v4 format string.
    Uuid,

    // ── Optional-backend types (NER or Presidio required) ──────────────────
    /// Person name (detected by NER or Presidio).
    Person,
    /// Organization or company name (detected by NER or Presidio).
    Org,
    /// Location, address, or place name (detected by NER or Presidio).
    Location,
    /// Date of birth in personal context (detected by NER or Presidio).
    DateOfBirth,
    /// Account number identified contextually (detected by NER or Presidio).
    AccountNumber,

    // ── Presidio-specific types (no regex equivalent in privox) ────────────
    /// Generic phone number as reported by Presidio (`PHONE_NUMBER`).
    /// Distinct from `PhoneCa`/`PhoneUs` which are regex-detected with regional patterns.
    Phone,
    /// Generic URL detected by Presidio (`URL`).
    /// Broader than `UrlWithCredentials`; covers any URL regardless of embedded credentials.
    Url,
    /// Date or time value detected by Presidio (`DATE_TIME`).
    DateTime,

    // ── Catch-all for unrecognised Presidio entity types ───────────────────
    /// An entity type reported by Presidio that has no direct privox equivalent.
    ///
    /// The inner string holds the raw Presidio entity type name (e.g. `"NRP"`,
    /// `"MEDICAL_LICENSE"`). This preserves coverage for Presidio entity types that
    /// are not yet formally mapped in privox.
    Other(String),
}

impl EntityType {
    /// Returns the uppercase string prefix used in token generation.
    ///
    /// This prefix appears verbatim in the token, e.g. `EMAIL_a3f2c1`.
    ///
    /// Returns a [`Cow<'static, str>`] so that static variants are zero-copy while
    /// `Other` can produce a dynamic string without a separate allocation path.
    pub fn token_prefix(&self) -> Cow<'static, str> {
        match self {
            EntityType::Email => Cow::Borrowed("EMAIL"),
            EntityType::PhoneCa => Cow::Borrowed("PHONE_CA"),
            EntityType::PhoneUs => Cow::Borrowed("PHONE_US"),
            EntityType::CreditCard => Cow::Borrowed("CREDIT_CARD"),
            EntityType::Sin => Cow::Borrowed("SIN"),
            EntityType::Ssn => Cow::Borrowed("SSN"),
            EntityType::Iban => Cow::Borrowed("IBAN"),
            EntityType::Ipv4 => Cow::Borrowed("IPV4"),
            EntityType::Ipv6 => Cow::Borrowed("IPV6"),
            EntityType::ApiKey => Cow::Borrowed("API_KEY"),
            EntityType::UrlWithCredentials => Cow::Borrowed("URL_CRED"),
            EntityType::Uuid => Cow::Borrowed("UUID"),
            EntityType::Person => Cow::Borrowed("PERSON"),
            EntityType::Org => Cow::Borrowed("ORG"),
            EntityType::Location => Cow::Borrowed("LOCATION"),
            EntityType::DateOfBirth => Cow::Borrowed("DOB"),
            EntityType::AccountNumber => Cow::Borrowed("ACCOUNT"),
            EntityType::Phone => Cow::Borrowed("PHONE"),
            EntityType::Url => Cow::Borrowed("URL"),
            EntityType::DateTime => Cow::Borrowed("DATETIME"),
            EntityType::Other(s) => Cow::Owned(s.to_uppercase()),
        }
    }

    // Will be used by the Presidio detector to filter entity types before querying.
    #[allow(dead_code)]
    /// Returns `true` if this entity type requires an optional detection backend
    /// (NER or Presidio) and is NOT detected by the always-active regex detector.
    pub fn requires_optional_backend(&self) -> bool {
        matches!(
            self,
            EntityType::Person
                | EntityType::Org
                | EntityType::Location
                | EntityType::DateOfBirth
                | EntityType::AccountNumber
                | EntityType::Phone
                | EntityType::Url
                | EntityType::DateTime
                | EntityType::Other(_)
        )
    }

    /// Converts to the string representation used for SQLite vault storage.
    ///
    /// Format is `PREFIX` for known types and `OTHER_TYPENAME` for [`EntityType::Other`].
    /// This is distinct from the serde representation so that vault storage
    /// does not depend on JSON serialization format stability.
    pub fn to_storage_str(&self) -> Cow<'static, str> {
        self.token_prefix()
    }

    /// Parses the SQLite vault storage representation back to an [`EntityType`].
    ///
    /// Returns `None` for strings that cannot be mapped to a known entity type.
    pub fn from_storage_str(s: &str) -> Option<EntityType> {
        EntityType::from_str(s).ok()
    }
}

impl FromStr for EntityType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "EMAIL" => Ok(EntityType::Email),
            "PHONE_CA" => Ok(EntityType::PhoneCa),
            "PHONE_US" => Ok(EntityType::PhoneUs),
            "CREDIT_CARD" => Ok(EntityType::CreditCard),
            "SIN" => Ok(EntityType::Sin),
            "SSN" => Ok(EntityType::Ssn),
            "IBAN" => Ok(EntityType::Iban),
            "IPV4" => Ok(EntityType::Ipv4),
            "IPV6" => Ok(EntityType::Ipv6),
            "API_KEY" => Ok(EntityType::ApiKey),
            "URL_CRED" => Ok(EntityType::UrlWithCredentials),
            "UUID" => Ok(EntityType::Uuid),
            "PERSON" => Ok(EntityType::Person),
            "ORG" => Ok(EntityType::Org),
            "LOCATION" => Ok(EntityType::Location),
            "DOB" => Ok(EntityType::DateOfBirth),
            "ACCOUNT" => Ok(EntityType::AccountNumber),
            "PHONE" => Ok(EntityType::Phone),
            "URL" => Ok(EntityType::Url),
            "DATETIME" => Ok(EntityType::DateTime),
            other => Ok(EntityType::Other(other.to_string())),
        }
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token_prefix().as_ref())
    }
}

/// A detected sensitive entity within a text span.
///
/// The `original_value` field holds the raw matched text and must not be logged.
#[derive(Debug, Clone)]
pub struct DetectedEntity {
    /// Byte offset of the match start in the source text.
    pub start: usize,
    /// Byte offset of the match end (exclusive) in the source text.
    pub end: usize,
    /// The category of the detected entity.
    pub entity_type: EntityType,
    /// The original text that was matched.
    ///
    /// # Security
    /// This value must never be written to logs or error messages. It is passed
    /// directly to the vault for encrypted storage and then discarded.
    pub original_value: String,
}

/// A stable, human-readable token that replaces a detected entity in sanitized text.
///
/// Format: `{PREFIX}_{shortid}`, e.g. `EMAIL_a3f2c1`.
///
/// The `shortid` is the first 6 hex characters of HMAC-SHA256 of the original value,
/// keyed with the installation secret. This makes tokens deterministic per installation
/// and resistant to guessing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token(pub String);

impl Token {
    /// Constructs a new token from its string representation.
    pub fn new(s: impl Into<String>) -> Self {
        Token(s.into())
    }

    /// Returns the token string as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Token> for String {
    fn from(t: Token) -> String {
        t.0
    }
}

/// A complete vault record persisting the mapping between a token and an original value.
///
/// The `encrypted_value` field stores the AES-256-GCM ciphertext. The `original_value`
/// never appears in this struct in plaintext; decryption is performed by `vault::crypto`.
#[derive(Debug, Clone)]
pub struct TokenRecord {
    /// The stable token string (e.g. `EMAIL_a3f2c1`).
    pub token: Token,
    /// The entity type category.
    pub entity_type: EntityType,
    /// AES-256-GCM encrypted original value: `nonce || ciphertext || tag`.
    pub encrypted_value: Vec<u8>,
    /// The session that created this mapping.
    pub session_id: Uuid,
    /// When this record was created (Unix timestamp seconds).
    pub created_at: i64,
    /// When this record expires and can be purged (Unix timestamp seconds).
    pub expires_at: i64,
}

/// A minimal result of tokenizing a single piece of input text.
///
/// Contains the rewritten text (with tokens substituted) and a list of the
/// entity types that were introduced, for audit logging.
/// Original values are never included here.
#[derive(Debug, Clone)]
pub struct TokenizationResult {
    /// The text with all detected entities replaced by their stable tokens.
    pub sanitized: String,
    /// The entity types detected (for debug logging — types only, no values).
    pub entity_types_found: Vec<EntityType>,
}

/// OpenAI-compatible chat message structure (subset used by privox).
///
/// Only the fields that privox needs to inspect or rewrite are represented here.
/// Unknown fields are passed through unchanged via `serde`'s `flatten`.
/// `deny_unknown_fields` is intentionally NOT set for forward-compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// The role of the message author (`system`, `user`, `assistant`, `tool`).
    pub role: String,
    /// The message content (may be null for tool calls with no textual content).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<MessageContent>,
    /// Tool call results, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<serde_json::Value>,
    /// For `tool` role messages, the tool call ID this message is responding to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Preserves any fields not explicitly modelled above.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The content of a chat message, which may be a plain string or a structured array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple string content (most common case).
    Text(String),
    /// Structured content parts (vision, tool results, etc.).
    Parts(Vec<serde_json::Value>),
}

impl MessageContent {
    // Will be used by the server to extract text for detection from multi-part messages.
    #[allow(dead_code)]
    /// Returns all text segments from this content value.
    ///
    /// For `Text`, returns a single-element vec. For `Parts`, collects the `text`
    /// field from all `{"type": "text", "text": "..."}` objects.
    pub fn text_segments(&self) -> Vec<&str> {
        match self {
            MessageContent::Text(s) => vec![s.as_str()],
            MessageContent::Parts(parts) => parts
                .iter()
                .filter_map(|p| {
                    if p.get("type")?.as_str()? == "text" {
                        p.get("text")?.as_str()
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

/// An OpenAI-compatible chat completion request (subset used by privox).
///
/// Non-inspected fields are preserved in `extra` and forwarded unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// The model to use (passed through unchanged).
    pub model: String,
    /// The conversation messages (content fields are tokenized).
    pub messages: Vec<ChatMessage>,
    /// Whether to stream the response.
    #[serde(default)]
    pub stream: bool,
    /// All other fields (temperature, max_tokens, tools, etc.) passed through unchanged.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_type_token_prefix_is_uppercase() {
        let types = [
            EntityType::Email,
            EntityType::PhoneCa,
            EntityType::PhoneUs,
            EntityType::CreditCard,
            EntityType::Sin,
            EntityType::Ssn,
            EntityType::Iban,
            EntityType::Ipv4,
            EntityType::Ipv6,
            EntityType::ApiKey,
            EntityType::UrlWithCredentials,
            EntityType::Uuid,
            EntityType::Person,
            EntityType::Org,
            EntityType::Location,
            EntityType::DateOfBirth,
            EntityType::AccountNumber,
            EntityType::Phone,
            EntityType::Url,
            EntityType::DateTime,
            EntityType::Other("NRP".to_string()),
        ];
        for et in &types {
            let prefix = et.token_prefix();
            let prefix_str: &str = prefix.as_ref();
            assert_eq!(
                prefix_str,
                prefix_str.to_uppercase(),
                "token_prefix for {et:?} must be uppercase"
            );
            assert!(
                !prefix_str.is_empty(),
                "token_prefix for {et:?} must not be empty"
            );
        }
    }

    #[test]
    fn entity_type_other_prefix_uses_inner_string_uppercased() {
        assert_eq!(
            EntityType::Other("nrp".to_string()).token_prefix().as_ref(),
            "NRP",
            "Other variant prefix must uppercase the inner string"
        );
        assert_eq!(
            EntityType::Other("Medical_License".to_string())
                .token_prefix()
                .as_ref(),
            "MEDICAL_LICENSE",
            "Other variant prefix must uppercase the inner string"
        );
    }

    #[test]
    fn entity_type_storage_roundtrip() {
        let types = [
            EntityType::Email,
            EntityType::PhoneCa,
            EntityType::Phone,
            EntityType::Url,
            EntityType::DateTime,
            EntityType::Other("NRP".to_string()),
        ];
        for et in &types {
            let stored = et.to_storage_str();
            let parsed = EntityType::from_storage_str(stored.as_ref()).unwrap_or_else(|| {
                panic!("failed to parse storage string '{}' for {et:?}", stored)
            });
            assert_eq!(
                &parsed, et,
                "storage roundtrip failed for {et:?}: stored as '{stored}' then parsed back as {parsed:?}"
            );
        }
    }

    #[test]
    fn entity_type_requires_optional_backend() {
        assert!(
            EntityType::Person.requires_optional_backend(),
            "PERSON requires optional backend"
        );
        assert!(
            EntityType::Phone.requires_optional_backend(),
            "PHONE requires optional backend (Presidio)"
        );
        assert!(
            EntityType::Url.requires_optional_backend(),
            "URL requires optional backend (Presidio)"
        );
        assert!(
            EntityType::DateTime.requires_optional_backend(),
            "DATETIME requires optional backend (Presidio)"
        );
        assert!(
            EntityType::Other("X".into()).requires_optional_backend(),
            "Other requires optional backend"
        );
        assert!(
            !EntityType::Email.requires_optional_backend(),
            "EMAIL is regex, no optional backend needed"
        );
        assert!(
            !EntityType::CreditCard.requires_optional_backend(),
            "CREDIT_CARD is regex, no optional backend needed"
        );
    }

    #[test]
    fn token_display_roundtrip() {
        let t = Token::new("EMAIL_a3f2c1");
        assert_eq!(
            t.to_string(),
            "EMAIL_a3f2c1",
            "Token Display must reproduce the inner string"
        );
        assert_eq!(
            t.as_str(),
            "EMAIL_a3f2c1",
            "Token::as_str must return the inner string"
        );
    }

    #[test]
    fn message_content_text_segments_plain() {
        let content = MessageContent::Text("hello world".to_string());
        assert_eq!(
            content.text_segments(),
            vec!["hello world"],
            "plain text content should yield one segment"
        );
    }

    #[test]
    fn message_content_text_segments_parts() {
        let parts = serde_json::json!([
            {"type": "text", "text": "first"},
            {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}},
            {"type": "text", "text": "second"}
        ]);
        let content = MessageContent::Parts(parts.as_array().unwrap().clone());
        let segs = content.text_segments();
        assert_eq!(
            segs,
            vec!["first", "second"],
            "parts content should yield only text-type segments"
        );
    }

    #[test]
    fn chat_request_preserves_extra_fields() {
        let json = r#"{
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "temperature": 0.7,
            "max_tokens": 100
        }"#;
        let req: ChatRequest = serde_json::from_str(json).expect("must parse valid chat request");
        assert_eq!(req.model, "gpt-4o", "model field must be parsed");
        assert_eq!(req.messages.len(), 1, "messages array must be parsed");
        assert!(
            req.extra.contains_key("temperature"),
            "temperature must be preserved in extra"
        );
        assert!(
            req.extra.contains_key("max_tokens"),
            "max_tokens must be preserved in extra"
        );
    }
}
