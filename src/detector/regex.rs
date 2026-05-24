use std::sync::OnceLock;

use async_trait::async_trait;
use regex::Regex;

use super::{Detector, DetectorPriority};
use crate::{
    error::DetectorError,
    types::{DetectedEntity, EntityType},
};

// ── Pre-compiled patterns ─────────────────────────────────────────────────────

// RFC 5321 simplified local-part + domain; intentionally permissive to reduce
// false negatives. Anchored with \b to avoid matching inside longer tokens.
static RE_EMAIL: OnceLock<Regex> = OnceLock::new();
fn re_email() -> &'static Regex {
    RE_EMAIL.get_or_init(|| {
        Regex::new(r"(?i)\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b").unwrap()
    })
}

// NANP phone numbers. Two forms:
//   Formatted:  (NXX) NXX-XXXX, NXX-NXX-XXXX, +1 NXX-NXX-XXXX and variants.
//   E.164 compact: +1NXXXXXXXXX (no separators, common in API payloads).
// NXX: first digit 2–9. Covers both CA and US (same numbering plan).
static RE_PHONE: OnceLock<Regex> = OnceLock::new();
fn re_phone() -> &'static Regex {
    RE_PHONE.get_or_init(|| {
        Regex::new(
            r"(?x)
            (?:
              # E.164 compact: +1 followed by 10 digits, NXX constraints
              \+1[2-9]\d{2}[2-9]\d{6}
            |
              # Formatted NANP with separators
              (?:\+?1[\s.\-]?)?          # optional country code
              (?:\([2-9]\d{2}\)[\s.\-]?  # (NXX) with separator
              |[2-9]\d{2}[\s.\-])        # or NXX with separator
              [2-9]\d{2}[\s.\-]\d{4}    # NXX-XXXX
            )
            ",
        )
        .unwrap()
    })
}

// 13–19 digit sequences with optional spaces or hyphens between groups.
// Luhn validation is applied in code after the regex matches.
static RE_CREDIT_CARD: OnceLock<Regex> = OnceLock::new();
fn re_credit_card() -> &'static Regex {
    RE_CREDIT_CARD.get_or_init(|| Regex::new(r"\b(?:\d[ \-]?){12,18}\d\b").unwrap())
}

// Canadian Social Insurance Number: 9 digits, optional spaces or hyphens.
// SINs starting with 0 or 8 are not issued (structural, not validated here).
static RE_SIN: OnceLock<Regex> = OnceLock::new();
fn re_sin() -> &'static Regex {
    RE_SIN.get_or_init(|| Regex::new(r"\b\d{3}[ \-]?\d{3}[ \-]?\d{3}\b").unwrap())
}

// US Social Security Number: SSA format DDD-DD-DDDD or with spaces.
static RE_SSN: OnceLock<Regex> = OnceLock::new();
fn re_ssn() -> &'static Regex {
    RE_SSN.get_or_init(|| Regex::new(r"\b\d{3}[ \-]\d{2}[ \-]\d{4}\b").unwrap())
}

// IBAN: ISO 13616 structural pattern — 2-letter country code, 2 check digits,
// then 11–30 alphanumeric BBAN characters. Checksum verification is out of
// scope for v1.
static RE_IBAN: OnceLock<Regex> = OnceLock::new();
fn re_iban() -> &'static Regex {
    RE_IBAN.get_or_init(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap())
}

// IPv4: each octet 0–255 with word boundaries. RFC 791.
static RE_IPV4: OnceLock<Regex> = OnceLock::new();
fn re_ipv4() -> &'static Regex {
    RE_IPV4.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
            .unwrap()
    })
}

// IPv6: simplified structural match — requires at least two colon-separated
// groups. No \b anchoring: `:` is not a word character, so \b behaves poorly
// for addresses like `::1`. The {2,7} minimum ensures a single-colon token
// like `not:word` won't match. Full RFC 4291 validation is out of scope for v1.
static RE_IPV6: OnceLock<Regex> = OnceLock::new();
fn re_ipv6() -> &'static Regex {
    RE_IPV6.get_or_init(|| Regex::new(r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}").unwrap())
}

// API key patterns — common prefixes used by major providers:
//   sk-...        OpenAI secret key
//   ghp_...       GitHub personal access token
//   xoxb-...      Slack bot token
//   AIza...       Google API key
//   Bearer <tok>  HTTP Authorization header value
static RE_API_KEY: OnceLock<Regex> = OnceLock::new();
fn re_api_key() -> &'static Regex {
    RE_API_KEY.get_or_init(|| {
        Regex::new(
            r"(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36,}|xoxb-[a-zA-Z0-9\-]{20,}|AIza[a-zA-Z0-9_\-]{35}|Bearer\s+[a-zA-Z0-9._\-]{20,})",
        )
        .unwrap()
    })
}

// URLs with embedded credentials: scheme://user:password@host[/path]
static RE_URL_WITH_CREDS: OnceLock<Regex> = OnceLock::new();
fn re_url_with_creds() -> &'static Regex {
    RE_URL_WITH_CREDS.get_or_init(|| Regex::new(r"https?://[^:@\s]+:[^@\s]+@[^\s]+").unwrap())
}

// UUID v4 canonical format: 8-4-4-4-12 hex, case-insensitive. RFC 4122.
static RE_UUID: OnceLock<Regex> = OnceLock::new();
fn re_uuid() -> &'static Regex {
    RE_UUID.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
            .unwrap()
    })
}

// ── Luhn validation ───────────────────────────────────────────────────────────

/// Returns `true` if `digits` passes the Luhn check (ISO/IEC 7812).
/// `digits` must contain only ASCII digit characters.
fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        let val = if double {
            let v = d * 2;
            if v > 9 {
                v - 9
            } else {
                v
            }
        } else {
            d
        };
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn strip_separators(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn matches_to_entities(text: &str, re: &Regex, entity_type: EntityType) -> Vec<DetectedEntity> {
    re.find_iter(text)
        .map(|m| DetectedEntity {
            start: m.start(),
            end: m.end(),
            entity_type: entity_type.clone(),
            original_value: m.as_str().to_string(),
        })
        .collect()
}

// ── RegexDetector ─────────────────────────────────────────────────────────────

/// Detects structured PII using pre-compiled regular expressions.
///
/// All patterns are compiled once at first use via [`OnceLock`]. Detection is
/// synchronous but wrapped in the async `Detector` interface.
pub struct RegexDetector;

impl RegexDetector {
    pub fn new() -> Self {
        Self
    }

    fn detect_sync(&self, text: &str) -> Vec<DetectedEntity> {
        let mut entities: Vec<DetectedEntity> = Vec::new();

        entities.extend(matches_to_entities(text, re_email(), EntityType::Email));

        // Phone: run once, emit both CA and US types for the same match.
        // The pipeline's merge_spans will deduplicate if they overlap.
        for m in re_phone().find_iter(text) {
            entities.push(DetectedEntity {
                start: m.start(),
                end: m.end(),
                entity_type: EntityType::PhoneCa,
                original_value: m.as_str().to_string(),
            });
            entities.push(DetectedEntity {
                start: m.start(),
                end: m.end(),
                entity_type: EntityType::PhoneUs,
                original_value: m.as_str().to_string(),
            });
        }

        // Credit card: regex match + Luhn validation.
        for m in re_credit_card().find_iter(text) {
            let digits = strip_separators(m.as_str());
            if digits.len() >= 13 && digits.len() <= 19 && luhn_valid(&digits) {
                entities.push(DetectedEntity {
                    start: m.start(),
                    end: m.end(),
                    entity_type: EntityType::CreditCard,
                    original_value: m.as_str().to_string(),
                });
            }
        }

        // SSN before SIN: SSN pattern (DDD-DD-DDDD) is more specific than SIN
        // (DDD-DDD-DDD). Run SSN first so a US SSN is not also tagged as SIN.
        entities.extend(matches_to_entities(text, re_ssn(), EntityType::Ssn));
        entities.extend(matches_to_entities(text, re_sin(), EntityType::Sin));
        entities.extend(matches_to_entities(text, re_iban(), EntityType::Iban));

        // IPv4 before IPv6: prevent IPv4-mapped IPv6 double-matches.
        entities.extend(matches_to_entities(text, re_ipv4(), EntityType::Ipv4));
        entities.extend(matches_to_entities(text, re_ipv6(), EntityType::Ipv6));

        entities.extend(matches_to_entities(text, re_api_key(), EntityType::ApiKey));
        entities.extend(matches_to_entities(
            text,
            re_url_with_creds(),
            EntityType::UrlWithCredentials,
        ));
        entities.extend(matches_to_entities(text, re_uuid(), EntityType::Uuid));

        entities
    }
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for RegexDetector {
    async fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>, DetectorError> {
        Ok(self.detect_sync(text))
    }

    fn name(&self) -> &'static str {
        "regex"
    }

    fn priority(&self) -> DetectorPriority {
        DetectorPriority::Regex
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str) -> Vec<DetectedEntity> {
        RegexDetector::new().detect_sync(text)
    }

    fn has(entities: &[DetectedEntity], et: &EntityType, value: &str) -> bool {
        entities
            .iter()
            .any(|e| &e.entity_type == et && e.original_value == value)
    }

    fn has_type(entities: &[DetectedEntity], et: &EntityType) -> bool {
        entities.iter().any(|e| &e.entity_type == et)
    }

    // ── Email ─────────────────────────────────────────────────────────────────

    #[test]
    fn email_positive() {
        let e = detect("Contact user.name+tag@sub.example.com today");
        assert!(has(&e, &EntityType::Email, "user.name+tag@sub.example.com"));
    }

    #[test]
    fn email_negative_no_tld() {
        let e = detect("not-an-email@localhost");
        assert!(!has_type(&e, &EntityType::Email));
    }

    // ── Phone ─────────────────────────────────────────────────────────────────

    #[test]
    fn phone_parenthesis_format() {
        let e = detect("Call (519) 555-1234 today");
        assert!(has(&e, &EntityType::PhoneCa, "(519) 555-1234"));
    }

    #[test]
    fn phone_dashed_format() {
        let e = detect("519-555-1234");
        assert!(has_type(&e, &EntityType::PhoneCa));
    }

    #[test]
    fn phone_e164_format() {
        let e = detect("+15195551234");
        assert!(has_type(&e, &EntityType::PhoneCa));
    }

    #[test]
    fn phone_negative_too_short() {
        let e = detect("555-1234");
        assert!(!has_type(&e, &EntityType::PhoneCa));
    }

    // ── Credit card ───────────────────────────────────────────────────────────

    #[test]
    fn credit_card_visa_positive() {
        // Luhn-valid Visa test number
        let e = detect("Card: 4111 1111 1111 1111");
        assert!(has(&e, &EntityType::CreditCard, "4111 1111 1111 1111"));
    }

    #[test]
    fn credit_card_mastercard_positive() {
        let e = detect("5500-0000-0000-0004");
        assert!(has_type(&e, &EntityType::CreditCard));
    }

    #[test]
    fn credit_card_luhn_invalid_rejected() {
        // Flip the last digit to break Luhn
        let e = detect("4111 1111 1111 1112");
        assert!(!has_type(&e, &EntityType::CreditCard));
    }

    #[test]
    fn luhn_known_valid() {
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("5500000000000004"));
        assert!(luhn_valid("378282246310005")); // Amex
    }

    #[test]
    fn luhn_known_invalid() {
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("1234567890123456"));
    }

    // ── SIN ──────────────────────────────────────────────────────────────────

    #[test]
    fn sin_spaced_positive() {
        let e = detect("SIN: 123 456 789");
        assert!(has_type(&e, &EntityType::Sin));
    }

    #[test]
    fn sin_dashed_positive() {
        let e = detect("123-456-789");
        assert!(has_type(&e, &EntityType::Sin));
    }

    #[test]
    fn sin_negative_too_few_digits() {
        let e = detect("12 345 67");
        assert!(!has_type(&e, &EntityType::Sin));
    }

    // ── SSN ──────────────────────────────────────────────────────────────────

    #[test]
    fn ssn_dashed_positive() {
        let e = detect("SSN: 123-45-6789");
        assert!(has(&e, &EntityType::Ssn, "123-45-6789"));
    }

    #[test]
    fn ssn_spaced_positive() {
        let e = detect("123 45 6789");
        assert!(has_type(&e, &EntityType::Ssn));
    }

    #[test]
    fn ssn_negative_wrong_grouping() {
        // 9 digits with no separators should not match SSN (requires separator)
        let e = detect("123456789");
        assert!(!has_type(&e, &EntityType::Ssn));
    }

    // ── IBAN ─────────────────────────────────────────────────────────────────

    #[test]
    fn iban_gb_positive() {
        let e = detect("IBAN GB82WEST12345698765432");
        assert!(has(&e, &EntityType::Iban, "GB82WEST12345698765432"));
    }

    #[test]
    fn iban_negative_lowercase() {
        // Pattern requires uppercase; lowercase should not match
        let e = detect("gb82west12345698765432");
        assert!(!has_type(&e, &EntityType::Iban));
    }

    // ── IPv4 ─────────────────────────────────────────────────────────────────

    #[test]
    fn ipv4_positive() {
        let e = detect("Server at 192.168.1.254 is down");
        assert!(has(&e, &EntityType::Ipv4, "192.168.1.254"));
    }

    #[test]
    fn ipv4_negative_octet_out_of_range() {
        let e = detect("999.999.999.999");
        assert!(!has_type(&e, &EntityType::Ipv4));
    }

    // ── IPv6 ─────────────────────────────────────────────────────────────────

    #[test]
    fn ipv6_positive() {
        let e = detect("Address 2001:db8::1 is reserved");
        assert!(has_type(&e, &EntityType::Ipv6));
    }

    #[test]
    fn ipv6_loopback_positive() {
        let e = detect("::1");
        assert!(has_type(&e, &EntityType::Ipv6));
    }

    #[test]
    fn ipv6_negative_single_colon() {
        let e = detect("not:ipv6");
        assert!(!has_type(&e, &EntityType::Ipv6));
    }

    // ── API key ───────────────────────────────────────────────────────────────

    #[test]
    fn api_key_openai_positive() {
        let e = detect("key=sk-abcdefghijklmnopqrstuvwxyz123456");
        assert!(has_type(&e, &EntityType::ApiKey));
    }

    #[test]
    fn api_key_github_positive() {
        let e = detect("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab");
        assert!(has_type(&e, &EntityType::ApiKey));
    }

    #[test]
    fn api_key_bearer_positive() {
        let e = detect("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload");
        assert!(has_type(&e, &EntityType::ApiKey));
    }

    #[test]
    fn api_key_negative_too_short() {
        let e = detect("sk-short");
        assert!(!has_type(&e, &EntityType::ApiKey));
    }

    // ── URL with credentials ──────────────────────────────────────────────────

    #[test]
    fn url_with_creds_positive() {
        let e = detect("Connect to https://admin:s3cr3t@db.example.com/mydb");
        assert!(has_type(&e, &EntityType::UrlWithCredentials));
    }

    #[test]
    fn url_without_creds_negative() {
        let e = detect("See https://example.com/path for details");
        assert!(!has_type(&e, &EntityType::UrlWithCredentials));
    }

    // ── UUID ─────────────────────────────────────────────────────────────────

    #[test]
    fn uuid_v4_positive() {
        let e = detect("ID: 550e8400-e29b-41d4-a716-446655440000");
        assert!(has(
            &e,
            &EntityType::Uuid,
            "550e8400-e29b-41d4-a716-446655440000"
        ));
    }

    #[test]
    fn uuid_negative_wrong_variant() {
        // Version nibble must be 4; this has version 1
        let e = detect("550e8400-e29b-11d4-a716-446655440000");
        assert!(!has_type(&e, &EntityType::Uuid));
    }

    // ── Multi-entity text ─────────────────────────────────────────────────────

    #[test]
    fn multiple_entities_in_one_text() {
        let text = "Email test@example.com, card 4111 1111 1111 1111, SSN 123-45-6789";
        let e = detect(text);
        assert!(has_type(&e, &EntityType::Email));
        assert!(has_type(&e, &EntityType::CreditCard));
        assert!(has_type(&e, &EntityType::Ssn));
    }

    #[test]
    fn empty_text_returns_no_entities() {
        let e = detect("");
        assert!(e.is_empty());
    }
}
