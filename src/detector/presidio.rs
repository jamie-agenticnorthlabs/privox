//! Presidio analyzer sidecar client.
//!
//! Calls a locally-running Presidio REST service (`POST /analyze`) and maps its
//! response to [`DetectedEntity`] values. Only the `/analyze` endpoint is used;
//! `privox` handles all tokenization internally via its own vault.
//!
//! See: <https://microsoft.github.io/presidio/api-docs/api-docs.html>
//!
//! # Entity type mapping
//!
//! Presidio entity type strings are mapped to [`EntityType`] variants. Unknown
//! types map to [`EntityType::Other`]. The mapping table is defined in
//! [`map_presidio_entity`].
//!
//! # Availability handling
//!
//! If `fallback_to_regex = true` (default), an unreachable or erroring Presidio
//! endpoint logs a warning and returns `Ok(vec![])` so the pipeline continues with
//! regex-only results. If `fallback_to_regex = false`, returns a
//! [`DetectorError::NerUnavailable`] which the pipeline propagates as a 503 error.
// TODO(next-session): Implement PresidioDetector fully.
// See ADDENDUM-001 section 2 for detailed requirements.

use async_trait::async_trait;

use crate::{
    error::DetectorError,
    types::{DetectedEntity, EntityType},
};

use super::{Detector, DetectorPriority};

/// Presidio entity type strings mapped to privox [`EntityType`] variants.
///
/// Source: <https://microsoft.github.io/presidio/supported_entities/>
fn map_presidio_entity(presidio_type: &str) -> EntityType {
    // This mapping MUST be kept in sync with Presidio's documented entity types.
    match presidio_type {
        "PERSON" => EntityType::Person,
        "EMAIL_ADDRESS" => EntityType::Email,
        "PHONE_NUMBER" => EntityType::Phone,
        "CREDIT_CARD" => EntityType::CreditCard,
        "IBAN_CODE" => EntityType::Iban,
        "US_SSN" => EntityType::Ssn,
        "CA_SIN" => EntityType::Sin,
        "IP_ADDRESS" => EntityType::Ipv4,
        "URL" => EntityType::Url,
        "LOCATION" => EntityType::Location,
        "DATE_TIME" => EntityType::DateTime,
        other => EntityType::Other(other.to_string()),
    }
}

/// Async HTTP client for the Presidio analyzer REST API.
pub struct PresidioDetector {
    // TODO(next-session): Add reqwest client, config fields (analyzer_url,
    // language, score_threshold, fallback_to_regex, timeout).
}

impl PresidioDetector {
    /// Creates a new `PresidioDetector`.
    ///
    /// # Arguments
    ///
    /// * `analyzer_url` — base URL of the Presidio analyzer service.
    /// * `language` — language code passed to Presidio (e.g. `"en"`).
    /// * `score_threshold` — minimum confidence score (0.0–1.0); entities below this are discarded.
    /// * `fallback_to_regex` — if `true`, return empty results on Presidio errors instead of failing.
    /// * `timeout_secs` — HTTP request timeout.
    pub fn new(
        _analyzer_url: String,
        _language: String,
        _score_threshold: f64,
        _fallback_to_regex: bool,
        _timeout_secs: u64,
    ) -> Self {
        // TODO(next-session): Build reqwest client and store config.
        Self {}
    }
}

#[async_trait]
impl Detector for PresidioDetector {
    async fn detect(&self, _text: &str) -> Result<Vec<DetectedEntity>, DetectorError> {
        // TODO(next-session): Call POST /analyze, parse response, apply score threshold,
        // map entity types via map_presidio_entity, return DetectedEntity vec.
        Ok(vec![])
    }

    fn name(&self) -> &'static str {
        "presidio"
    }

    fn priority(&self) -> DetectorPriority {
        DetectorPriority::Presidio
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presidio_entity_mapping_known_types() {
        assert_eq!(
            map_presidio_entity("PERSON"),
            EntityType::Person,
            "PERSON must map to EntityType::Person"
        );
        assert_eq!(
            map_presidio_entity("EMAIL_ADDRESS"),
            EntityType::Email,
            "EMAIL_ADDRESS must map to EntityType::Email"
        );
        assert_eq!(
            map_presidio_entity("PHONE_NUMBER"),
            EntityType::Phone,
            "PHONE_NUMBER must map to EntityType::Phone"
        );
        assert_eq!(
            map_presidio_entity("CREDIT_CARD"),
            EntityType::CreditCard,
            "CREDIT_CARD must map to EntityType::CreditCard"
        );
        assert_eq!(
            map_presidio_entity("IBAN_CODE"),
            EntityType::Iban,
            "IBAN_CODE must map to EntityType::Iban"
        );
        assert_eq!(
            map_presidio_entity("US_SSN"),
            EntityType::Ssn,
            "US_SSN must map to EntityType::Ssn"
        );
        assert_eq!(
            map_presidio_entity("CA_SIN"),
            EntityType::Sin,
            "CA_SIN must map to EntityType::Sin"
        );
        assert_eq!(
            map_presidio_entity("IP_ADDRESS"),
            EntityType::Ipv4,
            "IP_ADDRESS must map to EntityType::Ipv4"
        );
        assert_eq!(
            map_presidio_entity("URL"),
            EntityType::Url,
            "URL must map to EntityType::Url"
        );
        assert_eq!(
            map_presidio_entity("LOCATION"),
            EntityType::Location,
            "LOCATION must map to EntityType::Location"
        );
        assert_eq!(
            map_presidio_entity("DATE_TIME"),
            EntityType::DateTime,
            "DATE_TIME must map to EntityType::DateTime"
        );
    }

    #[test]
    fn presidio_entity_mapping_unknown_falls_back_to_other() {
        assert_eq!(
            map_presidio_entity("NRP"),
            EntityType::Other("NRP".to_string()),
            "unknown type NRP must map to EntityType::Other"
        );
        assert_eq!(
            map_presidio_entity("MEDICAL_LICENSE"),
            EntityType::Other("MEDICAL_LICENSE".to_string()),
            "unknown type MEDICAL_LICENSE must map to EntityType::Other"
        );
    }

    #[test]
    fn presidio_detector_priority_is_highest() {
        let d = PresidioDetector::new(
            "http://localhost:5002".to_string(),
            "en".to_string(),
            0.7,
            true,
            5,
        );
        assert_eq!(
            d.priority(),
            DetectorPriority::Presidio,
            "PresidioDetector must have the highest priority"
        );
    }
}
