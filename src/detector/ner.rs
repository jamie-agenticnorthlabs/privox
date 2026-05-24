use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{Detector, DetectorPriority};
use crate::{
    config::NerConfig,
    error::DetectorError,
    types::{DetectedEntity, EntityType},
};

// ── Prompt ────────────────────────────────────────────────────────────────────

const NER_PROMPT_TEMPLATE: &str = r#"You are a named entity recognition (NER) system.
Extract named entities from the text below.

Return ONLY a JSON array with no other text. Each object must have exactly two fields:
- "text": the exact entity text as it appears in the input (copy it verbatim)
- "type": one of: PERSON, ORG, LOCATION, DATE_OF_BIRTH, ACCOUNT_NUMBER

If there are no named entities, return an empty array: []

Input text:
"""
{TEXT}
"""

JSON array:"#;

fn build_prompt(text: &str) -> String {
    NER_PROMPT_TEMPLATE.replace("{TEXT}", text)
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

#[derive(Deserialize)]
struct NerItem {
    text: String,
    #[serde(rename = "type")]
    entity_type: String,
}

// ── Entity type mapping ───────────────────────────────────────────────────────

fn map_ner_type(s: &str) -> Option<EntityType> {
    match s {
        "PERSON" => Some(EntityType::Person),
        "ORG" => Some(EntityType::Org),
        "LOCATION" => Some(EntityType::Location),
        "DATE_OF_BIRTH" => Some(EntityType::DateOfBirth),
        "ACCOUNT_NUMBER" => Some(EntityType::AccountNumber),
        _ => None,
    }
}

// ── Response parsing ──────────────────────────────────────────────────────────

/// Extracts detected entities from an Ollama NER response string.
///
/// The model may include prose before or after the JSON array; this function
/// locates the first `[` in `response` and attempts to parse from that point.
/// On any parse failure the function returns an empty vec (the caller logs
/// a warning). Individual items with unknown entity types are silently skipped.
fn parse_ner_response(original_text: &str, response: &str) -> Vec<DetectedEntity> {
    // Find the start of the JSON array.
    let array_start = match response.find('[') {
        Some(pos) => pos,
        None => return vec![],
    };

    let items: Vec<NerItem> = match serde_json::from_str(&response[array_start..]) {
        Ok(v) => v,
        Err(_) => {
            // Try trimming trailing prose after the closing bracket.
            let slice = &response[array_start..];
            let array_end = find_array_end(slice);
            match serde_json::from_str(&slice[..array_end]) {
                Ok(v) => v,
                Err(_) => return vec![],
            }
        }
    };

    let mut entities = Vec::new();
    for item in items {
        let Some(entity_type) = map_ner_type(&item.entity_type) else {
            continue;
        };
        // Find every occurrence of the entity text in the original input.
        // The model is asked to copy text verbatim, so byte-level search is correct.
        let mut search_from = 0;
        while let Some(pos) = original_text[search_from..].find(&item.text) {
            let start = search_from + pos;
            let end = start + item.text.len();
            entities.push(DetectedEntity {
                start,
                end,
                entity_type: entity_type.clone(),
                original_value: item.text.clone(),
            });
            search_from = end;
        }
    }

    entities
}

/// Returns the byte index just past the closing `]` of the outermost JSON array
/// starting at position 0 of `s`.
fn find_array_end(s: &str) -> usize {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape_next = false;
    for (i, b) in s.bytes().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match b {
            b'\\' if in_string => escape_next = true,
            b'"' => in_string = !in_string,
            b'[' if !in_string => depth += 1,
            b']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    s.len()
}

// ── NerDetector ───────────────────────────────────────────────────────────────

/// Optional NER detector that calls a local Ollama model for contextual entity detection.
///
/// Detects entity types that regex patterns cannot: `PERSON`, `ORG`, `LOCATION`,
/// `DATE_OF_BIRTH`, and `ACCOUNT_NUMBER`.
///
/// When Ollama is unavailable, [`detect`] logs a warning and returns `Ok(vec![])`
/// so that the pipeline continues with regex-only results.
pub struct NerDetector {
    client: reqwest::Client,
    config: NerConfig,
}

impl NerDetector {
    /// Creates a new `NerDetector` with a dedicated `reqwest::Client` configured
    /// for the given NER config timeout.
    pub fn new(config: NerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("reqwest client construction is infallible with valid config");
        Self { client, config }
    }
}

#[async_trait]
impl Detector for NerDetector {
    async fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>, DetectorError> {
        if text.is_empty() {
            return Ok(vec![]);
        }

        let url = format!("{}/api/generate", self.config.url.trim_end_matches('/'));
        let body = OllamaRequest {
            model: &self.config.model,
            prompt: build_prompt(text),
            stream: false,
        };

        let http_result = self.client.post(&url).json(&body).send().await;

        let response = match http_result {
            Ok(r) => r,
            Err(e) if e.is_connect() || e.is_timeout() => {
                warn!(
                    url = %url,
                    model = %self.config.model,
                    "NER endpoint unreachable — continuing with regex-only detection"
                );
                return Ok(vec![]);
            }
            Err(e) => {
                return Err(DetectorError::NerUnavailable {
                    url: url.clone(),
                    source: e,
                })
            }
        };

        let ollama: OllamaResponse = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    url = %url,
                    model = %self.config.model,
                    error = %e,
                    "NER response was not valid JSON — continuing with regex-only detection"
                );
                return Ok(vec![]);
            }
        };

        let entities = parse_ner_response(text, &ollama.response);
        if entities.is_empty() {
            // Not a warning — the model may legitimately find nothing.
        }
        Ok(entities)
    }

    fn name(&self) -> &'static str {
        "ner"
    }

    fn priority(&self) -> DetectorPriority {
        DetectorPriority::Ner
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    // ── parse_ner_response ────────────────────────────────────────────────────

    #[test]
    fn parse_clean_json_array() {
        let text = "Alice works at Acme Corp in Ottawa";
        let response = r#"[{"text":"Alice","type":"PERSON"},{"text":"Acme Corp","type":"ORG"},{"text":"Ottawa","type":"LOCATION"}]"#;
        let entities = parse_ner_response(text, response);
        assert_eq!(entities.len(), 3);
        assert!(entities
            .iter()
            .any(|e| e.entity_type == EntityType::Person && e.original_value == "Alice"));
        assert!(entities
            .iter()
            .any(|e| e.entity_type == EntityType::Org && e.original_value == "Acme Corp"));
        assert!(entities
            .iter()
            .any(|e| e.entity_type == EntityType::Location && e.original_value == "Ottawa"));
    }

    #[test]
    fn parse_json_embedded_in_model_prose() {
        let text = "Bob is an engineer";
        // Model included a preamble and a trailing note
        let response = "Here are the entities I found:\n[{\"text\":\"Bob\",\"type\":\"PERSON\"}]\nLet me know if you need more.";
        let entities = parse_ner_response(text, response);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].entity_type, EntityType::Person);
        assert_eq!(entities[0].original_value, "Bob");
    }

    #[test]
    fn parse_empty_array() {
        let text = "The sky is blue today.";
        let entities = parse_ner_response(text, "[]");
        assert!(entities.is_empty());
    }

    #[test]
    fn parse_malformed_json_returns_empty() {
        let text = "Some text";
        let entities = parse_ner_response(text, "not json at all");
        assert!(entities.is_empty());
    }

    #[test]
    fn parse_unknown_entity_type_skipped() {
        let text = "Widget Corp";
        let response = r#"[{"text":"Widget Corp","type":"PRODUCT"}]"#;
        let entities = parse_ner_response(text, response);
        assert!(entities.is_empty(), "unknown type must be skipped");
    }

    #[test]
    fn parse_entity_not_found_in_text_skipped() {
        // Model hallucinated a name that isn't in the original text
        let text = "The meeting is scheduled for noon";
        let response = r#"[{"text":"John","type":"PERSON"}]"#;
        let entities = parse_ner_response(text, response);
        assert!(
            entities.is_empty(),
            "entity not present in text must be skipped"
        );
    }

    #[test]
    fn parse_repeated_entity_finds_all_occurrences() {
        let text = "Alice met Alice at the park";
        let response = r#"[{"text":"Alice","type":"PERSON"}]"#;
        let entities = parse_ner_response(text, response);
        assert_eq!(
            entities.len(),
            2,
            "both occurrences of Alice must be detected"
        );
        assert_eq!(entities[0].start, 0);
        assert_eq!(entities[1].start, 10);
    }

    #[test]
    fn parse_correct_byte_offsets() {
        let text = "Send it to Bob Smith please";
        let response = r#"[{"text":"Bob Smith","type":"PERSON"}]"#;
        let entities = parse_ner_response(text, response);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].start, 11);
        assert_eq!(entities[0].end, 20);
        assert_eq!(&text[entities[0].start..entities[0].end], "Bob Smith");
    }

    // ── Entity type mapping ───────────────────────────────────────────────────

    #[test]
    fn map_all_supported_types() {
        assert_eq!(map_ner_type("PERSON"), Some(EntityType::Person));
        assert_eq!(map_ner_type("ORG"), Some(EntityType::Org));
        assert_eq!(map_ner_type("LOCATION"), Some(EntityType::Location));
        assert_eq!(map_ner_type("DATE_OF_BIRTH"), Some(EntityType::DateOfBirth));
        assert_eq!(
            map_ner_type("ACCOUNT_NUMBER"),
            Some(EntityType::AccountNumber)
        );
    }

    #[test]
    fn map_unknown_type_returns_none() {
        assert_eq!(map_ner_type("PRODUCT"), None);
        assert_eq!(map_ner_type(""), None);
    }

    // ── NerDetector metadata ──────────────────────────────────────────────────

    #[test]
    fn ner_detector_priority_is_ner() {
        let config = NerConfig {
            url: "http://localhost:11434".to_string(),
            model: "qwen2.5:0.5b".to_string(),
            timeout_secs: 10,
        };
        let det = NerDetector::new(config);
        assert_eq!(det.priority(), DetectorPriority::Ner);
    }

    #[test]
    fn ner_detector_name() {
        let config = NerConfig {
            url: "http://localhost:11434".to_string(),
            model: "qwen2.5:0.5b".to_string(),
            timeout_secs: 10,
        };
        let det = NerDetector::new(config);
        assert_eq!(det.name(), "ner");
    }
}
