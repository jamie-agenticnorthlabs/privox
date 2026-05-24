/// Detector trait, pipeline orchestration, and span merge/deduplication.
///
/// # Pipeline
///
/// The [`DetectorPipeline`] holds a `Vec<Box<dyn Detector>>` and runs each detector
/// in sequence, then merges and deduplicates the resulting spans before returning
/// to the tokenizer.
///
/// # Detector priority for overlap resolution
///
/// When spans from different detectors overlap and disagree on entity type, the
/// higher-priority detector wins. Priority order (highest first):
/// `PresidioDetector` > `NerDetector` > `RegexDetector`.
///
/// This ordering is encoded in the [`DetectorPriority`] enum.
use async_trait::async_trait;
use tracing::debug;

use crate::{error::DetectorError, types::DetectedEntity};

pub mod ner;
pub mod presidio;
pub mod regex;

// ── Detector trait ────────────────────────────────────────────────────────────

/// Detects sensitive entities in a text string.
///
/// Implementations may use regex, a local NER model, or a remote service.
/// All implementations must be cheaply cloneable and safe to use across threads.
#[async_trait]
pub trait Detector: Send + Sync {
    /// Detect sensitive entities in `text`.
    ///
    /// Returns a list of detected entities in document order. Overlapping spans
    /// are permitted at this stage; [`DetectorPipeline`] resolves conflicts before
    /// passing results to the tokenizer.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError`] if the detector fails in a non-recoverable way.
    /// Implementations that degrade gracefully (e.g. Presidio with
    /// `fallback_to_regex = true`) should return `Ok(vec![])` and log a warning
    /// rather than returning an error.
    async fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>, DetectorError>;

    /// A human-readable name for this detector, used in structured log output.
    fn name(&self) -> &'static str;

    /// The priority of this detector relative to others when resolving span conflicts.
    fn priority(&self) -> DetectorPriority;
}

/// Priority ordering for detectors when resolving overlapping span conflicts.
///
/// Higher numeric value = higher priority. When two detectors produce overlapping
/// spans that disagree on entity type, the one with higher priority wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectorPriority {
    /// Lowest priority: regex-based structural pattern matching.
    Regex = 1,
    /// Medium priority: local NER model via Ollama.
    Ner = 2,
    /// Highest priority: Presidio analyzer service.
    Presidio = 3,
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Runs multiple detectors and merges their results.
///
/// The pipeline runs each detector in sequence (not in parallel for v1), collects
/// all [`DetectedEntity`] spans, then resolves overlaps according to the rules in
/// [`merge_spans`].
pub struct DetectorPipeline {
    detectors: Vec<(DetectorPriority, Box<dyn Detector>)>,
}

impl DetectorPipeline {
    /// Creates a pipeline from a list of detectors.
    ///
    /// The detectors may be provided in any order; the pipeline records each
    /// detector's declared priority for use in overlap resolution.
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        let detectors = detectors.into_iter().map(|d| (d.priority(), d)).collect();
        Self { detectors }
    }

    /// Runs all detectors on `text` and returns the merged, deduplicated span list.
    ///
    /// # Errors
    ///
    /// Returns the first [`DetectorError`] encountered if a detector fails in a
    /// non-recoverable way (i.e. did not degrade gracefully).
    pub async fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>, DetectorError> {
        let mut tagged: Vec<(DetectorPriority, DetectedEntity)> = Vec::new();

        for (priority, detector) in &self.detectors {
            debug!(detector = %detector.name(), "running detector");
            match detector.detect(text).await {
                Ok(entities) => {
                    for entity in entities {
                        tagged.push((*priority, entity));
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Ok(merge_spans(tagged))
    }
}

// ── Span merge/deduplication ──────────────────────────────────────────────────

/// Merges and deduplicates a list of tagged `(priority, entity)` spans.
///
/// Rules applied in order:
/// 1. Identical `(start, end, entity_type)` spans — keep one, discard duplicates.
/// 2. Overlapping spans from the same detector — keep the longer span.
/// 3. Overlapping spans from different detectors with different entity types —
///    keep the span from the higher-priority detector.
/// 4. Non-overlapping spans from all detectors — always included.
///
/// The returned list is sorted by `start` position.
pub fn merge_spans(mut tagged: Vec<(DetectorPriority, DetectedEntity)>) -> Vec<DetectedEntity> {
    if tagged.is_empty() {
        return vec![];
    }

    // Sort by start position, then by length (longest first), then by priority (highest first).
    tagged.sort_unstable_by(|a, b| {
        a.1.start
            .cmp(&b.1.start)
            .then_with(|| (b.1.end - b.1.start).cmp(&(a.1.end - a.1.start)))
            .then_with(|| b.0.cmp(&a.0))
    });

    let mut result: Vec<(DetectorPriority, DetectedEntity)> = Vec::new();

    'outer: for (priority, candidate) in tagged {
        for (existing_priority, existing) in &result {
            if spans_overlap(candidate.start, candidate.end, existing.start, existing.end) {
                // Identical span and type: silently discard.
                if candidate.start == existing.start
                    && candidate.end == existing.end
                    && candidate.entity_type == existing.entity_type
                {
                    continue 'outer;
                }
                // Any other overlap: keep the one already in result if it has
                // higher or equal priority. Since we sorted highest-priority first,
                // the first entry we encounter wins.
                if existing_priority >= &priority {
                    continue 'outer;
                }
                // If candidate has strictly higher priority and overlaps, it will
                // have been placed earlier by the sort, so this branch is unreachable.
                // (The sort puts higher-priority spans first for the same start position.)
            }
        }
        result.push((priority, candidate));
    }

    result.into_iter().map(|(_, e)| e).collect()
}

/// Returns `true` if `[a_start, a_end)` and `[b_start, b_end)` overlap.
fn spans_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && a_end > b_start
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    fn entity(start: usize, end: usize, et: EntityType, value: &str) -> DetectedEntity {
        DetectedEntity {
            start,
            end,
            entity_type: et,
            original_value: value.to_string(),
        }
    }

    fn tagged(
        priority: DetectorPriority,
        start: usize,
        end: usize,
        et: EntityType,
        value: &str,
    ) -> (DetectorPriority, DetectedEntity) {
        (priority, entity(start, end, et, value))
    }

    #[test]
    fn merge_empty_input() {
        let result = merge_spans(vec![]);
        assert!(result.is_empty(), "empty input must produce empty output");
    }

    #[test]
    fn merge_non_overlapping_spans_all_included() {
        let spans = vec![
            tagged(DetectorPriority::Regex, 0, 5, EntityType::Email, "a@b.c"),
            tagged(
                DetectorPriority::Regex,
                10,
                20,
                EntityType::Ssn,
                "555-55-5555",
            ),
        ];
        let result = merge_spans(spans);
        assert_eq!(
            result.len(),
            2,
            "two non-overlapping spans must both be included"
        );
    }

    #[test]
    fn merge_identical_spans_deduped() {
        let spans = vec![
            tagged(DetectorPriority::Regex, 0, 10, EntityType::Email, "a@b.com"),
            tagged(DetectorPriority::Ner, 0, 10, EntityType::Email, "a@b.com"),
        ];
        let result = merge_spans(spans);
        assert_eq!(
            result.len(),
            1,
            "identical (start, end, type) spans must be deduped to one"
        );
    }

    #[test]
    fn merge_overlap_different_types_higher_priority_wins() {
        // Presidio says 0..10 is PERSON; Regex says 0..10 is EMAIL.
        // Presidio has higher priority.
        let spans = vec![
            tagged(
                DetectorPriority::Regex,
                0,
                10,
                EntityType::Email,
                "John Doe",
            ),
            tagged(
                DetectorPriority::Presidio,
                0,
                10,
                EntityType::Person,
                "John Doe",
            ),
        ];
        let result = merge_spans(spans);
        assert_eq!(result.len(), 1, "overlapping spans must be resolved to one");
        assert_eq!(
            result[0].entity_type,
            EntityType::Person,
            "higher-priority detector (Presidio) must win"
        );
    }

    #[test]
    fn merge_overlap_same_detector_longer_wins() {
        // Same priority; longer span (0..15) should beat contained span (2..10).
        let spans = vec![
            tagged(
                DetectorPriority::Regex,
                0,
                15,
                EntityType::PhoneCa,
                "1-555-555-1234",
            ),
            tagged(
                DetectorPriority::Regex,
                2,
                10,
                EntityType::PhoneUs,
                "555-555-",
            ),
        ];
        let result = merge_spans(spans);
        assert_eq!(
            result.len(),
            1,
            "overlapping same-priority spans must be resolved to one"
        );
        assert_eq!(
            result[0].end - result[0].start,
            15,
            "longer span must be kept"
        );
    }

    #[test]
    fn merge_adjacent_non_overlapping_spans_both_kept() {
        // [0, 5) and [5, 10) are adjacent but not overlapping.
        let spans = vec![
            tagged(DetectorPriority::Regex, 0, 5, EntityType::Email, "hello"),
            tagged(DetectorPriority::Regex, 5, 10, EntityType::Ssn, "world"),
        ];
        let result = merge_spans(spans);
        assert_eq!(
            result.len(),
            2,
            "adjacent non-overlapping spans must both be included"
        );
    }

    #[test]
    fn merge_nested_span_outer_wins() {
        // Inner span [2, 8) is fully contained in outer [0, 10).
        // Both are same priority; outer (longer) should win.
        let spans = vec![
            tagged(
                DetectorPriority::Ner,
                0,
                10,
                EntityType::Person,
                "John Smith",
            ),
            tagged(DetectorPriority::Ner, 2, 8, EntityType::Org, "hn Smi"),
        ];
        let result = merge_spans(spans);
        assert_eq!(
            result.len(),
            1,
            "a span nested inside a longer span must be suppressed"
        );
        assert_eq!(result[0].entity_type, EntityType::Person);
    }
}
