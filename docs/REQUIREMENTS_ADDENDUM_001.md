# REQUIREMENTS ADDENDUM 001 — Detector Abstraction and Presidio Backend

**Addendum ID:** ADDENDUM-001
**Applies to:** docs/REQUIREMENTS.md
**Status:** Active
**Issued:** 2026-05-24

This addendum extends the original requirements. Where this document conflicts with
the original, this document takes precedence. All other original requirements remain
in force unchanged.

---

## Context and Rationale

The original requirements specify a single detection pipeline combining regex-based
detection with an optional local NER backend (Ollama). During design review, the
following gap was identified:

Microsoft Presidio is a mature, well-tested PII detection library with significantly
stronger NER quality than small local models, broad entity coverage, and documented
enterprise adoption. privox's regex detector and Presidio are not competitors — they
address different parts of the detection problem. Presidio's structured recognizers
and privox's streaming proxy, vault, and detokenization are complementary.

This addendum formalises a pluggable detection backend architecture that allows
privox to use its own Rust regex recognizers, an optional local Ollama NER backend,
or an optional Presidio REST sidecar — configured independently and composable.

It also documents the honest differentiation between privox and the existing
LiteLLM + Presidio stack, which must be reflected in the README.

---

## 1. Changes to Architecture (extends REQUIREMENTS.md section 4)

The detector is refactored from a pipeline of concrete types into a trait-based
abstraction. The module structure in section 4 and 7.4 is updated as follows.

### 1.1 Detector Trait

A `Detector` trait is introduced in `src/detector/mod.rs`:

```rust
/// Detects sensitive entities in a text string.
///
/// Implementations may use regex, a local NER model, or a remote service.
/// All implementations must be cheaply cloneable and safe to use across threads.
#[async_trait]
pub trait Detector: Send + Sync {
    /// Detect sensitive entities in `text`.
    ///
    /// Returns a list of detected entities in document order. Overlapping spans
    /// are permitted; the tokenizer resolves conflicts by preferring longer spans.
    async fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>, DetectorError>;

    /// Returns a human-readable name for this detector, used in log output.
    fn name(&self) -> &'static str;
}
```

The detection pipeline in `detector/mod.rs` accepts a `Vec<Box<dyn Detector>>` and
runs each detector, merges results, and deduplicates overlapping spans before
returning to the tokenizer.

### 1.2 Updated Module Structure

```
src/
  detector/
    mod.rs          Detector trait, pipeline orchestration, span merge/dedup logic.
    regex.rs        RegexDetector — Rust regex recognizers, always available.
    ner.rs          NerDetector — optional Ollama NER client. Unchanged from original.
    presidio.rs     PresidioDetector — optional Presidio REST sidecar client. NEW.
```

No other modules change structurally. The tokenizer, vault, and detokenizer are
unaffected by this change — they consume `Vec<DetectedEntity>` regardless of which
detector produced them.

---

## 2. New Module: `src/detector/presidio.rs`

`PresidioDetector` is an async HTTP client that calls a locally-running Presidio
analyzer service and maps its response to `DetectedEntity` values.

### 2.1 Behaviour

- Calls Presidio's `POST /analyze` endpoint with the text and configured language.
- Maps Presidio entity type strings to privox `EntityType` variants where a mapping
  exists. Unknown Presidio entity types are mapped to `EntityType::Other(String)`.
- If the Presidio endpoint is unreachable or returns a non-200 response:
  - If `fallback_to_regex = true` (default): log a warning and return an empty
    result. The pipeline continues with results from other detectors.
  - If `fallback_to_regex = false`: return a `DetectorError::Unavailable` which
    causes the proxy to return a 503 to the caller with a structured error body.
- The Presidio anonymizer endpoint (`/anonymize`) is NOT used. privox handles
  tokenization internally using its own vault. Only the analyzer (`/analyze`) is
  called to get entity spans.
- The Presidio sidecar is responsible only for detection. privox owns tokenization,
  vault storage, and detokenization in all configurations.

### 2.2 Presidio Entity Type Mapping

| Presidio entity type | privox EntityType |
|---|---|
| `PERSON` | `EntityType::Person` |
| `EMAIL_ADDRESS` | `EntityType::Email` |
| `PHONE_NUMBER` | `EntityType::Phone` |
| `CREDIT_CARD` | `EntityType::CreditCard` |
| `IBAN_CODE` | `EntityType::Iban` |
| `US_SSN` | `EntityType::Ssn` |
| `CA_SIN` | `EntityType::Sin` |
| `IP_ADDRESS` | `EntityType::IpV4` |
| `URL` | `EntityType::Url` |
| `LOCATION` | `EntityType::Location` |
| `DATE_TIME` | `EntityType::DateTime` |
| `NRP` | `EntityType::Other("NRP".into())` |
| `MEDICAL_LICENSE` | `EntityType::Other("MEDICAL_LICENSE".into())` |
| *(any unrecognised)* | `EntityType::Other(type_string)` |

This mapping table MUST be kept in sync with Presidio's documented entity types.
The mapping lives in `detector/presidio.rs` as a `const` or `match` expression
with a comment linking to the Presidio entity types documentation URL.

### 2.3 Span Confidence Threshold

Presidio returns a confidence score (0.0–1.0) for each detected entity. The
`PresidioDetector` MUST apply a configurable minimum score threshold before
including an entity in results. Default threshold is `0.7`. Entities below
the threshold are silently discarded (logged at `trace` level only).

---

## 3. Changes to Configuration (extends REQUIREMENTS.md section 5.7)

The `[detection]` section of `config.toml` is replaced with the following:

```toml
[detection]
# Which backends to use. All listed backends run; results are merged.
# Valid values: "regex", "ner", "presidio"
# "regex" is always active regardless of this setting and does not need to be listed.
backends = ["regex"]   # default: regex only

[detection.ner]
enabled = false
url = "http://localhost:11434"
model = "qwen2.5:0.5b"
timeout_secs = 10

[detection.presidio]
analyzer_url = "http://localhost:5002"
timeout_secs = 5
language = "en"
score_threshold = 0.7
fallback_to_regex = true   # if presidio is unreachable, continue with regex results
```

The `backends` field controls which detectors are instantiated at startup. `"regex"`
is always active. Listing `"ner"` or `"presidio"` activates those backends in
addition to regex.

Environment variable overrides follow the existing pattern:
- `PRIVOX_DETECTION_PRESIDIO_ANALYZER_URL`
- `PRIVOX_DETECTION_PRESIDIO_SCORE_THRESHOLD`
- `PRIVOX_DETECTION_PRESIDIO_FALLBACK_TO_REGEX`

### 3.1 Startup Validation

If `"presidio"` is listed in `backends`, the proxy MUST attempt a connectivity
check to the analyzer URL during `privox check` and on startup at `debug` log level.
If the endpoint is unreachable at startup and `fallback_to_regex = false`, the
proxy MUST refuse to start with a clear error message. If `fallback_to_regex = true`,
the proxy MUST log a warning and start anyway.

---

## 4. Span Merge and Deduplication (new logic in `detector/mod.rs`)

When multiple detectors return results for the same text, the pipeline must merge
and deduplicate spans before tokenization.

Rules:
- If two spans from different detectors cover the same character range and agree on
  entity type, keep one and discard the duplicate.
- If two spans from different detectors overlap but do not agree on entity type,
  prefer the span from the higher-priority detector. Priority order (highest first):
  `PresidioDetector`, `NerDetector`, `RegexDetector`.
- If two spans from the same detector overlap (should not happen but must be handled),
  prefer the longer span.
- Non-overlapping spans from all detectors are always included.

This logic MUST have unit tests covering: identical spans, overlapping spans with
same type, overlapping spans with different types, adjacent non-overlapping spans,
and nested spans.

---

## 5. New Dependency

`async-trait` is added to the approved dependency list from REQUIREMENTS.md section 7.5:

| Crate | Justification |
|---|---|
| `async-trait` | Required for async methods in the `Detector` trait until async-in-traits is stable in the MSRV |

This is the only new dependency introduced by this addendum.

---

## 6. Changes to Testing Requirements (extends REQUIREMENTS.md section 7.2)

- Unit tests MUST cover `PresidioDetector` with a mock HTTP server standing in
  for the Presidio analyzer. Tests must cover: successful detection, HTTP error
  response, connection refused with `fallback_to_regex = true`, connection refused
  with `fallback_to_regex = false`, and score threshold filtering.
- The span merge/dedup logic MUST have unit tests as described in section 4 above.
- Integration tests MUST include a configuration that uses `RegexDetector` +
  `PresidioDetector` together with a mock Presidio server, verifying that merged
  results are correctly tokenized and detokenized end-to-end.

---

## 7. Changes to Documentation Requirements (extends REQUIREMENTS.md section 8)

### 7.1 README Updates

The README MUST include a "How privox compares to Presidio" section. It MUST be
honest. The following points MUST be covered:

- Presidio is a mature Python library with stronger NER quality than privox's
  built-in regex recognizers, especially for contextual entities like names and
  addresses.
- privox is not a replacement for Presidio's detection capability.
- privox provides what Presidio does not: a transparent OpenAI-compatible HTTP proxy,
  correct streaming detokenization across SSE chunk boundaries, an encrypted
  persistent vault for token-to-value mappings, and a single-binary deployment
  with no Python runtime dependency.
- When Presidio is available as a local sidecar, privox can use it as its detection
  backend while still handling all proxy, vault, and streaming concerns.
- The LiteLLM + Presidio stack does not support streaming detokenization. privox does.
- For Python applications already using LiteLLM, LiteLLM + Presidio may be the
  simpler choice. privox is the better fit for non-Python agents, binary deployments,
  or situations where streaming detokenization is required.

The README MUST NOT claim privox detects PII as accurately as Presidio in its
default (regex-only) configuration. It does not.

### 7.2 SECURITY.md Updates

The "Threat model" section of `SECURITY.md` MUST note that detection quality
directly affects the security guarantee: entities that are not detected are not
tokenized and will be seen by the upstream. The regex detector covers structured
PII reliably. Unstructured PII (names, organisations, addresses) requires the NER
or Presidio backend for meaningful coverage.

---

## 8. Implementation Order Guidance for Coding Agents

This section is guidance, not a hard requirement. It describes the recommended
order of implementation to minimise rework.

If the `detector/regex.rs` module is already implemented as a concrete type rather
than a trait implementation, the refactor to the `Detector` trait is the first task.
The steps are:

1. Define the `Detector` trait and `DetectorError` in `detector/mod.rs`.
2. Refactor `RegexDetector` in `detector/regex.rs` to implement `Detector`.
3. Refactor `NerDetector` in `detector/ner.rs` to implement `Detector` (if built).
4. Update `detector/mod.rs` pipeline to use `Vec<Box<dyn Detector>>`.
5. Confirm all existing tests still pass.
6. Implement `PresidioDetector` in `detector/presidio.rs`.
7. Update `config.rs` to support the new `[detection]` structure.
8. Update `server.rs` or wherever detectors are instantiated at startup.
9. Write new tests per section 6 above.

Do not implement `PresidioDetector` before the trait refactor is complete and
tested. The trait is the foundation; `PresidioDetector` is an addition on top.
