# SCRATCHPAD.md — privox

This file is written and maintained by coding agents. It is the handoff document
between sessions. Update it at the end of every session before stopping.
The human maintainer reads this to understand project state at a glance.

Do not delete history from this file. Append to it. Prepend new sessions at the top
of the relevant sections so the most recent state is always visible first.

---

## Current State

**Last updated:** 2026-05-24 — Session 2 (Claude Sonnet 4.6)
**Build status:** COMPILES
**Test status:** 51 passed, 0 failing
**Clippy:** CLEAN (`cargo clippy -- -D warnings` passes)
**Fmt:** CLEAN (`cargo fmt --check` produces no diff)

### What Is Done

- [x] Project scaffolding — `cargo init`, `Cargo.toml` with full approved dependency list,
      module stub files, `.rustfmt.toml`, `.gitignore`
- [x] `error.rs` — all error types defined, compiles, no unit tests needed
- [x] `types.rs` — `EntityType` (all variants incl. ADDENDUM-001 additions: `Phone`, `Url`,
      `DateTime`, `Other(String)`), `Token`, `DetectedEntity`, `TokenRecord`,
      `TokenizationResult`, `ChatMessage`, `MessageContent`, `ChatRequest`;
      `EntityType::from_str`/`to_storage_str`/`from_storage_str` roundtrip;
      10 unit tests passing
- [x] `config.rs` — full TOML loading, env override, validation; updated for ADDENDUM-001
      `[detection]` schema with `backends`, `[detection.presidio]`; 7 unit tests passing
- [x] `vault/crypto.rs` — AES-256-GCM encrypt/decrypt, PBKDF2 key derivation (100k iterations);
      8 unit tests passing
- [x] `vault/mod.rs` — `Vault` trait with `store`, `lookup`, `purge_expired`, `stats`,
      `clear_all`; `SqliteVault` re-export
- [x] `vault/sqlite.rs` — SQLite-backed vault, WAL mode, TTL expiry, AES-GCM encryption at rest;
      7 unit tests passing
- [x] `tokenizer.rs` — HMAC-SHA256 token generation (6 hex char shortid), deterministic,
      overlap resolution (longest-first), vault integration; 9 unit tests passing
- [x] `detector/mod.rs` — `Detector` trait (async-trait), `DetectorPriority` enum,
      `DetectorPipeline`, `merge_spans` deduplication; 7 unit tests passing
- [x] `detector/presidio.rs` — `PresidioDetector` stub implementing `Detector` trait;
      Presidio entity type mapping table; 3 unit tests passing
- [~] `detector/regex.rs` — stub only
- [~] `detector/ner.rs` — stub only
- [~] `detokenizer.rs` — stub only
- [~] `proxy.rs` — stub only
- [~] `server.rs` — stub only
- [~] `main.rs` — module declarations only, no business logic
- [ ] Integration tests — non-streaming
- [ ] Integration tests — streaming
- [ ] CLI subcommands (vault purge, vault stats, vault clear, check)
- [ ] README.md
- [ ] CONTRIBUTING.md
- [ ] SECURITY.md
- [ ] CHANGELOG.md
- [ ] GitHub Actions CI workflow

---

## Active Task

Implement the next layer of modules in dependency order. The detector and vault layers
are now complete; the remaining work is the detection logic and the HTTP pipeline.

### Next up: `detector/regex.rs`

Implement all regex-based entity detectors from REQUIREMENTS.md §5.2.
The `RegexDetector` must implement the `Detector` trait from `detector/mod.rs`.

For each entity type, document the standard or rationale and write at least one
positive and one negative test case:

1. `EMAIL` — RFC 5321 simplified; use `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
2. `PHONE_CA` / `PHONE_US` — covers `(NXX) NXX-XXXX`, `NXX-NXX-XXXX`, `+1NXXXXXXXXX`,
   and variations. NXX means first digit 2–9.
3. `CREDIT_CARD` — 13–19 digits, spaces/hyphens allowed, Luhn-valid.
   Implement Luhn validation in Rust (not just regex).
4. `SIN` — 9 digits, optional spaces/hyphens: `\d{3}[ -]?\d{3}[ -]?\d{3}`
5. `SSN` — `\d{3}-\d{2}-\d{4}` or with spaces
6. `IBAN` — `[A-Z]{2}\d{2}[A-Z0-9]{11,30}` structural pattern; use structural regex only
   (Luhn-like checksum verification is out of scope for v1 unless simple)
7. `IPV4` — `\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\b`
8. `IPV6` — simplified; match `[:0-9a-fA-F]{2,39}` with at least two colons
9. `API_KEY` — patterns for `sk-[a-zA-Z0-9]+`, `ghp_[a-zA-Z0-9]+`,
   `xoxb-[a-zA-Z0-9-]+`, `AIza[a-zA-Z0-9_-]+`, `Bearer [a-zA-Z0-9._-]+`
10. `URL_WITH_CREDENTIALS` — `https?://[^:@\s]+:[^@\s]+@[^\s]+`
11. `UUID` — standard UUID v4 format

All patterns should be pre-compiled in a `lazy_static!` or `OnceLock<Regex>`.
`RegexDetector` is synchronous (since regex is instant) but wraps the `async fn detect`
interface required by the `Detector` trait.

### Then: `detector/ner.rs`

Implement `NerDetector` as a reqwest client calling Ollama's `/api/generate` endpoint
with a structured NER prompt. Map named entity tags in the response to `DetectedEntity`.
Must degrade gracefully when Ollama is unavailable.

### Then: `detokenizer.rs`

Implement response scanning and token substitution:
1. Regex to find tokens matching `[A-Z_]+_[0-9a-f]{6}` in response text.
2. For each token found, look up in vault, substitute original value.
3. If no vault entry, leave token unchanged and log a warning (with token ID only,
   never the value since we don't have it).
4. Streaming variant: use a 64-byte sliding window buffer to handle tokens
   split across SSE chunk boundaries.

### Then: `proxy.rs` and `server.rs`

These wire together the full pipeline: parse → detect → tokenize → forward → detokenize.

---

## Failing Tests

None — 51 tests passing.

---

## Decisions Made

### 2026-05-24 — ADDENDUM-001 entity types reconciled with original REQUIREMENTS.md
The addendum's Presidio mapping table uses type names slightly different from the
original REQUIREMENTS.md:
- Addendum uses `IpV4` in one place; original and implementation use `Ipv4`. Treated
  as a typo in the addendum; implementation uses `Ipv4`.
- Added three new EntityType variants: `Phone` (generic from Presidio), `Url` (generic),
  `DateTime` (from Presidio DATE_TIME). These have no regex equivalents.
- `Other(String)` added as a catch-all for unknown Presidio types.
- `token_prefix()` return type changed from `&'static str` to `Cow<'static, str>` to
  support dynamic prefixes for `Other(String)`.
- `requires_optional_backend()` replaces `is_ner_only()` semantically (covers NER + Presidio).
  Method kept as `requires_optional_backend` since it was never used externally.

### 2026-05-24 — Vault stores raw bytes; SqliteVault re-encrypts them
`TokenRecord.encrypted_value` is named as if it holds ciphertext, but at the point
where the tokenizer creates the record it actually holds the plaintext bytes. The vault's
`store()` method handles the actual AES-GCM encryption. This naming is a mild misnomer;
comments explain the flow. Consider renaming `encrypted_value` to `raw_value` in the
next refactor pass if it causes confusion.

### 2026-05-24 — `#![allow(dead_code, unused_imports)]` suppression in `main.rs`
During scaffolding, pub items and re-exports are unused because stub modules don't
reference them. Added crate-level allows with comment. MUST be removed when server.rs
is wired up.

### 2026-05-24 — `Token` short ID length: 6 hex chars (3 bytes of HMAC-SHA256)
At 50 entities/session, birthday collision probability ≈ 0.01%. Acceptable for v1.
Flagged for human review.

### 2026-05-24 — `rustfmt.toml` uses stable-only options
Nightly-only options silently ignored on stable. Restricted to stable options only.

### 2026-05-24 — `UrlWithCredentials` token prefix is `URL_CRED`
Keeps tokens readable. Only affects `EntityType::token_prefix()`.

---

## Dead Ends

None yet.

---

## Tips and Gotchas

- rusqlite WAL mode must be set immediately after opening the connection, before
  any reads or writes. Setting it later silently has no effect. (Implemented correctly
  in SqliteVault::open().)
- AES-GCM nonce must be unique per encryption operation. `vault/crypto.rs::encrypt()`
  generates a fresh random nonce on every call via `rand::thread_rng().fill_bytes()`.
- `async-trait` is required for `Box<dyn Detector>` because Rust 1.75's native async
  traits are not object-safe for `dyn`. See Open Question Q6.
- axum's streaming response type is `axum::response::Sse<S>`. The stream item
  type must be `Result<Event, E>` where E: Into<BoxError>.
- reqwest's streaming body is accessed via `.bytes_stream()` which returns a
  `Stream<Item = Result<Bytes, reqwest::Error>>`. Map errors before chaining.
- `cargo fmt` on Windows writes Unix line endings per `.rustfmt.toml`. Fine.
- Several rustfmt options are nightly-only. Do not add them to `.rustfmt.toml`.
- The hard-linking warning from cargo on the Z: drive is a filesystem artifact
  (SMB mount). Not a code issue.
- For regex patterns: pre-compile with `OnceLock<Regex>` (std, no extra dep) or
  `lazy_static!`. The `regex` crate is expensive to construct; compile once at startup.

---

## Open Questions Requiring Human Input

### ADDENDUM-001 — New open question

**Q6: async-trait vs native async traits (RESOLVED for now)**
Using `async-trait` as the addendum requires. Native async traits in Rust 1.75
are not object-safe (can't use `Box<dyn Detector>` without `async-trait`).
`async-trait` is the correct choice. Will revisit if MSRV is raised past 1.82
(when RPITIT in traits + dyn compatibility improves).

From `REQUIREMENTS.md` section 12:

1. **Token stability across restarts** — PLANNED: use installation secret for stability.
   Implemented as HMAC(original_value, installation_secret) in tokenizer.rs.

2. **Per-type vault TTL** — PLANNED: single global TTL for v1. Implemented.

3. **Tool call argument detection** — Not yet decided. Affects detector/mod.rs and server.rs.

4. **Passthrough for unknown endpoints** — Not yet decided. Affects server.rs.

5. **Secret rotation subcommand** — Not yet decided. Affects CLI in main.rs.

6. **Token short ID length** — Using 6 hex chars (3 bytes). Confirm or override.

---

## Session Log

### Session 2 — 2026-05-24
Agent: Claude Sonnet 4.6
Completed: Read and integrated REQUIREMENTS_ADDENDUM_001.md. Updated `Cargo.toml`
(added `async-trait`). Updated `types.rs` (new EntityType variants: Phone, Url,
DateTime, Other; Cow return from token_prefix; from_str/to_storage_str). Implemented
`config.rs` (full TOML+env, new detection schema, 7 tests). Implemented
`vault/crypto.rs` (AES-GCM, PBKDF2, 8 tests). Implemented `vault/mod.rs` (Vault trait).
Implemented `vault/sqlite.rs` (SQLite WAL, TTL expiry, 7 tests). Implemented
`tokenizer.rs` (HMAC-SHA256 tokens, 9 tests). Implemented `detector/mod.rs` (Detector
trait, pipeline, merge_spans with 7 tests). Created `detector/presidio.rs` (stub +
entity mapping table + 3 tests).
Build state at stop: COMPILES, 51 tests passing, clippy clean, fmt clean.
Next: Implement `detector/regex.rs` (see Active Task section above).

### Addendum injection — 2026-05-24
Human maintainer issued REQUIREMENTS_ADDENDUM_001.md.
Build state at injection: COMPILES, 6 tests passing, clippy clean, fmt clean.

### Session 1 — 2026-05-24
Agent: Claude Sonnet 4.6
Completed: Project scaffolding, `Cargo.toml`, all module stubs, `.rustfmt.toml`,
`error.rs`, `types.rs` (original 6 tests).
Build state at stop: COMPILES, 6 tests passing, clippy clean, fmt clean.
