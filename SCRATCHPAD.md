# SCRATCHPAD.md — privox

This file is written and maintained by coding agents. It is the handoff document
between sessions. Update it at the end of every session before stopping.
The human maintainer reads this to understand project state at a glance.

Do not delete history from this file. Append to it. Prepend new sessions at the top
of the relevant sections so the most recent state is always visible first.

---

## Current State

**Last updated:** 2026-05-24 — Session 3 (Claude Sonnet 4.6)
**Build status:** COMPILES
**Test status:** 108 passed, 0 failing
**Clippy:** CLEAN (`cargo clippy -- -D warnings` passes)
**Fmt:** CLEAN (`cargo fmt --check` produces no diff)
**Git:** 5 commits on main, ahead of origin/main by 5 (push pending — user in remote session)

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
      Presidio entity type mapping table; `new(PresidioConfig)` signature; 3 unit tests passing
- [x] `detector/regex.rs` — 11 patterns (OnceLock), Luhn validation, 34 unit tests passing
- [x] `detector/ner.rs` — Ollama `/api/generate` client, NER prompt, JSON response parsing,
      graceful degradation on connect/timeout; 12 unit tests passing
- [x] `detokenizer.rs` — `Detokenizer` (bulk) + `StreamingDetokenizer` (64-byte sliding window);
      token regex `\b[A-Z_]+_[0-9a-f]{6}\b`; 11 unit tests passing
- [x] `proxy.rs` — `UpstreamClient` wrapping reqwest, timeout, `UpstreamError` mapping
- [x] `server.rs` — axum routes `/v1/chat/completions` + `/v1/completions`; four-stage pipeline
      (detect → tokenize → forward → detokenize); SSE streaming via mpsc channel +
      `ReceiverStream` + `StreamingDetokenizer`; synthetic delta events for buffered content
- [x] `main.rs` — clap CLI: `init`, `check`, `vault purge/stats/clear` subcommands;
      secret file management (0600 perms on Unix); tokio runtime bootstrap; JSON tracing
- [x] `README.md` — architecture diagram, quickstart, config reference, entity type table,
      security model; committed but push pending
- [ ] Integration tests — non-streaming
- [ ] Integration tests — streaming
- [ ] `detector/presidio.rs` — full HTTP client implementation (currently stub `Ok(vec![])`)
- [ ] CONTRIBUTING.md
- [ ] SECURITY.md
- [ ] CHANGELOG.md
- [ ] GitHub Actions CI workflow

---

## Active Task

No active task. Session 3 completed all core HTTP pipeline modules. Push pending.

**Next session should start with:**
1. Push all pending commits to GitHub (user runs `git push origin main` when home)
2. Write integration tests (`tests/integration/proxy_test.rs`, `tests/integration/streaming_test.rs`)
3. Implement `detector/presidio.rs` HTTP client (see TODO comments in file)
4. GitHub Actions CI workflow

---

## Failing Tests

None — 108 tests passing.

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

### Session 3 — 2026-05-24
Agent: Claude Sonnet 4.6
Completed: `detector/regex.rs` (11 patterns, Luhn, 34 tests), `detector/ner.rs` (Ollama
client, NER prompt, JSON parsing, graceful degradation, 12 tests), `detokenizer.rs`
(bulk + 64-byte streaming sliding window, 11 tests), `proxy.rs` (UpstreamClient),
`server.rs` (axum routes, four-stage pipeline, SSE streaming via mpsc+ReceiverStream),
`main.rs` (full CLI wired up). Fixed 17 clippy errors during wiring. Added tokio-stream
dep for ReceiverStream. README.md committed. All commits pending push to GitHub (user
in remote session without interactive git auth).
Build state at stop: COMPILES, 108 tests passing, clippy clean, fmt clean.
Next: push to GitHub, integration tests, presidio HTTP client impl, CI workflow.

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
