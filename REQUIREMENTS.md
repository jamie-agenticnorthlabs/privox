# Requirements: `privox` — Privacy Proxy for LLM Calls

**Project codename:** `privox`
**Language:** Rust
**License:** MIT
**Status:** Pre-implementation requirements document

---

## 1. Purpose and Scope

`privox` is a lightweight, transparent, drop-in proxy that sits between an AI agent or application and any OpenAI-compatible LLM inference endpoint. It intercepts outbound requests, detects and tokenizes sensitive entities in the prompt payload, forwards the sanitized request to the configured upstream, and detokenizes the response before returning it to the caller.

The caller does not change its code. It points at `privox` instead of the inference endpoint. Everything else stays the same.

The project is scoped deliberately. It does one thing well: tokenize and detokenize PII and sensitive values around LLM calls. It does not attempt to be a general-purpose API gateway, an observability platform, or a model router. Scope creep is a design failure for this project.

---

## 2. Goals

- Drop-in replacement for any OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM, OpenRouter, OpenAI, Anthropic via OpenAI-compat shim).
- Zero changes required to the calling application.
- PII and sensitive entity detection runs locally with no external service dependencies.
- Token-to-value mapping vault stays on-disk, encrypted, never leaves the host.
- Streaming responses (`text/event-stream`) are supported with correct detokenization across chunks.
- Single binary with a single config file. No runtime dependencies.
- Suitable for local developer use, self-hosted agent deployments (OpenClaw, Hermes, etc.), and small team infrastructure.
- Code quality and documentation are first-class requirements, not afterthoughts.

---

## 3. Non-Goals

The following are explicitly out of scope for v1:

- Multi-host or distributed vault replication.
- Authentication or API key management for upstream providers.
- Model routing or load balancing.
- Observability, metrics export, or tracing infrastructure (logging is sufficient for v1).
- A web UI or dashboard.
- Plugin systems or dynamic extension loading.
- Training data pipeline integration.
- Rate limiting or quota enforcement.
- Fine-grained per-user policy (single policy config is sufficient for v1).

These may be appropriate for future versions and should be noted in the roadmap, but they must not influence the v1 architecture.

---

## 4. Architecture Overview

```
Calling App / Agent
       |
       | POST /v1/chat/completions  (OpenAI-compatible)
       v
  ┌──────────────────────────────────────────────┐
  │                  privox                       │
  │                                              │
  │  ┌──────────┐   ┌──────────┐  ┌───────────┐ │
  │  │  Inbound │   │ Detector │  │   Vault   │ │
  │  │  Parser  │──►│  Engine  │─►│  (SQLite/ │ │
  │  └──────────┘   └──────────┘  │  AES-256) │ │
  │        │                      └───────────┘ │
  │        │  tokenized request                  │
  │        v                                     │
  │  ┌──────────┐                                │
  │  │  Proxy   │──────────────────────────────► upstream
  │  │  Client  │◄────────────────────────────── upstream
  │  └──────────┘                                │
  │        │  raw response (possibly streaming)  │
  │        v                                     │
  │  ┌──────────────┐   ┌───────────┐            │
  │  │  Detokenizer │◄──│   Vault   │            │
  │  └──────────────┘   └───────────┘            │
  │        │                                     │
  └────────┼────────────────────────────────────-┘
           │  detokenized response
           v
  Calling App / Agent
```

Every request passes through four stages:

1. **Parse** — deserialize the incoming OpenAI-compatible request body.
2. **Detect and tokenize** — identify sensitive entities in all message content fields, replace with stable tokens, persist the mapping to the vault.
3. **Forward** — proxy the sanitized request to the configured upstream and receive the response (or stream).
4. **Detokenize** — scan the response content for known tokens, restore original values, return to caller.

Each stage is a distinct module with a defined interface. The stages must be independently testable.

---

## 5. Functional Requirements

### 5.1 Transparent Proxy

- MUST expose an HTTP server on a configurable host and port (default: `127.0.0.1:11435`).
- MUST implement `POST /v1/chat/completions` fully compatible with the OpenAI API schema.
- MUST pass through all request fields it does not need to inspect unchanged (model, temperature, max_tokens, tools, tool_choice, etc.).
- MUST pass through all response fields unchanged other than detokenizing message content.
- MUST support both non-streaming (`"stream": false`) and streaming (`"stream": true`, `text/event-stream`) modes.
- MUST preserve HTTP headers the upstream returns (except headers managed by the proxy itself such as `Content-Length`).
- SHOULD support `POST /v1/completions` (legacy completions endpoint) with the same tokenization behaviour applied to the `prompt` field.
- MAY pass through unknown endpoints to the upstream unchanged (passthrough mode) so that tools like `/v1/models` work without additional implementation.

### 5.2 Detection Engine

The detector identifies sensitive entities in text and returns a list of `(span_start, span_end, entity_type, original_value)` tuples.

**Regex-based detectors (always active, zero latency):**

| Entity type | Examples |
|---|---|
| `EMAIL` | `user@example.com` |
| `PHONE_CA` | `(519) 555-1234`, `519-555-1234`, `+15195551234` |
| `PHONE_US` | same pattern as CA for v1 |
| `CREDIT_CARD` | 13–19 digit Luhn-valid card numbers |
| `SIN` | Canadian Social Insurance Numbers (9-digit, space/dash separated) |
| `SSN` | US Social Security Numbers |
| `IBAN` | IBAN format strings |
| `IPV4` | IPv4 addresses |
| `IPV6` | IPv6 addresses |
| `API_KEY` | Common patterns: `sk-...`, `Bearer ...` tokens, `ghp_...`, `xoxb-...`, `AIza...` |
| `URL_WITH_CREDENTIALS` | `https://user:pass@host` |
| `UUID` | Standard UUID v4 format |

Regex patterns MUST be documented in source with the authority or reference used (RFC, standard, or explicit rationale). False positive rate is a known tradeoff; documentation must be honest about it.

**Local NER-based detectors (optional, configurable):**

When a local Ollama endpoint is configured, the detector MAY send text to a small local model (e.g. `llama3.2:1b` or `qwen2.5:0.5b`) for contextual entity detection. This is opt-in. Entities detected by NER but not by regex:

- `PERSON` — names
- `ORG` — company and organization names
- `LOCATION` — addresses and place names
- `DATE_OF_BIRTH` — dates in personal context
- `ACCOUNT_NUMBER` — contextually identified account references

NER detection MUST only trigger if `ner.enabled = true` in config. When enabled, if the local NER endpoint is unavailable the proxy MUST log a warning and continue with regex-only detection, never fail the request.

**Detection scope:**

The detector MUST be applied to all `content` fields in the `messages` array, including `system`, `user`, and `assistant` role messages. It MUST also be applied to `tool_call` result content and `function` call arguments. It MUST NOT be applied to non-content fields (model name, temperature, etc.).

### 5.3 Tokenization

- Tokens MUST be stable and deterministic for the same `(entity_type, original_value)` pair within a session.
- Token format MUST be readable and preserve semantic context for the model: `ENTITY_TYPE_shortid`, e.g. `EMAIL_a3f2`, `PERSON_9c1d`.
- The `shortid` component MUST be a truncated HMAC-SHA256 of the original value, keyed with a per-installation secret, represented as lowercase hex. This prevents token guessing while keeping tokens short.
- Tokens MUST be unique per value. Two different values of the same type MUST produce different tokens.
- The full mapping `(token, entity_type, original_value, session_id, created_at)` MUST be persisted to the vault.

### 5.4 Vault

- The vault is a local SQLite database stored at a configurable path (default: `~/.privox/vault.db`).
- All `original_value` fields MUST be encrypted at rest using AES-256-GCM with a key derived from the installation secret via PBKDF2-HMAC-SHA256.
- The installation secret is generated on first run and stored in a separate file (`~/.privox/secret.key`) with permissions `0600`. If the file is missing on startup, `privox` MUST refuse to start with a clear error message rather than generating a new secret (which would break all existing mappings).
- Vault entries MUST include a `created_at` timestamp and a `session_id` (a UUID generated per proxy process start, or per-request if configured).
- Vault entries MUST support TTL-based expiry. Default TTL is configurable; default value is 24 hours. Expired entries MUST be purged on startup and periodically during operation.
- The vault MUST be the only component that holds plaintext values. No other component in the system logs, stores, or returns original values except through the detokenizer.

### 5.5 Detokenization

- After receiving the upstream response, the detokenizer MUST scan all text content in the response for known token patterns.
- For each token found, the detokenizer MUST look up the original value in the vault and substitute it.
- If a token is found in the response but has no matching vault entry (e.g. expired TTL), the proxy MUST:
  - Leave the token in the response unchanged.
  - Log a warning with the token identifier but NOT the original value.
  - NOT fail the response.
- For streaming responses, detokenization MUST be applied correctly across SSE chunk boundaries. A token split across two chunks MUST be reassembled before substitution.

### 5.6 Streaming Support

Streaming is a first-class requirement, not an afterthought.

- The proxy MUST correctly handle `text/event-stream` responses from the upstream.
- Each SSE `data:` chunk MUST be parsed, its `delta.content` field detokenized, and re-serialized before forwarding to the caller.
- The proxy MUST buffer enough of the stream to detect tokens that span chunk boundaries. A sliding window of at least 64 bytes of unforwarded content is sufficient for v1.
- The proxy MUST forward chunks as they arrive; it MUST NOT buffer the entire stream before forwarding.
- The `[DONE]` sentinel MUST be forwarded unchanged.
- If the upstream closes the stream unexpectedly, the proxy MUST close the caller's stream cleanly and log the event.

### 5.7 Configuration

Configuration is loaded from a single TOML file. The default path is `~/.privox/config.toml`. An alternative path can be passed via `--config` CLI flag or `PRIVOX_CONFIG` environment variable.

**Required config fields:**

```toml
[proxy]
listen = "127.0.0.1:11435"   # address to bind

[upstream]
url = "http://localhost:11434"  # upstream OpenAI-compatible base URL
timeout_secs = 120

[vault]
path = "~/.privox/vault.db"
ttl_hours = 24

[detection]
# Regex detection is always on.
# NER detection requires a local Ollama endpoint.
[detection.ner]
enabled = false
url = "http://localhost:11434"
model = "qwen2.5:0.5b"
timeout_secs = 10

[log]
level = "info"   # trace | debug | info | warn | error
```

All fields MUST have documented defaults. Fields that have no reasonable default MUST be required and the proxy MUST fail on startup with a clear error if they are missing.

Environment variable overrides MUST be supported for all fields using the pattern `PRIVOX_PROXY_LISTEN`, `PRIVOX_UPSTREAM_URL`, etc. (prefix `PRIVOX_`, section name and field name uppercase, joined with `_`).

### 5.8 CLI

```
privox [OPTIONS]

OPTIONS:
    --config <PATH>     Path to config file [env: PRIVOX_CONFIG]
    --listen <ADDR>     Override listen address [env: PRIVOX_PROXY_LISTEN]
    --upstream <URL>    Override upstream URL [env: PRIVOX_UPSTREAM_URL]
    --log-level <LEVEL> Override log level [env: PRIVOX_LOG_LEVEL]
    --version           Print version and exit
    --help              Print help and exit

SUBCOMMANDS:
    privox vault purge             Purge all expired vault entries and exit
    privox vault stats             Print vault entry counts by entity type and exit
    privox vault clear             Clear all vault entries and exit (requires --confirm)
    privox check                   Validate config and connectivity, print status, exit
```

---

## 6. Non-Functional Requirements

### 6.1 Performance

- Added latency for non-streaming requests (excluding NER if disabled) MUST be less than 5ms on a modern laptop for typical chat completion payloads (under 4KB).
- Added latency for streaming responses MUST be imperceptible to a human reader; chunk-forwarding delay MUST be less than 1ms per chunk.
- The proxy MUST handle at least 50 concurrent in-flight requests without degradation on a single-core process.
- Vault reads and writes MUST not block the request path for more than 1ms under normal operating conditions.

### 6.2 Reliability

- A panic in the request handler MUST be caught and return a 500 response to the caller. The proxy process MUST NOT crash on a malformed request.
- If the upstream is unreachable, the proxy MUST return a structured error response in OpenAI error format and log the failure. It MUST NOT return a raw connection error to the caller.
- The vault MUST use SQLite WAL mode to prevent corruption on unclean shutdown.
- The proxy MUST handle SIGTERM and SIGINT gracefully: finish in-flight requests, flush the vault write-ahead log, and exit cleanly.

### 6.3 Security

- The vault encryption key MUST be derived from the installation secret using PBKDF2-HMAC-SHA256 with at least 100,000 iterations.
- The installation secret file MUST be created with `0600` permissions on Unix. On startup the proxy MUST verify these permissions and refuse to start if they are weaker.
- The proxy MUST NOT log original (pre-tokenization) values at any log level.
- The proxy MUST NOT include original values in error messages or responses.
- The proxy MUST NOT expose the vault contents via any HTTP endpoint.
- Dependencies MUST be kept minimal. Every dependency in `Cargo.toml` requires a justification comment.
- The project MUST pass `cargo audit` with no high-severity advisories before any release.

### 6.4 Observability

For v1, structured logging is sufficient. Metrics and tracing are out of scope.

- All log output MUST use structured JSON format at log level `info` and above.
- Every proxied request MUST produce a single log line at `info` level containing: request ID (UUID), method, path, upstream, entity types detected (not values, not counts that could reveal data), response status, total latency ms, and whether the request was streamed.
- Sensitive values MUST NEVER appear in log output at any level.
- Detection events MUST be logged at `debug` level with entity type and token only, never the original value.

---

## 7. Code Quality Requirements

These are non-negotiable for a project intended to be open source and trustworthy in a security context.

### 7.1 Correctness

- The codebase MUST compile with zero warnings under `cargo build --release`.
- `cargo clippy -- -D warnings` MUST pass with no suppressions except where a specific suppression is documented with an explicit rationale comment.
- `cargo fmt` MUST produce no diff. The repository MUST include a `.rustfmt.toml` with project formatting preferences documented.

### 7.2 Testing

- Unit tests MUST cover all detection regex patterns with at least one positive and one negative example per pattern.
- Unit tests MUST cover tokenization determinism: same input produces same token across calls.
- Unit tests MUST cover vault encryption round-trip: store and retrieve a value and verify equality.
- Unit tests MUST cover detokenization across simulated streaming chunk boundaries.
- Integration tests MUST start a mock upstream HTTP server, run the full request pipeline, and verify the upstream receives tokenized content and the caller receives detokenized content.
- Integration tests MUST cover the streaming path end-to-end.
- Test coverage MUST be measured with `cargo tarpaulin` or `cargo llvm-cov`. Coverage MUST be above 80% for all modules in `src/`. Coverage report MUST be generated in CI.
- Tests MUST use `assert!` and `assert_eq!` with informative failure messages, not just bare assertions.
- Test data MUST NOT contain real PII. Generated synthetic values MUST be used.

### 7.3 Error Handling

- The project MUST use `thiserror` for library error types and `anyhow` for application-level error propagation. Raw `unwrap()` and `expect()` are prohibited in non-test code except where truly unreachable, in which case a comment is required explaining why.
- Every `?` propagation in a public function MUST be traceable to a typed error variant.
- Error messages MUST be actionable: they MUST describe what failed and what the user can do about it.

### 7.4 Module Structure

The codebase MUST be organized into clearly named modules. Suggested structure:

```
src/
  main.rs          — CLI parsing, config loading, server startup
  config.rs        — Config struct, deserialization, validation, env overrides
  server.rs        — HTTP server, route handlers, request/response lifecycle
  proxy.rs         — Upstream HTTP client, streaming forwarder
  detector/
    mod.rs         — Detector trait and pipeline orchestration
    regex.rs       — All regex-based entity detectors
    ner.rs         — Optional NER client (Ollama)
  tokenizer.rs     — Tokenization logic, token generation
  detokenizer.rs   — Response scanning and token substitution, streaming support
  vault/
    mod.rs         — Vault trait and public API
    sqlite.rs      — SQLite-backed vault implementation
    crypto.rs      — AES-256-GCM encrypt/decrypt, key derivation
  error.rs         — Error types
  types.rs         — Shared types (entity types, token records, etc.)
tests/
  integration/
    proxy_test.rs  — End-to-end proxy tests with mock upstream
    streaming_test.rs
```

No module SHOULD be longer than 400 lines. If a module approaches this, split it.

### 7.5 Dependencies

Dependencies MUST be justified. The following are approved with rationale:

| Crate | Justification |
|---|---|
| `tokio` | Async runtime |
| `axum` | HTTP server framework, well-maintained, built on tokio |
| `reqwest` | HTTP client for upstream calls, async, TLS support |
| `serde` + `serde_json` | JSON serialization for OpenAI protocol |
| `toml` | Config file parsing |
| `rusqlite` | SQLite vault storage |
| `aes-gcm` | AES-256-GCM encryption for vault |
| `pbkdf2` + `hmac` + `sha2` | Key derivation and HMAC for token generation |
| `regex` | Regex-based entity detection |
| `uuid` | Request IDs and session IDs |
| `tracing` + `tracing-subscriber` | Structured logging |
| `thiserror` | Library error types |
| `anyhow` | Application error propagation |
| `clap` | CLI argument parsing |
| `rand` | Secure random for key generation |

Any dependency not on this list requires a justification comment in `Cargo.toml` before it can be merged.

---

## 8. Documentation Requirements

Documentation is a first-class deliverable, not a release afterthought.

### 8.1 README

The root `README.md` MUST include:

- One-paragraph description of what `privox` does and who it is for.
- A "How it works" section with a simple ASCII diagram (the one from section 4 of this document is a good starting point).
- A "Quickstart" section covering: install, generate config, run, verify with `curl`.
- A configuration reference table documenting every config field, its type, default, and a one-line description.
- A "Supported entity types" table.
- A "Tested with" section listing confirmed compatible upstreams (Ollama, llama.cpp server, vLLM, OpenRouter, OpenAI).
- A "Security model" section that is honest about what `privox` does and does not guarantee.
- Contributing guidelines link.
- License badge and text.

The README MUST NOT oversell the security guarantees of the project. It MUST include a section that explicitly states: "privox reduces what upstream providers see. It is not a guarantee of privacy and is not a substitute for proper data governance."

### 8.2 Inline Documentation

- Every `pub` function, struct, enum, and trait MUST have a Rustdoc comment.
- Rustdoc comments MUST include an example for any non-trivial public function.
- `cargo doc --no-deps` MUST produce zero warnings.
- Complex or security-sensitive logic MUST include an inline comment explaining the reasoning, not just what the code does.
- All regex patterns MUST be documented with the standard or rationale they implement, and a human-readable description of what they match.

### 8.3 CHANGELOG

The repository MUST include a `CHANGELOG.md` following the Keep a Changelog format (`https://keepachangelog.com`). Every PR that changes user-visible behaviour MUST include a CHANGELOG entry.

### 8.4 CONTRIBUTING

A `CONTRIBUTING.md` MUST document:

- How to set up the development environment.
- How to run tests (`cargo test`, `cargo clippy`, `cargo fmt --check`).
- The PR process and review expectations.
- The dependency policy (section 7.5).
- The commitment to not logging PII in any form, and why this matters.
- How to report security vulnerabilities (private disclosure via email, not GitHub Issues).

### 8.5 SECURITY

A `SECURITY.md` MUST document:

- The threat model: what `privox` protects against and what it does not.
- The vault encryption scheme and key derivation parameters.
- How to report a vulnerability.
- The process for publishing security advisories.

---

## 9. Release and CI Requirements

### 9.1 CI Pipeline

A GitHub Actions workflow MUST run on every PR and push to `main`:

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo audit`
- Coverage report generation (informational, not a gate for v1, but MUST be measured)

Matrix MUST include: `ubuntu-latest`, `macos-latest`. Windows is optional for v1.

### 9.2 Releases

- Releases MUST be tagged as `v{semver}` and MUST include a GitHub release with release notes drawn from CHANGELOG.
- Release binaries MUST be built via GitHub Actions for: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.
- Binaries MUST be statically linked where possible.

### 9.3 Versioning

The project follows Semantic Versioning. Until v1.0.0, minor version bumps may include breaking config or API changes, but these MUST be documented in CHANGELOG.

---

## 10. Explicit Design Constraints

These constraints encode decisions that MUST NOT be reversed without deliberate discussion and a documented rationale.

1. **The vault never leaves the host.** There is no sync, no export endpoint, no remote backup. This is a feature, not a limitation.

2. **Original values never touch logs.** No log level, no debug mode, no exception. If a developer needs to debug a tokenization issue, they use the `vault stats` subcommand or inspect the encrypted vault directly with the provided tooling.

3. **The proxy is not aware of which user sent a request.** There is no authentication, no user identity, no per-user policy. It is a single-tenant tool. Multi-tenancy is out of scope for v1.

4. **NER is opt-in and local only.** The proxy will never call an external NER or classification API to perform entity detection. If NER is enabled and the local endpoint is down, the proxy degrades gracefully to regex-only.

5. **Simplicity beats features.** When in doubt, do not add it. A focused tool that does one thing correctly is more valuable than a sprawling one that does ten things inconsistently. New features require a written rationale before implementation begins.

---

## 11. Suggested Project Name and Metadata

**Name:** `privox`
**Tagline:** Privacy proxy for LLM calls.
**Repository name:** `privox`
**Crate name:** `privox`
**Binary name:** `privox`

`Cargo.toml` metadata:

```toml
[package]
name = "privox"
version = "0.1.0"
edition = "2021"
description = "Privacy proxy for LLM calls — transparent PII tokenization for OpenAI-compatible inference endpoints"
license = "MIT"
repository = "https://github.com/YOUR_ORG/privox"
keywords = ["llm", "privacy", "pii", "proxy", "openai"]
categories = ["network-programming", "cryptography"]
rust-version = "1.75"
```

---

## 12. Open Questions for Pre-Implementation Review

These questions SHOULD be answered before implementation begins. They do not block requirements finalization but will affect implementation decisions.

1. **Token stability across restarts.** Tokens are generated as HMAC of the value keyed with the installation secret. This means the same value always produces the same token for a given installation, even across restarts. This is useful for long-running agents. Is this the desired behaviour, or should tokens be session-scoped only?

2. **Vault TTL granularity.** A global TTL is specified in config. Should entity types have individual TTLs (e.g. API keys expire after 1 hour, names after 24 hours)? For v1, a single TTL is simpler. A per-type TTL config is a clean extension.

3. **Handling tool calls and structured outputs.** The OpenAI tool call format includes `function.arguments` as a JSON string and `tool_call` results as message content. The current requirements apply detection to these fields. Is there any case where structured JSON arguments should be exempted from detection (e.g. to avoid mangling structured data the agent intentionally constructs)?

4. **Passthrough mode for unknown endpoints.** Should `privox` silently pass through any request it does not recognize (`/v1/models`, `/v1/embeddings`, etc.) to the upstream, or should it return a 501 for unimplemented endpoints? Passthrough is more compatible but slightly harder to audit.

5. **Installation secret rotation.** If the secret is rotated, all existing vault entries become undecryptable. Should `privox` provide a `vault rotate-secret` subcommand that re-encrypts all entries? Or is the expected behaviour "clear vault, generate new secret"?
