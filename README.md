# privox

A lightweight, transparent privacy proxy for OpenAI-compatible LLM endpoints. It sits between your application and any inference server, automatically detecting and tokenizing PII in outbound prompts, then restoring original values in responses — with zero changes required to your calling application.

## How it works

```
Your App / Agent
      │
      │ POST /v1/chat/completions
      ▼
┌─────────────────────────────────────┐
│              privox                  │
│                                     │
│  Parser → Detector → Tokenizer      │
│                  ↕                  │
│              Vault (AES-256-GCM)    │
│                                     │
│  Proxy Client ←→ upstream           │
│                                     │
│  Detokenizer ← Vault                │
└─────────────────────────────────────┘
      │
      │ detokenized response
      ▼
Your App / Agent
```

Every request passes through four stages:

1. **Parse** — deserialize the incoming OpenAI-compatible request.
2. **Detect & tokenize** — find sensitive entities in all message content, replace with stable tokens (e.g. `EMAIL_a3f2c1`), persist the mapping to the encrypted vault.
3. **Forward** — proxy the sanitized request to the configured upstream; receive the response.
4. **Detokenize** — scan the response for known tokens, restore original values, return to caller.

Your application sees its original data. The upstream LLM never sees it.

## Features

- **Drop-in replacement** for any OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM, OpenRouter, OpenAI, Anthropic via OpenAI-compat shim)
- **Zero code changes** required in your calling application
- **Regex-based detection** (always active, zero latency): email, phone numbers (CA/US), credit cards with Luhn validation, SIN, SSN, IBAN, IPv4, IPv6, API keys, URLs with credentials, UUIDs
- **Local NER detection** (optional): person names, organizations, locations, dates of birth, account numbers — via a locally-running Ollama model
- **Presidio integration** (optional): connect to a self-hosted Presidio analyzer for additional entity types
- **Stable, deterministic tokens**: same value always produces the same token within an installation, so long-running agents see consistent identifiers
- **Encrypted vault**: all original values stored AES-256-GCM encrypted on-disk; key derived via PBKDF2-HMAC-SHA256
- **Streaming support**: correct detokenization across SSE chunk boundaries, chunks forwarded as they arrive
- **Single binary, single config file**: no runtime dependencies, no external services required

## Quickstart

```sh
# 1. Build
cargo build --release

# 2. Create a minimal config
mkdir -p ~/.privox
cat > ~/.privox/config.toml << 'EOF'
[proxy]
listen = "127.0.0.1:11435"

[upstream]
url = "http://localhost:11434"   # your Ollama / vLLM / etc. endpoint
timeout_secs = 120

[vault]
path = "~/.privox/vault.db"
ttl_hours = 24

[log]
level = "info"
EOF

# 3. Run
./target/release/privox

# 4. Point your application at privox instead of the upstream
# e.g. set OPENAI_BASE_URL=http://127.0.0.1:11435/v1
```

## Configuration

The default config path is `~/.privox/config.toml`. Override with `--config <path>` or `PRIVOX_CONFIG=<path>`.

```toml
[proxy]
listen = "127.0.0.1:11435"

[upstream]
url = "http://localhost:11434"
timeout_secs = 120

[vault]
path = "~/.privox/vault.db"
ttl_hours = 24

[detection]
# Detectors to enable. "regex" is always active.
# Add "ner" to enable Ollama-based NER, "presidio" for Presidio integration.
backends = ["regex"]

[detection.ner]
enabled = false
ollama_url = "http://localhost:11434"
model = "llama3.2:1b"

[detection.presidio]
analyzer_url = "http://localhost:5002"
score_threshold = 0.7
fallback_to_regex = true

[log]
level = "info"   # trace | debug | info | warn | error
```

### Environment variable overrides

| Variable | Overrides |
|---|---|
| `PRIVOX_PROXY_LISTEN` | `proxy.listen` |
| `PRIVOX_UPSTREAM_URL` | `upstream.url` |
| `PRIVOX_UPSTREAM_TIMEOUT_SECS` | `upstream.timeout_secs` |
| `PRIVOX_VAULT_PATH` | `vault.path` |
| `PRIVOX_VAULT_TTL_HOURS` | `vault.ttl_hours` |
| `PRIVOX_LOG_LEVEL` | `log.level` |
| `PRIVOX_DETECTION_PRESIDIO_ANALYZER_URL` | `detection.presidio.analyzer_url` |
| `PRIVOX_DETECTION_PRESIDIO_SCORE_THRESHOLD` | `detection.presidio.score_threshold` |
| `PRIVOX_DETECTION_PRESIDIO_FALLBACK_TO_REGEX` | `detection.presidio.fallback_to_regex` |

## Detected entity types

| Type | Examples | Detector |
|---|---|---|
| `EMAIL` | `user@example.com` | Regex |
| `PHONE_CA` | `(519) 555-1234`, `+15195551234` | Regex |
| `PHONE_US` | `(212) 555-0100` | Regex |
| `CREDIT_CARD` | Luhn-valid 13–19 digit numbers | Regex |
| `SIN` | `123 456 789` (Canadian SIN) | Regex |
| `SSN` | `123-45-6789` | Regex |
| `IBAN` | `GB82WEST12345698765432` | Regex |
| `IPV4` | `192.168.1.1` | Regex |
| `IPV6` | `2001:db8::1` | Regex |
| `API_KEY` | `sk-...`, `ghp_...`, `Bearer ...`, `AIza...`, `xoxb-...` | Regex |
| `URL_CRED` | `https://user:pass@host` | Regex |
| `UUID` | `550e8400-e29b-41d4-a716-446655440000` | Regex |
| `PERSON` | Person names | NER / Presidio |
| `ORG` | Organization names | NER / Presidio |
| `LOCATION` | Addresses, place names | NER / Presidio |
| `DATE_OF_BIRTH` | Dates in personal context | NER / Presidio |
| `ACCOUNT_NUMBER` | Contextual account references | NER / Presidio |

## Token format

Tokens are human-readable and preserve semantic context for the model:

```
EMAIL_a3f2c1
CREDIT_CARD_7b9e04
PERSON_c1d88f
```

The short ID is the first 3 bytes of HMAC-SHA256(original\_value, installation\_secret), encoded as lowercase hex. Tokens are stable: the same value always produces the same token for a given installation, across restarts.

## Security model

- Original values **never** appear in logs at any level.
- Original values **never** appear in error messages.
- Original values **never** leave the vault except via the detokenizer.
- The vault is **never** exposed via any HTTP endpoint.
- The vault encryption key is derived at startup and held in memory; it is never logged or written to disk directly.
- The installation secret is stored at `~/.privox/secret.key` with `0600` permissions. If the file is missing, privox refuses to start rather than generating a new secret (which would break all existing token mappings).

## Development

```sh
cargo build          # build
cargo test           # run all tests
cargo clippy -- -D warnings   # lint (must be clean)
cargo fmt --check    # formatting check
```

## Status

`privox` is in active development. The vault, tokenizer, and detector trait layers are implemented and tested. The HTTP proxy pipeline and streaming detokenizer are in progress.

## License

MIT
