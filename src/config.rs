/// Configuration loading, TOML deserialization, environment variable overrides,
/// and startup validation for `privox`.
///
/// Config is loaded from a TOML file (default `~/.privox/config.toml`) and then
/// overlaid with environment variable overrides using the `PRIVOX_` prefix.
use std::path::Path;

use crate::error::ConfigError;

// ── Config structs ────────────────────────────────────────────────────────────

/// Root configuration for `privox`.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// HTTP server bind address.
    pub proxy: ProxyConfig,
    /// Upstream LLM endpoint settings.
    pub upstream: UpstreamConfig,
    /// Vault storage settings.
    pub vault: VaultConfig,
    /// Entity detection backend settings.
    pub detection: DetectionConfig,
    /// Logging settings.
    pub log: LogConfig,
}

/// Settings for the `privox` HTTP listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to bind, e.g. `"127.0.0.1:11435"`.
    pub listen: String,
}

/// Settings for the upstream OpenAI-compatible inference endpoint.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Base URL of the upstream endpoint, e.g. `"http://localhost:11434"`.
    pub url: String,
    /// Request timeout in seconds (applied to the full round-trip).
    pub timeout_secs: u64,
}

/// Settings for the encrypted token vault.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Path to the SQLite database file. Tilde is expanded.
    pub path: String,
    /// How long vault entries live before they are eligible for purging.
    pub ttl_hours: u64,
}

/// Settings for entity detection backends.
///
/// Regex detection is always active. NER and Presidio are opt-in via `backends`.
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Which optional backends to activate in addition to the always-on regex detector.
    /// Valid values: `"ner"`, `"presidio"`. `"regex"` is accepted but has no effect
    /// since regex is unconditionally enabled.
    pub backends: Vec<String>,
    /// Local Ollama NER backend settings (used when `"ner"` is in `backends`).
    pub ner: NerConfig,
    /// Presidio analyzer sidecar settings (used when `"presidio"` is in `backends`).
    pub presidio: PresidioConfig,
}

impl DetectionConfig {
    /// Returns `true` if the NER backend is configured and enabled.
    pub fn ner_enabled(&self) -> bool {
        self.backends.iter().any(|b| b == "ner")
    }

    /// Returns `true` if the Presidio backend is configured and enabled.
    pub fn presidio_enabled(&self) -> bool {
        self.backends.iter().any(|b| b == "presidio")
    }
}

/// Settings for the optional local Ollama NER backend.
#[derive(Debug, Clone)]
pub struct NerConfig {
    /// Base URL of the local Ollama endpoint.
    pub url: String,
    /// Model to use for NER (e.g. `"qwen2.5:0.5b"`).
    pub model: String,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

/// Settings for the optional Presidio analyzer sidecar.
#[derive(Debug, Clone)]
pub struct PresidioConfig {
    /// URL of the Presidio `/analyze` endpoint (e.g. `"http://localhost:5002"`).
    pub analyzer_url: String,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Language code passed to Presidio (e.g. `"en"`).
    pub language: String,
    /// Minimum confidence score threshold (0.0–1.0). Entities below this are discarded.
    pub score_threshold: f64,
    /// If `true`, continue with regex results when Presidio is unreachable.
    /// If `false`, return 503 to the caller when Presidio is unavailable.
    pub fallback_to_regex: bool,
}

/// Settings for structured log output.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, or `"error"`.
    pub level: String,
}

// ── Default implementations ───────────────────────────────────────────────────

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:11435".to_string(),
        }
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            // url has no reasonable default; left empty so validation catches it.
            url: String::new(),
            timeout_secs: 120,
        }
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            path: "~/.privox/vault.db".to_string(),
            ttl_hours: 24,
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            backends: vec!["regex".to_string()],
            ner: NerConfig::default(),
            presidio: PresidioConfig::default(),
        }
    }
}

impl Default for NerConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:11434".to_string(),
            model: "qwen2.5:0.5b".to_string(),
            timeout_secs: 10,
        }
    }
}

impl Default for PresidioConfig {
    fn default() -> Self {
        Self {
            analyzer_url: "http://localhost:5002".to_string(),
            timeout_secs: 5,
            language: "en".to_string(),
            score_threshold: 0.7,
            fallback_to_regex: true,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

// ── TOML raw structs (private) ────────────────────────────────────────────────

/// Internal TOML-deserialization mirror of [`Config`].
///
/// All fields are `Option<T>` so that missing keys use our explicit defaults
/// rather than serde's implicit defaults, giving us control over validation messages.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawConfig {
    proxy: RawProxyConfig,
    upstream: RawUpstreamConfig,
    vault: RawVaultConfig,
    detection: RawDetectionConfig,
    log: RawLogConfig,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawProxyConfig {
    listen: Option<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawUpstreamConfig {
    url: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawVaultConfig {
    path: Option<String>,
    ttl_hours: Option<u64>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawDetectionConfig {
    backends: Option<Vec<String>>,
    ner: RawNerConfig,
    presidio: RawPresidioConfig,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawNerConfig {
    url: Option<String>,
    model: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawPresidioConfig {
    analyzer_url: Option<String>,
    timeout_secs: Option<u64>,
    language: Option<String>,
    score_threshold: Option<f64>,
    fallback_to_regex: Option<bool>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct RawLogConfig {
    level: Option<String>,
}

// ── Public loading API ────────────────────────────────────────────────────────

impl Config {
    /// Loads config from a TOML file and applies environment variable overrides.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if the file cannot be read, [`ConfigError::Parse`]
    /// if the TOML is invalid, or [`ConfigError::MissingField`] /
    /// [`ConfigError::InvalidValue`] if a required field is absent or out of range.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let toml_str = std::fs::read_to_string(path)?;
        let raw: RawConfig = toml::from_str(&toml_str)?;
        let mut cfg = Self::from_raw(raw);
        apply_env_overrides(&mut cfg, |key| std::env::var(key).ok());
        cfg.validate()?;
        Ok(cfg)
    }

    /// Loads config from a TOML string (used in tests without touching the filesystem).
    ///
    /// Does NOT apply environment variable overrides — use [`Config::load`] for production.
    #[cfg(test)]
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(toml_str)?;
        Ok(Self::from_raw(raw))
    }

    fn from_raw(raw: RawConfig) -> Self {
        let defaults = Self::default();
        Self {
            proxy: ProxyConfig {
                listen: raw.proxy.listen.unwrap_or(defaults.proxy.listen),
            },
            upstream: UpstreamConfig {
                url: raw.upstream.url.unwrap_or(defaults.upstream.url),
                timeout_secs: raw
                    .upstream
                    .timeout_secs
                    .unwrap_or(defaults.upstream.timeout_secs),
            },
            vault: VaultConfig {
                path: raw.vault.path.unwrap_or(defaults.vault.path),
                ttl_hours: raw.vault.ttl_hours.unwrap_or(defaults.vault.ttl_hours),
            },
            detection: DetectionConfig {
                backends: raw
                    .detection
                    .backends
                    .unwrap_or(defaults.detection.backends),
                ner: NerConfig {
                    url: raw.detection.ner.url.unwrap_or(defaults.detection.ner.url),
                    model: raw
                        .detection
                        .ner
                        .model
                        .unwrap_or(defaults.detection.ner.model),
                    timeout_secs: raw
                        .detection
                        .ner
                        .timeout_secs
                        .unwrap_or(defaults.detection.ner.timeout_secs),
                },
                presidio: PresidioConfig {
                    analyzer_url: raw
                        .detection
                        .presidio
                        .analyzer_url
                        .unwrap_or(defaults.detection.presidio.analyzer_url),
                    timeout_secs: raw
                        .detection
                        .presidio
                        .timeout_secs
                        .unwrap_or(defaults.detection.presidio.timeout_secs),
                    language: raw
                        .detection
                        .presidio
                        .language
                        .unwrap_or(defaults.detection.presidio.language),
                    score_threshold: raw
                        .detection
                        .presidio
                        .score_threshold
                        .unwrap_or(defaults.detection.presidio.score_threshold),
                    fallback_to_regex: raw
                        .detection
                        .presidio
                        .fallback_to_regex
                        .unwrap_or(defaults.detection.presidio.fallback_to_regex),
                },
            },
            log: LogConfig {
                level: raw.log.level.unwrap_or(defaults.log.level),
            },
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.upstream.url.is_empty() {
            return Err(ConfigError::MissingField {
                field: "upstream.url".to_string(),
                message: "set upstream.url to the base URL of your OpenAI-compatible endpoint, \
                          e.g. url = \"http://localhost:11434\""
                    .to_string(),
            });
        }

        if self.upstream.timeout_secs == 0 {
            return Err(ConfigError::InvalidValue {
                field: "upstream.timeout_secs".to_string(),
                message: "timeout must be at least 1 second".to_string(),
            });
        }

        if self.vault.ttl_hours == 0 {
            return Err(ConfigError::InvalidValue {
                field: "vault.ttl_hours".to_string(),
                message: "TTL must be at least 1 hour".to_string(),
            });
        }

        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.log.level.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "log.level".to_string(),
                message: format!(
                    "must be one of: {}; got '{}'",
                    valid_levels.join(", "),
                    self.log.level
                ),
            });
        }

        let valid_backends = ["regex", "ner", "presidio"];
        for backend in &self.detection.backends {
            if !valid_backends.contains(&backend.as_str()) {
                return Err(ConfigError::InvalidValue {
                    field: "detection.backends".to_string(),
                    message: format!(
                        "unknown backend '{}'; valid values are: {}",
                        backend,
                        valid_backends.join(", ")
                    ),
                });
            }
        }

        let threshold = self.detection.presidio.score_threshold;
        if !(0.0..=1.0).contains(&threshold) {
            return Err(ConfigError::InvalidValue {
                field: "detection.presidio.score_threshold".to_string(),
                message: format!("must be between 0.0 and 1.0; got {threshold}"),
            });
        }

        Ok(())
    }
}

/// Applies environment variable overrides to `cfg`.
///
/// The `env_getter` closure abstracts the env source so tests can inject a mock
/// without touching real environment variables (which are process-global state).
fn apply_env_overrides(cfg: &mut Config, env_getter: impl Fn(&str) -> Option<String>) {
    if let Some(v) = env_getter("PRIVOX_PROXY_LISTEN") {
        cfg.proxy.listen = v;
    }
    if let Some(v) = env_getter("PRIVOX_UPSTREAM_URL") {
        cfg.upstream.url = v;
    }
    if let Some(v) = env_getter("PRIVOX_UPSTREAM_TIMEOUT_SECS") {
        if let Ok(n) = v.parse::<u64>() {
            cfg.upstream.timeout_secs = n;
        }
    }
    if let Some(v) = env_getter("PRIVOX_VAULT_PATH") {
        cfg.vault.path = v;
    }
    if let Some(v) = env_getter("PRIVOX_VAULT_TTL_HOURS") {
        if let Ok(n) = v.parse::<u64>() {
            cfg.vault.ttl_hours = n;
        }
    }
    if let Some(v) = env_getter("PRIVOX_LOG_LEVEL") {
        cfg.log.level = v;
    }
    if let Some(v) = env_getter("PRIVOX_DETECTION_PRESIDIO_ANALYZER_URL") {
        cfg.detection.presidio.analyzer_url = v;
    }
    if let Some(v) = env_getter("PRIVOX_DETECTION_PRESIDIO_SCORE_THRESHOLD") {
        if let Ok(f) = v.parse::<f64>() {
            cfg.detection.presidio.score_threshold = f;
        }
    }
    if let Some(v) = env_getter("PRIVOX_DETECTION_PRESIDIO_FALLBACK_TO_REGEX") {
        cfg.detection.presidio.fallback_to_regex =
            matches!(v.to_lowercase().as_str(), "true" | "1" | "yes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_TOML: &str = r#"
[upstream]
url = "http://localhost:11434"
"#;

    const FULL_TOML: &str = r#"
[proxy]
listen = "0.0.0.0:9000"

[upstream]
url = "http://my-llm:8080"
timeout_secs = 60

[vault]
path = "/tmp/test.db"
ttl_hours = 48

[detection]
backends = ["regex", "presidio"]

[detection.ner]
url = "http://ollama:11434"
model = "llama3.2:1b"
timeout_secs = 15

[detection.presidio]
analyzer_url = "http://presidio:5002"
timeout_secs = 8
language = "fr"
score_threshold = 0.85
fallback_to_regex = false

[log]
level = "debug"
"#;

    #[test]
    fn minimal_toml_loads_with_defaults() {
        let cfg = Config::from_toml_str(MINIMAL_TOML).expect("minimal TOML must parse");
        assert_eq!(
            cfg.upstream.url, "http://localhost:11434",
            "upstream.url must be set from TOML"
        );
        assert_eq!(
            cfg.proxy.listen, "127.0.0.1:11435",
            "proxy.listen must use default when absent"
        );
        assert_eq!(
            cfg.upstream.timeout_secs, 120,
            "upstream.timeout_secs must use default"
        );
        assert_eq!(cfg.vault.ttl_hours, 24, "vault.ttl_hours must use default");
        assert_eq!(cfg.log.level, "info", "log.level must use default");
        assert_eq!(
            cfg.detection.backends,
            vec!["regex"],
            "detection.backends must default to regex-only"
        );
    }

    #[test]
    fn full_toml_overrides_all_fields() {
        let cfg = Config::from_toml_str(FULL_TOML).expect("full TOML must parse");
        assert_eq!(cfg.proxy.listen, "0.0.0.0:9000");
        assert_eq!(cfg.upstream.url, "http://my-llm:8080");
        assert_eq!(cfg.upstream.timeout_secs, 60);
        assert_eq!(cfg.vault.path, "/tmp/test.db");
        assert_eq!(cfg.vault.ttl_hours, 48);
        assert_eq!(cfg.detection.backends, vec!["regex", "presidio"]);
        assert_eq!(cfg.detection.ner.model, "llama3.2:1b");
        assert_eq!(cfg.detection.presidio.analyzer_url, "http://presidio:5002");
        assert!((cfg.detection.presidio.score_threshold - 0.85).abs() < f64::EPSILON);
        assert!(!cfg.detection.presidio.fallback_to_regex);
        assert_eq!(cfg.detection.presidio.language, "fr");
        assert_eq!(cfg.log.level, "debug");
    }

    #[test]
    fn env_override_takes_precedence_over_toml() {
        let mut cfg = Config::from_toml_str(MINIMAL_TOML).expect("must parse");
        let env = |key: &str| -> Option<String> {
            match key {
                "PRIVOX_UPSTREAM_URL" => Some("http://env-override:9999".to_string()),
                "PRIVOX_LOG_LEVEL" => Some("debug".to_string()),
                "PRIVOX_DETECTION_PRESIDIO_SCORE_THRESHOLD" => Some("0.5".to_string()),
                _ => None,
            }
        };
        apply_env_overrides(&mut cfg, env);
        assert_eq!(
            cfg.upstream.url, "http://env-override:9999",
            "env PRIVOX_UPSTREAM_URL must override TOML"
        );
        assert_eq!(
            cfg.log.level, "debug",
            "env PRIVOX_LOG_LEVEL must override TOML"
        );
        assert!(
            (cfg.detection.presidio.score_threshold - 0.5).abs() < f64::EPSILON,
            "env PRIVOX_DETECTION_PRESIDIO_SCORE_THRESHOLD must override TOML"
        );
    }

    #[test]
    fn missing_upstream_url_returns_error() {
        let toml = "[proxy]\nlisten = \"127.0.0.1:11435\"\n";
        let cfg = Config::from_toml_str(toml).expect("must parse");
        let err = cfg
            .validate()
            .expect_err("missing upstream.url must fail validation");
        match err {
            ConfigError::MissingField { field, .. } => {
                assert_eq!(field, "upstream.url", "error must name the missing field");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn invalid_log_level_returns_error() {
        let toml = "[upstream]\nurl = \"http://x\"\n[log]\nlevel = \"verbose\"\n";
        let cfg = Config::from_toml_str(toml).expect("must parse");
        let err = cfg
            .validate()
            .expect_err("invalid log level must fail validation");
        match err {
            ConfigError::InvalidValue { field, .. } => {
                assert_eq!(field, "log.level");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn invalid_backend_name_returns_error() {
        let toml =
            "[upstream]\nurl = \"http://x\"\n[detection]\nbackends = [\"regex\", \"unknown\"]\n";
        let cfg = Config::from_toml_str(toml).expect("must parse");
        let err = cfg
            .validate()
            .expect_err("unknown backend must fail validation");
        match err {
            ConfigError::InvalidValue { field, .. } => {
                assert_eq!(field, "detection.backends");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn presidio_enabled_detection() {
        let toml =
            "[upstream]\nurl = \"http://x\"\n[detection]\nbackends = [\"regex\", \"presidio\"]\n";
        let cfg = Config::from_toml_str(toml).expect("must parse");
        assert!(
            cfg.detection.presidio_enabled(),
            "presidio backend should be detected"
        );
        assert!(
            !cfg.detection.ner_enabled(),
            "ner backend should not be active"
        );
    }
}
