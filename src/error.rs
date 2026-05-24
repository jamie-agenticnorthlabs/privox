/// All error types for `privox`, using `thiserror` for automatic `Display` and `From` impls.
///
/// `PrivoxError` is the library-level error type. Application code in `main.rs` and `server.rs`
/// uses `anyhow::Error` for context-chaining, but ultimately wraps these variants.
use thiserror::Error;

/// Top-level error type for the `privox` library.
#[derive(Debug, Error)]
pub enum PrivoxError {
    /// Configuration file could not be read or parsed.
    #[error("failed to load config from {path}: {source}")]
    ConfigLoad {
        path: String,
        #[source]
        source: ConfigError,
    },

    /// Vault operation failed.
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    /// Detection engine error.
    #[error("detector error: {0}")]
    Detector(#[from] DetectorError),

    /// Upstream proxy error.
    #[error("upstream error: {0}")]
    Upstream(#[from] UpstreamError),

    /// Detokenization error.
    #[error("detokenizer error: {0}")]
    Detokenizer(#[from] DetokenizerError),
}

/// Errors that occur while loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("could not read file: {0}")]
    Io(#[from] std::io::Error),

    /// The TOML content was malformed or missing required fields.
    #[error("invalid TOML: {0}")]
    Parse(#[from] toml::de::Error),

    /// A required field was absent and has no default.
    #[error("missing required field '{field}': {message}")]
    MissingField { field: String, message: String },

    /// A field value was out of the acceptable range.
    #[error("invalid value for '{field}': {message}")]
    InvalidValue { field: String, message: String },
}

/// Errors from vault operations (SQLite, encryption, key derivation).
#[derive(Debug, Error)]
pub enum VaultError {
    /// Could not open or initialize the SQLite database.
    #[error("failed to open vault at '{path}': {source}")]
    Open {
        path: String,
        #[source]
        source: rusqlite::Error,
    },

    /// A SQL query or statement failed.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Encryption of a value failed (AES-GCM).
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption of a stored value failed (wrong key, corrupted data, etc.).
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// The installation secret file is missing at startup.
    ///
    /// The proxy refuses to start rather than silently generating a new secret,
    /// which would break all existing vault mappings.
    #[error(
        "installation secret not found at '{path}'. \
         Run `privox init` to generate a new installation, or restore the secret file. \
         Generating a new secret will invalidate all existing vault entries."
    )]
    SecretMissing { path: String },

    /// The secret file has permissions weaker than 0600.
    #[error(
        "secret file at '{path}' has insecure permissions (found {found:#o}, expected 0600). \
         Run `chmod 0600 {path}` to fix."
    )]
    SecretPermissions { path: String, found: u32 },

    /// Key derivation (PBKDF2) produced an output of unexpected length.
    #[error("key derivation produced unexpected output length: {0}")]
    KeyDerivation(String),
}

/// Errors from the detection engine.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// A regex pattern failed to compile (should only happen at startup).
    #[error("failed to compile regex for entity type '{entity_type}': {source}")]
    RegexCompile {
        entity_type: String,
        #[source]
        source: regex::Error,
    },

    /// The optional NER endpoint returned an unexpected response.
    #[error("NER endpoint error for model '{model}': {message}")]
    NerResponse { model: String, message: String },

    /// The NER endpoint was unreachable (logged as warning; request continues).
    #[error("NER endpoint unreachable at '{url}': {source}")]
    NerUnavailable {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

/// Errors from the upstream proxy client.
#[derive(Debug, Error)]
pub enum UpstreamError {
    /// The upstream server was unreachable or the connection was refused.
    #[error("could not connect to upstream at '{url}': {source}")]
    Connect {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    /// The request to the upstream timed out.
    #[error("upstream request timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },

    /// The upstream returned a non-2xx status (passed through to caller as-is).
    #[error("upstream returned status {status}")]
    Status { status: u16 },

    /// A streaming chunk from the upstream could not be decoded.
    #[error("failed to decode upstream stream chunk: {0}")]
    StreamDecode(String),

    /// Generic reqwest error not covered by the above variants.
    #[error("upstream HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Errors from the detokenization stage.
#[derive(Debug, Error)]
pub enum DetokenizerError {
    /// The vault lookup for a token failed unexpectedly (not the same as a missing/expired entry).
    #[error("vault lookup failed during detokenization: {0}")]
    VaultLookup(#[from] VaultError),

    /// A streaming response could not be re-serialized after detokenization.
    #[error("failed to re-serialize streaming chunk: {0}")]
    ChunkSerialize(String),
}
