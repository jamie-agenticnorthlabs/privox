use std::time::Duration;

use reqwest::{Client, Response};
use serde_json::Value;
use tracing::debug;

use crate::{config::UpstreamConfig, error::UpstreamError};

/// HTTP client for forwarding sanitized requests to the configured upstream
/// OpenAI-compatible endpoint.
pub struct UpstreamClient {
    client: Client,
    /// Upstream base URL with no trailing slash, e.g. `"http://localhost:11434"`.
    base_url: String,
}

impl UpstreamClient {
    /// Creates a new client with a timeout taken from `config`.
    pub fn new(config: &UpstreamConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            // reqwest::ClientBuilder::build() only fails if TLS backend initialisation
            // fails, which is not possible with the bundled rustls backend.
            .expect("reqwest client construction cannot fail with rustls");
        Self {
            client,
            base_url: config.url.trim_end_matches('/').to_string(),
        }
    }

    /// POST `body` to `{base_url}{path}` and return the raw upstream response.
    ///
    /// `path` must begin with `/`, e.g. `"/v1/chat/completions"`.
    ///
    /// # Errors
    ///
    /// Returns [`UpstreamError::Connect`] when the upstream is unreachable,
    /// [`UpstreamError::Http`] for other reqwest errors.
    pub async fn post(&self, path: &str, body: &Value) -> Result<Response, UpstreamError> {
        let url = format!("{}{}", self.base_url, path);
        debug!(url = %url, "forwarding request to upstream");
        self.client.post(&url).json(body).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                UpstreamError::Connect {
                    url: url.clone(),
                    source: e,
                }
            } else {
                UpstreamError::Http(e)
            }
        })
    }
}
