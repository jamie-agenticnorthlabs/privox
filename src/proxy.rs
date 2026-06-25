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
    pub async fn post(
        &self,
        path: &str,
        body: &Value,
        upstream_base_url: Option<&str>,
        headers: &[(String, String)],
    ) -> Result<Response, UpstreamError> {
        let url = self.upstream_url(path, upstream_base_url);
        debug!(url = %url, "forwarding request to upstream");
        let mut request = self.client.post(&url).json(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        request.send().await.map_err(|e| {
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

    fn upstream_url(&self, path: &str, upstream_base_url: Option<&str>) -> String {
        let base = upstream_base_url
            .filter(|url| !url.trim().is_empty())
            .unwrap_or(&self.base_url)
            .trim_end_matches('/');
        if upstream_base_url.is_some() && base.ends_with("/v1") && path.starts_with("/v1/") {
            return format!("{}{}", base, &path[3..]);
        }
        format!("{}{}", base, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamConfig;

    fn client() -> UpstreamClient {
        UpstreamClient::new(&UpstreamConfig {
            url: "http://local-model:1234".to_string(),
            timeout_secs: 30,
        })
    }

    #[test]
    fn dynamic_v1_upstream_does_not_duplicate_v1_path() {
        assert_eq!(
            client().upstream_url(
                "/v1/chat/completions",
                Some("https://api.cohere.ai/compatibility/v1"),
            ),
            "https://api.cohere.ai/compatibility/v1/chat/completions",
        );
    }

    #[test]
    fn configured_upstream_keeps_existing_v1_path() {
        assert_eq!(
            client().upstream_url("/v1/chat/completions", None),
            "http://local-model:1234/v1/chat/completions",
        );
    }
}
