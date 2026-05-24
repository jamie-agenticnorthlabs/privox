use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    detector::DetectorPipeline,
    detokenizer::Detokenizer,
    error::UpstreamError,
    proxy::UpstreamClient,
    tokenizer::Tokenizer,
    types::{ChatRequest, EntityType, MessageContent},
};

// ── Application state ─────────────────────────────────────────────────────────

pub struct AppState {
    pub pipeline: DetectorPipeline,
    pub tokenizer: Tokenizer,
    pub detokenizer: Detokenizer,
    pub upstream: UpstreamClient,
}

// ── Server startup ────────────────────────────────────────────────────────────

/// Builds the router and starts the HTTP listener.
///
/// This function runs until the process receives SIGTERM/SIGINT or an
/// unrecoverable server error occurs.
pub async fn run(state: Arc<AppState>, listen: &str) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/v1/chat/completions", post(chat_completions_handler))
        .route("/v1/completions", post(legacy_completions_handler))
        .with_state(state);

    let listener = TcpListener::bind(listen).await?;
    info!(listen = %listen, "privox listening");
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Route handlers ────────────────────────────────────────────────────────────

async fn chat_completions_handler(
    State(state): State<Arc<AppState>>,
    Json(mut request): Json<ChatRequest>,
) -> Response {
    let request_id = Uuid::new_v4();
    let streaming = request.stream;

    // Stage 2a: Detect and tokenize all message content.
    let mut all_entity_types: Vec<EntityType> = Vec::new();
    for msg in &mut request.messages {
        if let Some(ref mut content) = msg.content {
            match tokenize_content(content, &state.pipeline, &state.tokenizer, request_id).await {
                Ok(types) => all_entity_types.extend(types),
                Err(resp) => return resp,
            }
        }
    }

    debug!(
        request_id = %request_id,
        entity_types = ?all_entity_types,
        "tokenization complete"
    );

    // Stage 3: Forward sanitized request to upstream.
    let body = match serde_json::to_value(&request) {
        Ok(v) => v,
        Err(e) => {
            error!(request_id = %request_id, error = %e, "failed to serialize request");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "serialization error");
        }
    };

    let upstream_resp = match state.upstream.post("/v1/chat/completions", &body).await {
        Ok(r) => r,
        Err(e) => {
            error!(request_id = %request_id, error = %e, "upstream unreachable");
            return upstream_error_response(&e);
        }
    };

    let upstream_status = upstream_resp.status();
    info!(
        request_id = %request_id,
        status = %upstream_status.as_u16(),
        streaming = %streaming,
        "upstream responded"
    );

    if !upstream_status.is_success() {
        let body = upstream_resp.text().await.unwrap_or_default();
        return (
            StatusCode::from_u16(upstream_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body,
        )
            .into_response();
    }

    // Stage 4: Detokenize the upstream response.
    if streaming {
        handle_streaming(upstream_resp, Arc::clone(&state), request_id).await
    } else {
        handle_non_streaming(upstream_resp, &state.detokenizer).await
    }
}

/// Legacy `/v1/completions` handler — applies the same pipeline to the `prompt` field.
async fn legacy_completions_handler(
    State(state): State<Arc<AppState>>,
    Json(mut body): Json<Value>,
) -> Response {
    let request_id = Uuid::new_v4();

    if let Some(prompt) = body
        .get("prompt")
        .and_then(|p| p.as_str())
        .map(str::to_string)
    {
        let entities = match state.pipeline.detect(&prompt).await {
            Ok(e) => e,
            Err(e) => {
                error!(request_id = %request_id, error = %e, "detection failed");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "detection error");
            }
        };
        match state.tokenizer.tokenize(&prompt, &entities) {
            Ok(result) => {
                body["prompt"] = Value::String(result.sanitized);
            }
            Err(e) => {
                error!(request_id = %request_id, error = %e, "tokenization failed");
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "tokenization error");
            }
        }
    }

    let upstream_resp = match state.upstream.post("/v1/completions", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_error_response(&e),
    };

    let upstream_status = upstream_resp.status();
    if !upstream_status.is_success() {
        let body = upstream_resp.text().await.unwrap_or_default();
        return (
            StatusCode::from_u16(upstream_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body,
        )
            .into_response();
    }

    handle_non_streaming(upstream_resp, &state.detokenizer).await
}

// ── Pipeline helpers ──────────────────────────────────────────────────────────

/// Runs detection and tokenization on a single message content, mutating it in place.
/// Returns the entity types found, or an error Response if any stage failed.
async fn tokenize_content(
    content: &mut MessageContent,
    pipeline: &DetectorPipeline,
    tokenizer: &Tokenizer,
    request_id: Uuid,
) -> Result<Vec<EntityType>, Response> {
    match content {
        MessageContent::Text(ref mut text) => {
            let entities = pipeline.detect(text).await.map_err(|e| {
                error!(request_id = %request_id, error = %e, "detection failed");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "detection error")
            })?;
            let result = tokenizer.tokenize(text, &entities).map_err(|e| {
                error!(request_id = %request_id, error = %e, "tokenization failed");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "tokenization error")
            })?;
            *text = result.sanitized;
            Ok(result.entity_types_found)
        }
        MessageContent::Parts(ref mut parts) => {
            let mut found = Vec::new();
            for part in parts.iter_mut() {
                if part.get("type").and_then(|t| t.as_str()) != Some("text") {
                    continue;
                }
                let Some(text_val) = part.get_mut("text") else {
                    continue;
                };
                let Some(text) = text_val.as_str().map(str::to_string) else {
                    continue;
                };

                let entities = pipeline.detect(&text).await.map_err(|e| {
                    error!(request_id = %request_id, error = %e, "detection failed");
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "detection error")
                })?;
                let result = tokenizer.tokenize(&text, &entities).map_err(|e| {
                    error!(request_id = %request_id, error = %e, "tokenization failed");
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "tokenization error")
                })?;
                found.extend(result.entity_types_found);
                *text_val = Value::String(result.sanitized);
            }
            Ok(found)
        }
    }
}

// ── Response handling ─────────────────────────────────────────────────────────

async fn handle_non_streaming(resp: reqwest::Response, detokenizer: &Detokenizer) -> Response {
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "failed to read upstream response body");
            return error_response(StatusCode::BAD_GATEWAY, "failed to read upstream response");
        }
    };
    match detokenizer.detokenize(&text) {
        Ok(detokenized) => {
            let val: Value =
                serde_json::from_str(&detokenized).unwrap_or(Value::String(detokenized));
            Json(val).into_response()
        }
        Err(e) => {
            error!(error = %e, "detokenization failed");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "detokenization error")
        }
    }
}

async fn handle_streaming(
    upstream_resp: reqwest::Response,
    state: Arc<AppState>,
    request_id: Uuid,
) -> Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, String>>(32);

    tokio::spawn(async move {
        let mut sd = state.detokenizer.streaming();
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut line_buf = String::new();

        while let Some(chunk) = byte_stream.next().await {
            let bytes = match chunk {
                Ok(b) => b,
                Err(e) => {
                    warn!(request_id = %request_id, error = %e, "upstream stream read error");
                    break;
                }
            };

            let text = match std::str::from_utf8(&bytes) {
                Ok(t) => t,
                Err(_) => {
                    warn!(request_id = %request_id, "non-UTF-8 bytes in SSE stream — skipping chunk");
                    continue;
                }
            };
            line_buf.push_str(text);

            // Process complete lines from the buffer.
            while let Some(nl) = line_buf.find('\n') {
                let line = line_buf[..nl].trim_end_matches('\r').to_string();
                line_buf = line_buf[nl + 1..].to_string();

                let Some(data) = line.strip_prefix("data: ") else {
                    continue;
                };

                if data == "[DONE]" {
                    // Flush any content held in the sliding window.
                    match sd.flush() {
                        Ok(remaining) if !remaining.is_empty() => {
                            let _ = tx.send(Ok(make_delta_event(&remaining))).await;
                        }
                        Err(e) => {
                            warn!(request_id = %request_id, error = %e, "detokenizer flush error")
                        }
                        _ => {}
                    }
                    let _ = tx.send(Ok(Event::default().data("[DONE]"))).await;
                    return;
                }

                let mut json_val: Value = match serde_json::from_str(data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if let Some(content) = extract_delta_content(&json_val).map(str::to_string) {
                    match sd.push_chunk(&content) {
                        Ok(safe) if !safe.is_empty() => {
                            // Replace the content in the original JSON with the safe portion
                            // so metadata fields (id, model, finish_reason) are preserved.
                            set_delta_content(&mut json_val, &safe);
                            let _ = tx
                                .send(Ok(Event::default().data(json_val.to_string())))
                                .await;
                        }
                        Ok(_) => {
                            // Content is still being buffered — do not forward this chunk yet.
                        }
                        Err(e) => {
                            warn!(request_id = %request_id, error = %e, "streaming detokenizer error");
                        }
                    }
                } else {
                    // No content field (role delta, finish_reason, tool calls, etc.) — forward unchanged.
                    let _ = tx
                        .send(Ok(Event::default().data(json_val.to_string())))
                        .await;
                }
            }
        }

        // Upstream closed the stream without [DONE].
        match sd.flush() {
            Ok(remaining) if !remaining.is_empty() => {
                let _ = tx.send(Ok(make_delta_event(&remaining))).await;
            }
            Err(e) => {
                warn!(request_id = %request_id, error = %e, "detokenizer flush on stream close")
            }
            _ => {}
        }
    });

    Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── SSE helpers ───────────────────────────────────────────────────────────────

fn extract_delta_content(val: &Value) -> Option<&str> {
    val.get("choices")?
        .get(0)?
        .get("delta")?
        .get("content")?
        .as_str()
}

fn set_delta_content(val: &mut Value, content: &str) {
    if let Some(choices) = val.get_mut("choices") {
        if let Some(choice) = choices.get_mut(0) {
            if let Some(delta) = choice.get_mut("delta") {
                delta["content"] = Value::String(content.to_string());
            }
        }
    }
}

/// Creates a minimal SSE delta event carrying only the given content string.
/// Used when the detokenizer releases safe content that doesn't map 1:1 to
/// an upstream chunk.
fn make_delta_event(content: &str) -> Event {
    let chunk = json!({
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
    });
    Event::default().data(chunk.to_string())
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = json!({
        "error": {
            "message": message,
            "type": "privox_proxy_error",
            "code": status.as_u16(),
        }
    });
    (status, Json(body)).into_response()
}

fn upstream_error_response(e: &UpstreamError) -> Response {
    let status = match e {
        UpstreamError::Connect { .. } | UpstreamError::Timeout { .. } => StatusCode::BAD_GATEWAY,
        UpstreamError::Status { status } => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        _ => StatusCode::BAD_GATEWAY,
    };
    error_response(status, "upstream unavailable")
}
