use std::collections::HashMap;
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
    types::{ChatRequest, EntityType},
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
    Json(request): Json<ChatRequest>,
) -> Response {
    let request_id = Uuid::new_v4();
    let streaming = request.stream;

    // Stage 2a: Detect and tokenize all eligible string leaves in the full
    // request payload. Protocol/control fields are skipped so model IDs, roles,
    // tool names, schemas, and provider wiring stay intact.
    let mut body = match serde_json::to_value(&request) {
        Ok(v) => v,
        Err(e) => {
            error!(request_id = %request_id, error = %e, "failed to serialize request");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "serialization error");
        }
    };
    let all_entity_types =
        match tokenize_json_strings(&mut body, &state.pipeline, &state.tokenizer, request_id).await
        {
            Ok(types) => types,
            Err(resp) => return resp,
        };

    debug!(
        request_id = %request_id,
        entity_types = ?all_entity_types,
        "tokenization complete"
    );

    // Stage 3: Forward sanitized request to upstream.
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

    if let Err(resp) =
        tokenize_json_strings(&mut body, &state.pipeline, &state.tokenizer, request_id).await
    {
        return resp;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum JsonPathSegment {
    Key(String),
    Index(usize),
}

fn is_protocol_key(key: &str) -> bool {
    matches!(
        key,
        "model"
            | "role"
            | "name"
            | "type"
            | "id"
            | "tool_call_id"
            | "object"
            | "finish_reason"
            | "system_fingerprint"
            | "service_tier"
    )
}

fn is_schema_path(path: &[JsonPathSegment]) -> bool {
    path.iter().any(|segment| {
        matches!(
            segment,
            JsonPathSegment::Key(key)
                if key == "tools"
                    || key == "tool_choice"
                    || key == "response_format"
                    || key == "functions"
        )
    })
}

fn should_tokenize_path(path: &[JsonPathSegment]) -> bool {
    if is_schema_path(path) {
        return false;
    }
    !matches!(
        path.last(),
        Some(JsonPathSegment::Key(key)) if is_protocol_key(key)
    )
}

fn collect_string_paths(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    out: &mut Vec<Vec<JsonPathSegment>>,
) {
    match value {
        Value::String(_) => {
            if should_tokenize_path(path) {
                out.push(path.clone());
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                collect_string_paths(item, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                collect_string_paths(item, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

fn value_mut_at_path<'a>(value: &'a mut Value, path: &[JsonPathSegment]) -> Option<&'a mut Value> {
    let mut current = value;
    for segment in path {
        match segment {
            JsonPathSegment::Key(key) => current = current.get_mut(key)?,
            JsonPathSegment::Index(index) => current = current.get_mut(*index)?,
        }
    }
    Some(current)
}

async fn tokenize_json_strings(
    value: &mut Value,
    pipeline: &DetectorPipeline,
    tokenizer: &Tokenizer,
    request_id: Uuid,
) -> Result<Vec<EntityType>, Response> {
    let mut paths = Vec::new();
    collect_string_paths(value, &mut Vec::new(), &mut paths);
    let mut found = Vec::new();
    for path in paths {
        let Some(text_val) = value_mut_at_path(value, &path) else {
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
        if !result.entity_types_found.is_empty() {
            *text_val = Value::String(result.sanitized);
            found.extend(result.entity_types_found);
        }
    }
    Ok(found)
}

fn detokenize_json_strings(value: &mut Value, detokenizer: &Detokenizer) -> Result<(), Response> {
    match value {
        Value::String(text) => {
            *text = detokenizer.detokenize(text).map_err(|e| {
                error!(error = %e, "detokenization failed");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "detokenization error")
            })?;
        }
        Value::Array(items) => {
            for item in items {
                detokenize_json_strings(item, detokenizer)?;
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                detokenize_json_strings(item, detokenizer)?;
            }
        }
        _ => {}
    }
    Ok(())
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
    if let Ok(mut val) = serde_json::from_str::<Value>(&text) {
        if let Err(resp) = detokenize_json_strings(&mut val, detokenizer) {
            return resp;
        }
        Json(val).into_response()
    } else {
        match detokenizer.detokenize(&text) {
            Ok(detokenized) => Json(Value::String(detokenized)).into_response(),
            Err(e) => {
                error!(error = %e, "detokenization failed");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "detokenization error")
            }
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
        let mut stream_detokenizers: HashMap<
            Vec<JsonPathSegment>,
            crate::detokenizer::StreamingDetokenizer,
        > = HashMap::new();
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
                    flush_stream_json_strings(&tx, &mut stream_detokenizers, request_id).await;
                    let _ = tx.send(Ok(Event::default().data("[DONE]"))).await;
                    return;
                }

                let mut json_val: Value = match serde_json::from_str(data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let had_buffered_strings = detokenize_streaming_json_strings(
                    &mut json_val,
                    &mut stream_detokenizers,
                    &state.detokenizer,
                    request_id,
                );

                if has_finish_reason(&json_val) {
                    flush_stream_json_strings(&tx, &mut stream_detokenizers, request_id).await;
                }

                if should_forward_stream_event(&json_val, had_buffered_strings) {
                    let _ = tx
                        .send(Ok(Event::default().data(json_val.to_string())))
                        .await;
                }
            }
        }

        // Upstream closed the stream without [DONE].
        flush_stream_json_strings(&tx, &mut stream_detokenizers, request_id).await;
    });

    Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── SSE helpers ───────────────────────────────────────────────────────────────

fn has_finish_reason(val: &Value) -> bool {
    val.get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("finish_reason"))
        .is_some_and(|finish| !finish.is_null())
}

fn delta_has_fields(val: &Value) -> bool {
    val.get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("delta"))
        .and_then(Value::as_object)
        .is_some_and(|delta| !delta.is_empty())
}

fn should_forward_stream_event(val: &Value, had_buffered_field: bool) -> bool {
    if !had_buffered_field {
        return true;
    }
    has_finish_reason(val) || delta_has_fields(val)
}

fn is_stream_buffered_path(path: &[JsonPathSegment]) -> bool {
    path.iter().any(|segment| {
        matches!(
            segment,
            JsonPathSegment::Key(key)
                if key == "delta"
                    || key == "message"
                    || key == "text"
                    || key == "content"
                    || key == "reasoning_content"
                    || key == "arguments"
        )
    }) && !matches!(
        path.last(),
        Some(JsonPathSegment::Key(key)) if is_protocol_key(key)
    )
}

fn detokenize_streaming_json_strings(
    value: &mut Value,
    streams: &mut HashMap<Vec<JsonPathSegment>, crate::detokenizer::StreamingDetokenizer>,
    detokenizer: &Detokenizer,
    request_id: Uuid,
) -> bool {
    let mut paths = Vec::new();
    collect_all_string_paths(value, &mut Vec::new(), &mut paths);
    let mut saw_buffered = false;

    for path in paths {
        let Some(text_val) = value_mut_at_path(value, &path) else {
            continue;
        };
        let Some(text) = text_val.as_str().map(str::to_string) else {
            continue;
        };

        if !is_stream_buffered_path(&path) {
            match detokenizer.detokenize(&text) {
                Ok(detokenized) => *text_val = Value::String(detokenized),
                Err(e) => {
                    warn!(request_id = %request_id, error = %e, "streaming metadata detokenizer error");
                }
            }
            continue;
        }

        saw_buffered = true;
        let stream = streams
            .entry(path.clone())
            .or_insert_with(|| detokenizer.streaming());
        match stream.push_chunk(&text) {
            Ok(safe) if !safe.is_empty() => {
                *text_val = Value::String(safe);
            }
            Ok(_) => {
                remove_value_at_path(value, &path);
            }
            Err(e) => {
                warn!(request_id = %request_id, path = ?path, error = %e, "streaming detokenizer error");
                remove_value_at_path(value, &path);
            }
        }
    }
    prune_empty_streaming_containers(value);
    saw_buffered
}

fn collect_all_string_paths(
    value: &Value,
    path: &mut Vec<JsonPathSegment>,
    out: &mut Vec<Vec<JsonPathSegment>>,
) {
    match value {
        Value::String(_) => out.push(path.clone()),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(JsonPathSegment::Index(index));
                collect_all_string_paths(item, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                path.push(JsonPathSegment::Key(key.clone()));
                collect_all_string_paths(item, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

fn remove_value_at_path(value: &mut Value, path: &[JsonPathSegment]) {
    let Some((last, parent_path)) = path.split_last() else {
        return;
    };
    let Some(parent) = value_mut_at_path(value, parent_path) else {
        return;
    };
    match (parent, last) {
        (Value::Object(map), JsonPathSegment::Key(key)) => {
            map.remove(key);
        }
        (Value::Array(items), JsonPathSegment::Index(index)) => {
            if let Some(item) = items.get_mut(*index) {
                *item = Value::Null;
            }
        }
        _ => {}
    }
}

fn prune_empty_streaming_containers(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items.iter_mut() {
                prune_empty_streaming_containers(item);
            }
            items.retain(|item| !item.is_null() && !is_empty_streaming_container(item));
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                prune_empty_streaming_containers(item);
            }
            map.retain(|_, item| !is_empty_streaming_container(item));
        }
        _ => {}
    }
}

fn is_empty_streaming_container(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.is_empty() || (map.len() == 1 && map.contains_key("index")),
        Value::Array(items) => items.is_empty(),
        _ => false,
    }
}

async fn flush_stream_json_strings(
    tx: &tokio::sync::mpsc::Sender<Result<Event, String>>,
    streams: &mut HashMap<Vec<JsonPathSegment>, crate::detokenizer::StreamingDetokenizer>,
    request_id: Uuid,
) {
    let mut entries: Vec<_> = streams.drain().collect();
    entries.sort_by_key(|(path, _)| path.len());
    for (path, mut sd) in entries {
        match sd.flush() {
            Ok(remaining) if !remaining.is_empty() => {
                let _ = tx
                    .send(Ok(make_stream_delta_event(&path, &remaining)))
                    .await;
            }
            Err(e) => {
                warn!(
                    request_id = %request_id,
                    path = ?path,
                    error = %e,
                    "streaming detokenizer flush error"
                )
            }
            _ => {}
        }
    }
}

fn make_stream_delta_event(path: &[JsonPathSegment], content: &str) -> Event {
    let mut chunk = json!({"choices": [{"index": 0, "delta": {}, "finish_reason": null}]});
    if let Some(delta_pos) = path
        .iter()
        .position(|segment| matches!(segment, JsonPathSegment::Key(key) if key == "delta"))
    {
        let relative = &path[delta_pos + 1..];
        set_value_at_path(
            &mut chunk["choices"][0]["delta"],
            relative,
            Value::String(content.to_string()),
        );
    }
    Event::default().data(chunk.to_string())
}

fn set_value_at_path(value: &mut Value, path: &[JsonPathSegment], replacement: Value) {
    if path.is_empty() {
        *value = replacement;
        return;
    }
    let mut current = value;
    for (index, segment) in path.iter().enumerate() {
        let is_last = index == path.len() - 1;
        match segment {
            JsonPathSegment::Key(key) => {
                if is_last {
                    current[key] = replacement;
                    return;
                }
                if !current.get(key).is_some() {
                    current[key] = match path.get(index + 1) {
                        Some(JsonPathSegment::Index(_)) => Value::Array(vec![]),
                        _ => Value::Object(serde_json::Map::new()),
                    };
                }
                current = &mut current[key];
            }
            JsonPathSegment::Index(item_index) => {
                if !current.is_array() {
                    *current = Value::Array(vec![]);
                }
                let items = current.as_array_mut().expect("current must be array");
                while items.len() <= *item_index {
                    items.push(Value::Object(serde_json::Map::new()));
                }
                if is_last {
                    items[*item_index] = replacement;
                    return;
                }
                current = &mut items[*item_index];
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        detector::{regex::RegexDetector, DetectorPipeline},
        tokenizer::Tokenizer,
        types::{EntityType, Token, TokenRecord},
        vault::{sqlite::SqliteVault, Vault},
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn make_detokenizer() -> Detokenizer {
        let vault: Arc<dyn Vault> = Arc::new(SqliteVault::open_in_memory(b"test-secret").unwrap());
        let now = unix_now();
        vault
            .store(&TokenRecord {
                token: Token::new("EMAIL_a1b2c3"),
                entity_type: EntityType::Email,
                encrypted_value: b"alice@example.test".to_vec(),
                session_id: Uuid::new_v4(),
                created_at: now,
                expires_at: now + 3600,
            })
            .unwrap();
        Detokenizer::new(vault)
    }

    fn make_tokenization_stack() -> (DetectorPipeline, Tokenizer, Detokenizer) {
        let secret = b"test-secret".to_vec();
        let vault: Arc<dyn Vault> = Arc::new(SqliteVault::open_in_memory(&secret).unwrap());
        let pipeline = DetectorPipeline::new(vec![Box::new(RegexDetector::new())]);
        let tokenizer = Tokenizer::new(Arc::clone(&vault), secret, Uuid::new_v4(), 24);
        let detokenizer = Detokenizer::new(vault);
        (pipeline, tokenizer, detokenizer)
    }

    #[test]
    fn detokenizes_streaming_tool_call_arguments() {
        let detokenizer = make_detokenizer();
        let mut streams = HashMap::new();
        let mut chunk = json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {
                            "arguments": format!(
                                "{{\"content\":\"EMAIL_a1b2c3\"}}{}",
                                "x".repeat(600)
                            )
                        }
                    }]
                },
                "finish_reason": null
            }]
        });

        assert!(detokenize_streaming_json_strings(
            &mut chunk,
            &mut streams,
            &detokenizer,
            Uuid::new_v4(),
        ));

        let arguments = chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments should contain the safe streamed prefix");
        assert!(
            arguments.contains("alice@example.test"),
            "streamed tool arguments should be detokenized before forwarding"
        );
        assert!(
            !arguments.contains("EMAIL_a1b2c3"),
            "streamed tool arguments should not leak raw Privox tokens"
        );
    }

    #[test]
    fn buffers_short_streaming_tool_call_arguments() {
        let detokenizer = make_detokenizer();
        let mut streams = HashMap::new();
        let mut chunk = json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {
                            "arguments": "{\"content\":\"EMAIL_"
                        }
                    }]
                },
                "finish_reason": null
            }]
        });

        assert!(detokenize_streaming_json_strings(
            &mut chunk,
            &mut streams,
            &detokenizer,
            Uuid::new_v4(),
        ));

        assert!(
            chunk["choices"][0].get("delta").is_none()
                || chunk["choices"][0]["delta"].as_object().unwrap().is_empty(),
            "buffered tool arguments should be withheld until they can be safely detokenized"
        );
    }

    #[test]
    fn detokenizes_streaming_content_recursively() {
        let detokenizer = make_detokenizer();
        let mut streams = HashMap::new();
        let mut chunk = json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "content": format!("{} EMAIL_a1b2c3 {}", "x".repeat(40), "y".repeat(600))
                },
                "finish_reason": null
            }]
        });

        assert!(detokenize_streaming_json_strings(
            &mut chunk,
            &mut streams,
            &detokenizer,
            Uuid::new_v4(),
        ));

        let content = chunk["choices"][0]["delta"]["content"]
            .as_str()
            .expect("content should contain the safe streamed prefix");
        assert!(content.contains("alice@example.test"));
        assert!(!content.contains("EMAIL_a1b2c3"));
    }

    #[tokio::test]
    async fn tokenizes_outbound_json_string_leaves_without_rewriting_protocol_fields() {
        let (pipeline, tokenizer, detokenizer) = make_tokenization_stack();
        let mut body = json!({
            "model": "qwen/qwen3.6-27b",
            "messages": [
                {
                    "role": "user",
                    "content": "Please process alice@example.test"
                },
                {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "workspace_write",
                            "arguments": "{\"content\":\"alice@example.test\"}"
                        }
                    }]
                }
            ]
        });

        let found = tokenize_json_strings(&mut body, &pipeline, &tokenizer, Uuid::new_v4())
            .await
            .expect("JSON string leaves should tokenize");

        let content = body["messages"][0]["content"]
            .as_str()
            .expect("content should remain a string");
        let arguments = body["messages"][1]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments should remain a string");
        assert_eq!(found, vec![EntityType::Email, EntityType::Email]);
        assert!(
            !content.contains("alice@example.test") && !arguments.contains("alice@example.test"),
            "outbound context must not expose restored values upstream"
        );
        assert!(
            content.contains("EMAIL_") && arguments.contains("EMAIL_"),
            "outbound context should use Privox tokens"
        );
        assert_eq!(body["model"].as_str().unwrap(), "qwen/qwen3.6-27b");
        assert_eq!(body["messages"][0]["role"].as_str().unwrap(), "user");
        assert_eq!(
            body["messages"][1]["tool_calls"][0]["function"]["name"]
                .as_str()
                .unwrap(),
            "workspace_write"
        );
        assert!(
            !arguments.contains("alice@example.test"),
            "outbound tool-call history must not expose restored values upstream"
        );
        assert!(
            arguments.contains("EMAIL_"),
            "outbound tool-call history should use Privox tokens"
        );
        assert_eq!(
            detokenizer.detokenize(arguments).unwrap(),
            "{\"content\":\"alice@example.test\"}"
        );
    }

    #[test]
    fn detokenizes_inbound_json_string_leaves() {
        let detokenizer = make_detokenizer();
        let mut body = json!({
            "choices": [{
                "message": {
                    "content": "Contact EMAIL_a1b2c3",
                    "tool_calls": [{
                        "function": {
                            "arguments": "{\"email\":\"EMAIL_a1b2c3\"}"
                        }
                    }]
                }
            }]
        });

        detokenize_json_strings(&mut body, &detokenizer).expect("JSON should detokenize");

        assert_eq!(
            body["choices"][0]["message"]["content"].as_str().unwrap(),
            "Contact alice@example.test"
        );
        assert_eq!(
            body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap(),
            "{\"email\":\"alice@example.test\"}"
        );
    }
}
