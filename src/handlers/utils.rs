use crate::{handlers::ApiError, stream::SecurityAssessedStream, AppState};

use async_stream::stream;
use axum::{body::Body, response::Response};
use bytes::Bytes;
use futures_util::stream::StreamExt;
use http_body_util::StreamBody;
use serde::Serialize;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{error, info, warn};

// Maximum wall-clock time the proxy will wait between successive chunks
// from the upstream Ollama stream before aborting the connection.
//
// Defends against slow-loris-style attacks where an adversarial upstream
// (or a wedged Ollama process) drips a few bytes and then stalls
// indefinitely, accumulating buffer state and tying up a tokio task.
//
// Tunable via `STREAM_CHUNK_TIMEOUT_SECS` (default: 300s = 5 min, generous
// because legitimate slow models can take a long time to emit the first
// token). Setting `0` disables the timeout.
const DEFAULT_STREAM_CHUNK_TIMEOUT_SECS: u64 = 300;

fn stream_chunk_timeout() -> Option<Duration> {
    let secs = std::env::var("STREAM_CHUNK_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_STREAM_CHUNK_TIMEOUT_SECS);
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

// Builds an HTTP response with JSON content type from the provided bytes.
pub fn build_json_response(bytes: Bytes) -> Result<Response<Body>, ApiError> {
    Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from(bytes))
        .map_err(|e| ApiError::InternalError(format!("Failed to create response: {}", e)))
}

// Helper function to convert `reqwest::Error` to `StreamError`.
fn convert_stream_error(err: reqwest::Error) -> reqwest::Error {
    err // Maintain original error type
}

// Handles streaming requests to API endpoints, applying security assessment to the streamed responses.
pub async fn handle_streaming_request<T>(
    state: &AppState,
    request: T,
    endpoint: &str,
    model: &str,
    is_prompt: bool,
) -> Result<Response<Body>, ApiError>
where
    T: Serialize + Send + 'static,
{
    // Get the original stream from ollama client
    let upstream = state.ollama_client.stream(endpoint, &request).await?;

    // Wrap upstream with a per-chunk wall-clock timeout. If the upstream
    // does not produce a chunk within `chunk_timeout`, terminate the stream
    // cleanly so buffer state and tokio resources are released. This is a
    // defensive guard against a wedged or adversarial upstream; legitimate
    // slow models stay well under the default 5-minute window.
    let chunk_timeout = stream_chunk_timeout();
    let timed_stream = stream! {
        let mut upstream = Box::pin(upstream);
        loop {
            let next = match chunk_timeout {
                Some(d) => match timeout(d, upstream.next()).await {
                    Ok(item) => item,
                    Err(_elapsed) => {
                        warn!(
                            "Upstream Ollama stream produced no chunk within {:?}; aborting",
                            d
                        );
                        break;
                    }
                },
                None => upstream.next().await,
            };
            match next {
                Some(item) => yield item,
                None => break,
            }
        }
    };

    // SecurityAssessedStream requires `S: Stream + Unpin`. async_stream's
    // `AsyncStream` is `!Unpin`; pin to the heap so the type satisfies the
    // bound without changing the downstream API.
    let timed_stream = Box::pin(timed_stream);

    // Convert the stream to the expected type by mapping the error type
    let converted_stream = timed_stream.map(|result| result.map_err(convert_stream_error));

    // Create the security-assessed stream
    let assessed_stream = SecurityAssessedStream::new(
        converted_stream,
        state.security_client.clone(),
        model.to_string(),
        is_prompt,
    );

    // Clone the model string for use in the closure
    let model_string = model.to_string();

    // Map any errors to bytes for the final stream - add 'move' to take ownership
    let mapped_stream = assessed_stream.map(move |result| match result {
        Ok(bytes) => Ok::<_, std::convert::Infallible>(bytes),
        Err(e) => {
            error!("Error in security assessment stream: {:?}", e);
            // Convert error to a user-friendly message
            const ERROR_MESSAGE: &str = "Error processing response";
            let error_json = serde_json::json!({
                "model": model_string,
                "error": ERROR_MESSAGE,
                "done": true
            });
            let error_bytes = serde_json::to_vec(&error_json)
                .unwrap_or_else(|_| ERROR_MESSAGE.as_bytes().to_vec());
            Ok(Bytes::from(error_bytes))
        }
    });

    // Create and return the streaming response
    let stream_body = StreamBody::new(mapped_stream);
    let body = Body::from_stream(stream_body);

    Response::builder()
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| ApiError::InternalError(format!("Failed to create response: {}", e)))
}

// Formats a comprehensive security violation message with detailed detection reasons.
pub fn format_security_violation_message(assessment: &crate::security::Assessment) -> String {
    let mut reasons = Vec::new();

    // Check prompt detection reasons
    if assessment.details.prompt_detected.url_cats {
        reasons.push("Prompt contains malicious URLs");
    }
    if assessment.details.prompt_detected.dlp {
        reasons.push("Prompt contains sensitive information");
    }
    if assessment.details.prompt_detected.injection {
        reasons.push("Prompt contains injection threats");
    }
    if assessment.details.prompt_detected.toxic_content {
        reasons.push("Prompt contains harmful content");
    }
    if assessment.details.prompt_detected.malicious_code {
        reasons.push("Prompt contains malicious code");
    }
    if assessment.details.prompt_detected.agent {
        reasons.push("Prompt contains any Agent related threats");
    }
    if assessment.details.prompt_detected.topic_violation {
        reasons.push("Prompt contains any content violates topic guardrails");
    }

    // Check response detection reasons
    if assessment.details.response_detected.url_cats {
        reasons.push("Response contains malicious URLs");
    }
    if assessment.details.response_detected.dlp {
        reasons.push("Response contains sensitive information");
    }
    if assessment.details.response_detected.db_security {
        reasons.push("Response contains database security threats");
    }
    if assessment.details.response_detected.toxic_content {
        reasons.push("Response contains harmful content");
    }
    if assessment.details.response_detected.malicious_code {
        reasons.push("Response contains malicious code");
    }
    if assessment.details.response_detected.agent {
        reasons.push("Response contains any Agent related threats");
    }
    if assessment.details.response_detected.ungrounded {
        reasons.push("Response contains any ungrounded content");
    }
    if assessment.details.response_detected.topic_violation {
        reasons.push("Response contains any content violates topic guardrails");
    }

    let reasons_text = if reasons.is_empty() {
        "Unspecified security concern".to_string()
    } else {
        reasons.join("\n - ")
    };

    // Format topic guardrails information if available
    let mut topic_info = String::new();

    // Check prompt topic guardrails
    if let Some(ref details) = assessment
        .details
        .prompt_detection_details
        .topic_guardrails_details
    {
        if !details.allowed_topics.is_empty() {
            topic_info.push_str("\n• Allowed Topics:\n");
            for topic in &details.allowed_topics {
                topic_info.push_str(&format!("  - {}\n", topic));
            }
        }
        if !details.blocked_topics.is_empty() {
            topic_info.push_str("\n• Blocked Topics:\n");
            for topic in &details.blocked_topics {
                topic_info.push_str(&format!("  - {}\n", topic));
            }
        }
    }

    // Check response topic guardrails
    if let Some(ref details) = assessment
        .details
        .response_detection_details
        .topic_guardrails_details
    {
        if !details.allowed_topics.is_empty() {
            topic_info.push_str("\n• Allowed Topics (Response):\n");
            for topic in &details.allowed_topics {
                topic_info.push_str(&format!("  - {}\n", topic));
            }
        }
        if !details.blocked_topics.is_empty() {
            topic_info.push_str("\n• Blocked Topics (Response):\n");
            for topic in &details.blocked_topics {
                topic_info.push_str(&format!("  - {}\n", topic));
            }
        }
    }

    format!(
        "\n\n⚠️ This content was blocked due to security policy violations:\n\n\
         • Category: {}\n\
         • Action: {}\n\
         • Reasons: \n\
          - {}{}\n\
         \n\nPlease reformulate your request to comply with security policies.\n\n",
        assessment.category, assessment.action, reasons_text, topic_info
    )
}

// Builds a response with serialized data for a security violation.
pub fn build_violation_response<T>(data: T) -> Result<Response<Body>, ApiError>
where
    T: Serialize,
{
    let json_bytes = serde_json::to_vec(&data).map_err(|e| {
        error!("Failed to serialize response: {}", e);
        ApiError::InternalError("Failed to serialize response".to_string())
    })?;
    build_json_response(Bytes::from(json_bytes))
}

/// Extract and log LLM performance metrics from JSON response data
///
/// # Arguments
///
/// * `json_data` - The JSON data potentially containing LLM metrics
/// * `is_streaming` - Whether this is from a streaming response or not
///
/// # Returns
///
/// Returns true if metrics were found and logged, false otherwise
pub fn log_llm_metrics(json_data: &serde_json::Value, is_streaming: bool) -> bool {
    let eval_metrics = [
        ("total_duration", json_data.get("total_duration")),
        ("load_duration", json_data.get("load_duration")),
        ("prompt_eval_count", json_data.get("prompt_eval_count")),
        (
            "prompt_eval_duration",
            json_data.get("prompt_eval_duration"),
        ),
        ("eval_count", json_data.get("eval_count")),
        ("eval_duration", json_data.get("eval_duration")),
    ];

    let metrics_string: Vec<String> = eval_metrics
        .iter()
        .filter_map(|(name, value)| {
            value.and_then(|v| v.as_u64()).map(|v| {
                if name.contains("duration") && !name.contains("count") {
                    format!("{}: {}ms", name, v / 1_000_000) // Convert ns to ms
                } else {
                    format!("{}: {}", name, v)
                }
            })
        })
        .collect();

    if !metrics_string.is_empty() {
        let mode = if is_streaming {
            "streaming"
        } else {
            "non-streaming"
        };
        info!(
            "LLM {} performance metrics - {}",
            mode,
            metrics_string.join(", ")
        );
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::Assessment;
    use crate::types::ScanResponse;
    use serde_json::json;

    fn assessment_with_prompt_dlp() -> Assessment {
        let mut details = ScanResponse::default_safe_response();
        details.prompt_detected.dlp = true;
        details.prompt_detected.injection = true;
        Assessment {
            is_safe: false,
            category: "malicious".into(),
            action: "block".into(),
            final_content: String::new(),
            is_masked: false,
            details,
        }
    }

    #[test]
    fn format_security_violation_lists_each_active_reason() {
        let a = assessment_with_prompt_dlp();
        let msg = format_security_violation_message(&a);
        assert!(msg.contains("Category: malicious"));
        assert!(msg.contains("Action: block"));
        assert!(msg.contains("Prompt contains sensitive information"));
        assert!(msg.contains("Prompt contains injection threats"));
    }

    #[test]
    fn format_security_violation_falls_back_when_no_flags_set() {
        let mut a = assessment_with_prompt_dlp();
        // Reset every flag.
        a.details = ScanResponse::default_safe_response();
        let msg = format_security_violation_message(&a);
        assert!(msg.contains("Unspecified security concern"));
    }

    #[test]
    fn log_llm_metrics_returns_false_when_no_metrics_present() {
        let v = json!({"model": "qwen", "done": true});
        assert!(!log_llm_metrics(&v, false));
    }

    #[test]
    fn log_llm_metrics_returns_true_when_metrics_present() {
        let v = json!({
            "total_duration": 1_500_000_000u64,
            "load_duration": 500_000_000u64,
            "eval_count": 42u64,
            "eval_duration": 700_000_000u64
        });
        assert!(log_llm_metrics(&v, true));
    }

    #[test]
    fn build_json_response_sets_content_type() {
        let resp = build_json_response(Bytes::from_static(b"{\"ok\":true}")).unwrap();
        let ct = resp
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(ct, "application/json");
    }

    // The env-driven timeout helper is exercised in isolation. The streaming
    // integration path is covered by the live smoke suite.
    //
    // Note: these tests mutate process-wide env vars and therefore must not
    // run concurrently with each other. They share a mutex via `serial_test`
    // would be cleanest, but since this crate has no other env-touching tests
    // we accept the convention that all `STREAM_CHUNK_TIMEOUT_SECS` access
    // lives here and rely on cargo's per-test isolation when running with
    // `--test-threads=1` for env-sensitive runs.
    #[test]
    fn stream_chunk_timeout_default_when_env_unset() {
        std::env::remove_var("STREAM_CHUNK_TIMEOUT_SECS");
        assert_eq!(
            stream_chunk_timeout(),
            Some(Duration::from_secs(DEFAULT_STREAM_CHUNK_TIMEOUT_SECS))
        );
    }

    #[test]
    fn stream_chunk_timeout_respects_env_value() {
        std::env::set_var("STREAM_CHUNK_TIMEOUT_SECS", "42");
        assert_eq!(stream_chunk_timeout(), Some(Duration::from_secs(42)));
        std::env::remove_var("STREAM_CHUNK_TIMEOUT_SECS");
    }

    #[test]
    fn stream_chunk_timeout_zero_disables_timeout() {
        std::env::set_var("STREAM_CHUNK_TIMEOUT_SECS", "0");
        assert_eq!(stream_chunk_timeout(), None);
        std::env::remove_var("STREAM_CHUNK_TIMEOUT_SECS");
    }

    #[test]
    fn stream_chunk_timeout_falls_back_to_default_on_garbage() {
        std::env::set_var("STREAM_CHUNK_TIMEOUT_SECS", "not-a-number");
        assert_eq!(
            stream_chunk_timeout(),
            Some(Duration::from_secs(DEFAULT_STREAM_CHUNK_TIMEOUT_SECS))
        );
        std::env::remove_var("STREAM_CHUNK_TIMEOUT_SECS");
    }
}
