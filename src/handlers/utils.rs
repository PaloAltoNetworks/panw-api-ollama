use crate::{handlers::ApiError, stream::SecurityAssessedStream, AppState};

use axum::{body::Body, response::Response};
use bytes::Bytes;
use futures_util::stream::StreamExt;
use http_body_util::StreamBody;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{error, info};

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
pub async fn handle_streaming_request<T, R>(
    state: &AppState,
    request: T,
    endpoint: &str,
    model: &str,
    is_prompt: bool,
) -> Result<Response<Body>, ApiError>
where
    T: Serialize + Send + 'static,
    R: DeserializeOwned + Serialize + Send + Sync + Unpin + 'static,
{
    // Get the original stream from ollama client
    let stream = state.ollama_client.stream(endpoint, &request).await?;

    // Convert the stream to the expected type by mapping the error type
    let converted_stream = stream.map(|result| result.map_err(convert_stream_error));

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
            let error_message = match e {
                _ => "Error processing response",
            };
            let error_json = serde_json::json!({
                "model": model_string,
                "error": error_message,
                "done": true
            });
            let error_bytes = serde_json::to_vec(&error_json)
                .unwrap_or_else(|_| error_message.as_bytes().to_vec());
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

    format!(
        "\n\n⚠️ This content was blocked due to security policy violations:\n\n\
         • Category: {}\n\
         • Action: {}\n\
         • Reasons: \n\
          - {}\n\n\
         Please reformulate your request to comply with security policies.\n\n",
        assessment.category, assessment.action, reasons_text
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
        ("prompt_eval_duration", json_data.get("prompt_eval_duration")),
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
        let mode = if is_streaming { "streaming" } else { "non-streaming" };
        info!("LLM {} performance metrics - {}", mode, metrics_string.join(", "));
        true
    } else {
        false
    }
}
