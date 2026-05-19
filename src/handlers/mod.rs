use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::error;

pub mod chat;
pub mod embeddings;
pub mod generate;
pub mod models;
pub mod utils;
pub mod version;

// Custom error types for API request handling.
//
// This enum represents the various error conditions that can occur
// when handling API requests. It consolidates errors from the Ollama client,
// security assessment, and internal server issues into a unified error type
// that can be converted into appropriate HTTP responses.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub enum ApiError {
    // Errors from the Ollama backend service.
    //
    // These errors occur when communicating with the Ollama API,
    // such as connection failures, timeouts, or invalid responses.
    #[error("Ollama error: {0}")]
    OllamaError(#[from] crate::ollama::OllamaError),
    
    // Errors from the security assessment system.
    //
    // These errors occur during content security scanning,
    // including API failures or policy violations.
    #[error("Security error: {0}")]
    SecurityError(#[from] crate::security::SecurityError),
    
    // Internal server errors.
    //
    // General errors that occur within the application itself,
    // not directly related to external services.
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl IntoResponse for ApiError {
    // Converts an API error into an HTTP response.
    //
    // Maps each error type to an appropriate HTTP status code and
    // formats the error message for the response body.
    fn into_response(self) -> Response {
        // Map error types to appropriate status codes and messages.
        //
        // Error responses returned to the client must NEVER include upstream
        // detail (URLs, internal hostnames, reqwest serialization context,
        // arbitrary strings from external services). Full detail is logged
        // server-side at error level; the client receives a stable, generic
        // message scoped to a category.
        let (status, error_message) = match self {
            ApiError::OllamaError(e) => {
                error!("Ollama service error: {}", e);
                (
                    StatusCode::BAD_GATEWAY,
                    "Upstream Ollama service unavailable.".to_string(),
                )
            }
            ApiError::SecurityError(e) => {
                error!("Security assessment error: {}", e);
                match e {
                    crate::security::SecurityError::Forbidden => (
                        StatusCode::FORBIDDEN,
                        "Invalid API key or insufficient permissions. Please check your PANW API key configuration.".to_string(),
                    ),
                    crate::security::SecurityError::Unauthenticated => (
                        StatusCode::UNAUTHORIZED,
                        "Authentication failed. Please check your credentials.".to_string(),
                    ),
                    crate::security::SecurityError::TooManyRequests(interval, unit) => (
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("Rate limit exceeded. Please retry after {} {}.", interval, unit),
                    ),
                    crate::security::SecurityError::BlockedContent(msg) => (
                        StatusCode::FORBIDDEN,
                        format!("Content blocked: {}", msg),
                    ),
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Security service error. See server logs for details.".to_string(),
                    ),
                }
            }
            ApiError::InternalError(msg) => {
                error!("Internal server error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error.".to_string(),
                )
            }
        };

        // Create a JSON response with the error message
        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16(),
        }));
        
        // Return the status code and body as a response
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityError;
    use axum::body::to_bytes;
    use serde_json::Value;

    // Drives the real `IntoResponse::into_response` impl, then reads the body
    // bytes through axum's body reader and parses the JSON envelope. Returns
    // `(status, error_field, raw_json)` so tests assert on the actual wire
    // format clients see, not a duplicated mock.
    async fn render(err: ApiError) -> (StatusCode, String, Value) {
        let resp = err.into_response();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read response body");
        let json: Value = serde_json::from_slice(&body).expect("response body is valid JSON");
        let msg = json
            .get("error")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .expect("response body has an `error` field");
        (status, msg, json)
    }

    #[tokio::test]
    async fn internal_error_does_not_leak_message_to_client() {
        let leaky = ApiError::InternalError("DB at 10.0.0.5 down: secret_xyz".into());
        let (status, msg, json) = render(leaky).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!msg.contains("10.0.0.5"));
        assert!(!msg.contains("secret_xyz"));
        // Wire envelope contract: `status` field mirrors the HTTP status code.
        assert_eq!(json.get("status").and_then(|v| v.as_u64()), Some(500));
    }

    #[tokio::test]
    async fn security_assessment_error_does_not_leak_upstream_detail() {
        let leaky = ApiError::SecurityError(SecurityError::AssessmentError(
            "PANW returned 502 from internal.svc:8080".into(),
        ));
        let (status, msg, _json) = render(leaky).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!msg.contains("internal.svc"));
        assert!(!msg.contains("8080"));
    }

    #[tokio::test]
    async fn ollama_error_does_not_leak_upstream_detail() {
        // ApiError::OllamaError wraps OllamaError; construct an ApiError of
        // that variant via OllamaError::ApiError which carries leaky fields.
        let leaky = ApiError::OllamaError(crate::ollama::OllamaError::ApiError {
            status: reqwest::StatusCode::NOT_FOUND,
            message: "model 'super-secret-internal-name' not found at 10.0.0.5:11434".into(),
        });
        let (status, msg, _) = render(leaky).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!msg.contains("super-secret-internal-name"));
        assert!(!msg.contains("10.0.0.5"));
    }

    #[tokio::test]
    async fn user_actionable_security_messages_are_preserved() {
        let (s, m, _) = render(ApiError::SecurityError(SecurityError::Forbidden)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(m.contains("API key"));

        let (s, m, _) = render(ApiError::SecurityError(SecurityError::Unauthenticated)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(m.contains("Authentication"));

        let (s, m, _) = render(ApiError::SecurityError(SecurityError::TooManyRequests(
            5,
            "minute".into(),
        ))).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert!(m.contains("5 minute"));

        let (s, m, _) = render(ApiError::SecurityError(SecurityError::BlockedContent(
            "policy:dlp".into(),
        ))).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(m.contains("policy:dlp"));
    }
}
