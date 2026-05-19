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
                // Map upstream Ollama outcomes to client-facing status codes
                // WITHOUT leaking URLs, hostnames, or reqwest internals. Only
                // the upstream HTTP status code is reflected through; the
                // body is always a stable generic message.
                match &e {
                    // Upstream returned a structured error: surface its
                    // status class so clients can distinguish 404 (request
                    // fix) from 5xx (retry-friendly).
                    crate::ollama::OllamaError::ApiError { status, .. } => match status.as_u16() {
                        404 => (
                            StatusCode::NOT_FOUND,
                            "Model not found on upstream Ollama.".to_string(),
                        ),
                        s if (400..500).contains(&s) => (
                            // Reflect the upstream client-error status (e.g.
                            // 400 bad request, 413 payload too large) but
                            // keep the body generic.
                            StatusCode::from_u16(s).unwrap_or(StatusCode::BAD_REQUEST),
                            "Ollama rejected the request.".to_string(),
                        ),
                        _ => (
                            StatusCode::BAD_GATEWAY,
                            "Upstream Ollama service error.".to_string(),
                        ),
                    },
                    // Network-level failure (DNS, connect, timeout). Treat
                    // as a transient infrastructure problem so the client
                    // can decide whether to retry.
                    crate::ollama::OllamaError::RequestError(req_err) => {
                        if req_err.is_timeout() || req_err.is_connect() {
                            (
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Upstream Ollama unreachable.".to_string(),
                            )
                        } else {
                            (
                                StatusCode::BAD_GATEWAY,
                                "Upstream Ollama service unavailable.".to_string(),
                            )
                        }
                    }
                    crate::ollama::OllamaError::ConfigError(_) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Ollama client misconfigured.".to_string(),
                    ),
                }
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
    async fn ollama_404_returns_404_without_leaking_upstream_detail() {
        // Upstream 404 (model not found) deserves its own status code so
        // clients can distinguish a request-fix problem from a retry-friendly
        // one. The leaky message must not appear in the body.
        let leaky = ApiError::OllamaError(crate::ollama::OllamaError::ApiError {
            status: reqwest::StatusCode::NOT_FOUND,
            message: "model 'super-secret-internal-name' not found at 10.0.0.5:11434".into(),
        });
        let (status, msg, _) = render(leaky).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(msg.contains("Model not found"));
        assert!(!msg.contains("super-secret-internal-name"));
        assert!(!msg.contains("10.0.0.5"));
    }

    #[tokio::test]
    async fn ollama_4xx_reflects_status_with_generic_body() {
        let leaky = ApiError::OllamaError(crate::ollama::OllamaError::ApiError {
            status: reqwest::StatusCode::PAYLOAD_TOO_LARGE,
            message: "request body too large at internal-host:11434".into(),
        });
        let (status, msg, _) = render(leaky).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(msg.contains("Ollama rejected"));
        assert!(!msg.contains("internal-host"));
    }

    #[tokio::test]
    async fn ollama_5xx_collapses_to_502_without_leaking_detail() {
        let leaky = ApiError::OllamaError(crate::ollama::OllamaError::ApiError {
            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            message: "panic at line 42 of /opt/ollama/internal.rs".into(),
        });
        let (status, msg, _) = render(leaky).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(msg.contains("Upstream Ollama"));
        assert!(!msg.contains("internal.rs"));
    }

    #[tokio::test]
    async fn ollama_config_error_returns_500() {
        let leaky = ApiError::OllamaError(crate::ollama::OllamaError::ConfigError(
            "missing CA bundle at /opt/secret-path".into(),
        ));
        let (status, msg, _) = render(leaky).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!msg.contains("/opt/secret-path"));
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
