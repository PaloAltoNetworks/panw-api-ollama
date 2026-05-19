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

    fn body_str(err: ApiError) -> (StatusCode, String) {
        let (status, msg) = match err {
            ApiError::OllamaError(_) => (
                StatusCode::BAD_GATEWAY,
                "Upstream Ollama service unavailable.".to_string(),
            ),
            ApiError::SecurityError(e) => match e {
                SecurityError::Forbidden => (
                    StatusCode::FORBIDDEN,
                    "Invalid API key or insufficient permissions. Please check your PANW API key configuration.".to_string(),
                ),
                SecurityError::Unauthenticated => (
                    StatusCode::UNAUTHORIZED,
                    "Authentication failed. Please check your credentials.".to_string(),
                ),
                SecurityError::TooManyRequests(i, u) => (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("Rate limit exceeded. Please retry after {} {}.", i, u),
                ),
                SecurityError::BlockedContent(m) => (
                    StatusCode::FORBIDDEN,
                    format!("Content blocked: {}", m),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Security service error. See server logs for details.".to_string(),
                ),
            },
            ApiError::InternalError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error.".to_string(),
            ),
        };
        (status, msg)
    }

    #[test]
    fn internal_error_does_not_leak_message_to_client() {
        let leaky = ApiError::InternalError("DB at 10.0.0.5 down: secret_xyz".into());
        let (status, msg) = body_str(leaky);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!msg.contains("10.0.0.5"));
        assert!(!msg.contains("secret_xyz"));
    }

    #[test]
    fn security_assessment_error_does_not_leak_upstream_detail() {
        let leaky = ApiError::SecurityError(SecurityError::AssessmentError(
            "PANW returned 502 from internal.svc:8080".into(),
        ));
        let (status, msg) = body_str(leaky);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!msg.contains("internal.svc"));
        assert!(!msg.contains("8080"));
    }

    #[test]
    fn user_actionable_security_messages_are_preserved() {
        let (s, m) = body_str(ApiError::SecurityError(SecurityError::Forbidden));
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(m.contains("API key"));

        let (s, m) = body_str(ApiError::SecurityError(SecurityError::Unauthenticated));
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(m.contains("Authentication"));

        let (s, m) = body_str(ApiError::SecurityError(SecurityError::TooManyRequests(
            5,
            "minute".into(),
        )));
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert!(m.contains("5 minute"));

        let (s, m) = body_str(ApiError::SecurityError(SecurityError::BlockedContent(
            "policy:dlp".into(),
        )));
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(m.contains("policy:dlp"));
    }
}
