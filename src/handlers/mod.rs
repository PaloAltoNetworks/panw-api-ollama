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
        // Map error types to appropriate status codes and messages
        let (status, error_message) = match self {
            ApiError::OllamaError(e) => {
                error!("Ollama service error: {}", e);
                (StatusCode::BAD_GATEWAY, format!("Ollama error: {}", e))
            },
            ApiError::SecurityError(e) => {
                error!("Security assessment error: {}", e);
                match e {
                    crate::security::SecurityError::Forbidden => (
                        StatusCode::FORBIDDEN,
                        "Invalid API key or insufficient permissions. Please check your PANW API key configuration.".to_string()
                    ),
                    crate::security::SecurityError::Unauthenticated => (
                        StatusCode::UNAUTHORIZED,
                        "Authentication failed. Please check your credentials.".to_string()
                    ),
                    crate::security::SecurityError::TooManyRequests(interval, unit) => (
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("Rate limit exceeded. Please retry after {} {}.", interval, unit)
                    ),
                    crate::security::SecurityError::BlockedContent(msg) => (
                        StatusCode::FORBIDDEN,
                        format!("Content blocked: {}", msg)
                    ),
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR, 
                        format!("Security service error: {}", e)
                    ),
                }
            },
            ApiError::InternalError(msg) => {
                error!("Internal server error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, msg)
            },
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
