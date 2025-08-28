use axum::{extract::State, response::Response};
use tracing::debug;

use crate::handlers::utils::build_json_response;
use crate::handlers::ApiError;
use crate::AppState;

pub async fn handle_version(State(state): State<AppState>) -> Result<Response, ApiError> {
    debug!("Forwarding version request");
    let response = state.ollama_client.forward_get("/api/version").await?;
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    build_json_response(body_bytes)
}
