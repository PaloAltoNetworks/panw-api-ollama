use crate::handlers::utils::{build_json_response, build_violation_response};
use crate::handlers::ApiError;
use crate::types::EmbeddingsRequest;
use crate::types::EmbeddingsResponse;
use crate::AppState;
use axum::{extract::State, response::Response, Json};
use tracing::debug;

pub async fn handle_embeddings(
    State(state): State<AppState>,
    Json(request): Json<EmbeddingsRequest>,
) -> Result<Response, ApiError> {
    debug!("Received embeddings request for model: {}", request.model);

    let assessment = state
        .security_client
        .assess_content(
            &request.prompt,
            &request.model,
            true, // This is a prompt
        )
        .await?;

    if !assessment.is_safe {
        // Return a mock embedding response with zeros
        let response = EmbeddingsResponse {
            embedding: vec![0.0; 10], // A small vector of zeros as placeholder
        };

        return build_violation_response(response);
    }

    // Forward to Ollama
    let response = state
        .ollama_client
        .forward("/api/embeddings", &request)
        .await?;
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    Ok(build_json_response(body_bytes)?)
}
