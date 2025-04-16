// Handler for text generation requests from the Ollama API.
//
// This module provides security-enhanced handlers for text generation
// requests, scanning both prompts and responses for policy violations.
use axum::{extract::State, response::Response, Json};
use tracing::{debug, error};

use crate::handlers::utils::{
    build_json_response, build_violation_response, format_security_violation_message,
    handle_streaming_request, log_llm_metrics,
};
use crate::handlers::ApiError;
use crate::types::{GenerateRequest, GenerateResponse};
use crate::AppState;

// Handles text generation requests with security assessment.
//
// This handler:
// 1. Performs security checks on the input prompt
// 2. Routes the request to Ollama if the prompt passes security checks
// 3. Scans the generated response for security issues before returning to client
// 4. Handles both streaming and non-streaming requests
//
// # Arguments
//
// * `State(state)` - Application state containing client connections
// * `Json(request)` - The generation request from the client
//
// # Returns
//
// * `Ok(Response)` - The generation response
// * `Err(ApiError)` - If an error occurs during processing
pub async fn handle_generate(
    State(state): State<AppState>,
    Json(request): Json<GenerateRequest>,
) -> Result<Response, ApiError> {
    // Ensure stream parameter is explicitly set
    // request.stream = Some(false);

    debug!("Received generate request for model: {}", request.model);

    // Check the input prompt for security violations
    if let Err(response) = assess_generate_prompt(&state, &request).await? {
        return Ok(response);
    }

    // Route based on streaming or non-streaming mode
    if request.stream.unwrap() {
        debug!("Handling streaming generate request");
        handle_streaming_generate(State(state), Json(request)).await
    } else {
        debug!("Handling non-streaming generate request");
        handle_non_streaming_generate(State(state), Json(request)).await
    }
}

// Assesses a generation prompt for security policy violations.
//
// # Arguments
//
// * `state` - Application state containing security client
// * `request` - The generation request containing the prompt to assess
//
// # Returns
//
// * `Ok(Ok(()))` - If the prompt passes security checks
// * `Ok(Err(Response))` - If security violation is detected, with appropriate response
// * `Err(ApiError)` - If an error occurs during security assessment
async fn assess_generate_prompt(
    state: &AppState,
    request: &GenerateRequest,
) -> Result<Result<(), Response>, ApiError> {
    // Check input prompt
    let assessment = state
        .security_client
        .assess_content(&request.prompt, &request.model, true)
        .await?;

    // If the content is not safe, create a blocked response
    if !assessment.is_safe {
        let blocked_message = format_security_violation_message(&assessment);

        let response = GenerateResponse {
            model: request.model.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            response: blocked_message,
            context: None,
            done: true,
        };

        return Ok(Err(build_violation_response(response)?));
    }

    Ok(Ok(()))
}

// Handles non-streaming generate requests.
//
// # Arguments
//
// * `State(state)` - Application state containing client connections
// * `Json(request)` - The generation request from the client
//
// # Returns
//
// * `Ok(Response)` - The generation response
// * `Err(ApiError)` - If an error occurs during processing
async fn handle_non_streaming_generate(
    State(state): State<AppState>,
    Json(request): Json<GenerateRequest>,
) -> Result<Response, ApiError> {
    debug!("Processing non-streaming generate request");

    // Forward request to Ollama
    let response = state
        .ollama_client
        .forward("/api/generate", &request)
        .await?;

    // Read response body
    let body_bytes = response.bytes().await.map_err(|e| {
        error!("Failed to read response body: {}", e);
        ApiError::InternalError("Failed to read response body".to_string())
    })?;

    // Extract and log performance metrics if available
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        log_llm_metrics(&json, false);
    }

    // Parse response
    let mut response_body: GenerateResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
        error!("Failed to parse response: {}", e);
        ApiError::InternalError("Failed to parse response".to_string())
    })?;

    // Check model output for security issues
    let assessment = state
        .security_client
        .assess_content(&response_body.response, &request.model, false)
        .await?;

    // If response is not safe, replace content with security message
    if !assessment.is_safe {
        // Replace the content with security message
        response_body.response = format_security_violation_message(&assessment);

        return build_violation_response(response_body);
    }

    // Return safe response
    Ok(build_json_response(body_bytes)?)
}

// Handles streaming generate requests.
//
// # Arguments
//
// * `State(state)` - Application state containing client connections
// * `Json(request)` - The generation request from the client
//
// # Returns
//
// * `Ok(Response)` - The streaming response
// * `Err(ApiError)` - If an error occurs during processing
async fn handle_streaming_generate(
    State(state): State<AppState>,
    Json(request): Json<GenerateRequest>,
) -> Result<Response, ApiError> {
    debug!("Setting up streaming generate request");

    let model = request.model.clone();
    // For streaming generate, we're dealing with responses from the LLM, so is_prompt should be false
    handle_streaming_request::<GenerateRequest, GenerateResponse>(
        &state,
        request,
        "/api/generate",
        &model,
        false,
    )
    .await
}
