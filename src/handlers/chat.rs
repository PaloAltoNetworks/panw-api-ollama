// Chat request handler for the Ollama API proxy.
//
// This module handles chat completion requests with security assessment
// for both incoming prompts and outgoing AI responses.
//
// # Module Overview
//
// The chat handler serves as a secure proxy between clients and the Ollama API,
// ensuring that both prompts sent to the language model and responses from the
// model are scanned for security issues using Palo Alto Networks' AI Runtime API.
//
// # Features
//
// - Security assessment of all chat messages
// - Support for both streaming and non-streaming response formats
// - Consistent error handling and security violation reporting
// - Transparent proxying of valid requests to Ollama backend
use axum::{extract::State, response::Response, Json};
use tracing::{debug, error, info};

use crate::handlers::utils::{
    build_json_response, build_violation_response, format_security_violation_message,
    handle_streaming_request, log_llm_metrics,
};
use crate::handlers::ApiError;
use crate::types::{ChatRequest, ChatResponse, Message};
use crate::AppState;

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

// Handles chat completion requests with security assessment.
//
// This handler:
// 1. Performs security checks on incoming chat messages
// 2. Routes the request to Ollama if messages pass security checks
// 3. Scans the response for security issues before returning to client
// 4. Handles both streaming and non-streaming responses
//
// # Arguments
//
// * `State(state)` - Application state containing client connections
// * `Json(request)` - The chat completion request from the client
//
// # Returns
//
// * `Ok(Response)` - The chat completion response
// * `Err(ApiError)` - If an error occurs during processing
pub async fn handle_chat(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Response, ApiError> {
    // Ensure stream parameter is always set
    // request.stream = Some(false);

    info!("Received chat request for model: {}", request.model);
    debug!(
        "Chat request details: stream={}, messages={}",
        request.stream.unwrap(),
        request.messages.len()
    );

    // Security assessment: check all input messages for policy violations
    if let Err(response) = assess_chat_messages(&state, &request).await? {
        return Ok(response);
    }

    // Route based on streaming or non-streaming mode
    if request.stream.unwrap() {
        debug!("Handling streaming chat request");
        handle_streaming_chat(State(state), Json(request)).await
    } else {
        debug!("Handling non-streaming chat request");
        handle_non_streaming_chat(State(state), Json(request)).await
    }
}

//------------------------------------------------------------------------------
// Helper Functions
//------------------------------------------------------------------------------

// Assesses all chat messages for security policy violations.
//
// Iterates through each message in the chat request and uses the security client
// to check for policy violations or harmful content.
//
// # Arguments
//
// * `state` - Application state containing security client
// * `request` - The chat request containing messages to assess
//
// # Returns
//
// * `Ok(Ok(()))` - If all messages pass security checks
// * `Ok(Err(Response))` - If security violation is detected, with appropriate response
// * `Err(ApiError)` - If an error occurs during security assessment
async fn assess_chat_messages(
    state: &AppState,
    request: &ChatRequest,
) -> Result<Result<(), Response>, ApiError> {
    for (index, message) in request.messages.iter().enumerate() {
        debug!(
            "Assessing message {}/{}: role={}",
            index + 1,
            request.messages.len(),
            message.role
        );

        let assessment = state
            .security_client
            .assess_content(&message.content, &request.model, true)
            .await?;

        if !assessment.is_safe {
            let blocked_message = format_security_violation_message(&assessment);

            let response = ChatResponse {
                model: request.model.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                message: Message {
                    role: "assistant".to_string(),
                    content: blocked_message,
                },
                done: true,
            };

            return Ok(Err(build_violation_response(response)?));
        }
    }

    Ok(Ok(()))
}

// Handles non-streaming chat requests.
//
// This function:
// 1. Forwards the request to Ollama
// 2. Performs security assessment on the response
// 3. Returns the response or a security violation message
//
// # Arguments
//
// * `State(state)` - Application state containing client connections
// * `Json(request)` - The chat completion request from the client
//
// # Returns
//
// * `Ok(Response)` - The processed chat response
// * `Err(ApiError)` - If an error occurs during processing
async fn handle_non_streaming_chat(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Response, ApiError> {
    // Forward request to Ollama
    let response = state.ollama_client.forward("/api/chat", &request).await?;
    let body_bytes = response.bytes().await.map_err(|e| {
        error!("Failed to read response body: {}", e);
        ApiError::InternalError("Failed to read response body".to_string())
    })?;

    // Parse response
    let mut response_body: ChatResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
        error!("Failed to parse response: {}", e);
        ApiError::InternalError("Failed to parse response".to_string())
    })?;

    debug!("Received response from Ollama, performing security assessment");

    // Extract and log performance metrics if available
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        log_llm_metrics(&json, false);
    }

    // Security assessment on response content
    let assessment = state
        .security_client
        .assess_content(&response_body.message.content, &request.model, false)
        .await?;

    if !assessment.is_safe {
        // Replace content with security violation message
        response_body.message.content = format_security_violation_message(&assessment);

        return build_violation_response(response_body);
    }

    info!("Chat response passed security checks, returning to client");
    Ok(build_json_response(body_bytes)?)
}

// Handles streaming chat requests using the generic streaming handler.
//
// Sets up a streaming request to Ollama and wraps the response stream
// with security assessment capabilities.
//
// # Arguments
//
// * `State(state)` - Application state containing client connections
// * `Json(request)` - The chat completion request from the client
//
// # Returns
//
// * `Ok(Response)` - The streaming response
// * `Err(ApiError)` - If an error occurs during processing
async fn handle_streaming_chat(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Response, ApiError> {
    debug!("Processing streaming chat request");

    let model = request.model.clone();
    // For streaming chat, we're dealing with responses from the LLM, so is_prompt should be false
    handle_streaming_request::<ChatRequest, ChatResponse>(
        &state,
        request,
        "/api/chat",
        &model,
        false,
    )
    .await
}
