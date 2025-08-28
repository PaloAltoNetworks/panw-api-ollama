use axum::{extract::State, http::Method, response::Response, Json};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    handlers::{utils::build_json_response, ApiError},
    AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ModelRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

#[derive(Debug)]
pub enum OllamaEndpoint {
    Tags,
    Show,
    Create,
    Copy,
    Delete,
    Pull,
    Push,
}

impl OllamaEndpoint {
    // Returns the API path for the endpoint.
    fn path(&self) -> &'static str {
        match self {
            Self::Tags => "/api/tags",
            Self::Show => "/api/show",
            Self::Create => "/api/create",
            Self::Copy => "/api/copy",
            Self::Delete => "/api/delete",
            Self::Pull => "/api/pull",
            Self::Push => "/api/push",
        }
    }

    // Returns the HTTP method for the endpoint.
    fn method(&self) -> Method {
        match self {
            Self::Tags => Method::GET,
            _ => Method::POST,
        }
    }

    // Returns the appropriate log message prefix for the endpoint.
    fn log_prefix(&self) -> &'static str {
        match self {
            Self::Tags => "Forwarding list models request",
            Self::Show => "Forwarding show model request for",
            Self::Create => "Forwarding create model request",
            Self::Copy => "Forwarding copy model request",
            Self::Delete => "Forwarding delete model request for",
            Self::Pull => "Forwarding pull model request for",
            Self::Push => "Forwarding push model request for",
        }
    }

    // Determines if this endpoint should include model name in logs.
    fn includes_model_name_in_logs(&self) -> bool {
        matches!(self, Self::Show | Self::Delete | Self::Pull | Self::Push)
    }
}

// Forwards a request to the Ollama service.
async fn forward_to_ollama<T: Serialize>(
    state: &AppState,
    endpoint: OllamaEndpoint,
    body: Option<&T>,
    model_name: Option<&str>,
) -> Result<Response, ApiError> {
    // Create log message
    let log_message = if endpoint.includes_model_name_in_logs() {
        if let Some(name) = model_name {
            format!("{}: {}", endpoint.log_prefix(), name)
        } else {
            endpoint.log_prefix().to_string()
        }
    } else {
        endpoint.log_prefix().to_string()
    };
    debug!("{}", log_message);

    // Forward the request
    let response = match endpoint.method() {
        Method::GET => state.ollama_client.forward_get(endpoint.path()).await?,
        Method::POST => {
            let body = body
                .ok_or_else(|| ApiError::InternalError("Body required for POST request".into()))?;
            state.ollama_client.forward(endpoint.path(), body).await?
        }
        _ => return Err(ApiError::InternalError("Unsupported HTTP method".into())),
    };

    // Process the response
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    build_json_response(body_bytes)
}

// Handler for listing models (GET /api/tags)
pub async fn handle_list_models(State(state): State<AppState>) -> Result<Response, ApiError> {
    forward_to_ollama::<()>(&state, OllamaEndpoint::Tags, None, None).await
}

// Handler for showing model details (POST /api/show)
pub async fn handle_show_model(
    State(state): State<AppState>,
    Json(request): Json<ModelRequest>,
) -> Result<Response, ApiError> {
    forward_to_ollama(
        &state,
        OllamaEndpoint::Show,
        Some(&request),
        Some(&request.name),
    )
    .await
}

// Handler for creating a model (POST /api/create)
pub async fn handle_create_model(
    State(state): State<AppState>,
    Json(request): Json<ModelRequest>,
) -> Result<Response, ApiError> {
    forward_to_ollama(&state, OllamaEndpoint::Create, Some(&request), None).await
}

// Handler for copying a model (POST /api/copy)
pub async fn handle_copy_model(
    State(state): State<AppState>,
    Json(request): Json<ModelRequest>,
) -> Result<Response, ApiError> {
    forward_to_ollama(&state, OllamaEndpoint::Copy, Some(&request), None).await
}

// Handler for deleting a model (POST /api/delete)
pub async fn handle_delete_model(
    State(state): State<AppState>,
    Json(request): Json<ModelRequest>,
) -> Result<Response, ApiError> {
    forward_to_ollama(
        &state,
        OllamaEndpoint::Delete,
        Some(&request),
        Some(&request.name),
    )
    .await
}

// Handler for pulling a model (POST /api/pull)
pub async fn handle_pull_model(
    State(state): State<AppState>,
    Json(request): Json<ModelRequest>,
) -> Result<Response, ApiError> {
    forward_to_ollama(
        &state,
        OllamaEndpoint::Pull,
        Some(&request),
        Some(&request.name),
    )
    .await
}

// Handler for pushing a model (POST /api/push)
pub async fn handle_push_model(
    State(state): State<AppState>,
    Json(request): Json<ModelRequest>,
) -> Result<Response, ApiError> {
    forward_to_ollama(
        &state,
        OllamaEndpoint::Push,
        Some(&request),
        Some(&request.name),
    )
    .await
}
