// panw-api-ollama: A secure proxy for Ollama API with PANW AI security integration
//
// This service wraps the Ollama API and provides content security scanning using
// Palo Alto Networks' AI Runtime API before forwarding requests to Ollama.
//
// # Overview
//
// This application serves as a security proxy for the Ollama API, scanning both
// prompts sent to language models and responses from them for security threats,
// policy violations, and potentially harmful content using Palo Alto Networks'
// AI Runtime security services.
//
// # Architecture
//
// - Configuration: Loaded from a YAML file at startup
// - Security: Integration with PANW AI Runtime API
// - Proxying: Transparent forwarding to Ollama API
// - Handlers: Endpoint-specific request processors
// - Streaming: Support for both streaming and non-streaming responses

//------------------------------------------------------------------------------
// Module declarations
//------------------------------------------------------------------------------

// Configuration loading and management.
mod config;
// HTTP request handlers for API endpoints.
mod handlers;
// Client for interacting with Ollama API services.
mod ollama;
// Security assessment and content filtering using PANW AI Runtime API.
mod security;
// Utilities for handling streaming responses.
mod stream;
// Common type definitions used throughout the application.
mod types;

//------------------------------------------------------------------------------
// Import declarations
//------------------------------------------------------------------------------

// Internal crate imports
use crate::handlers::*;
use crate::ollama::OllamaClient;
use crate::security::SecurityClient;

// Web framework imports
use axum::{
    routing::{get, post},
    Router,
};

// Standard library imports
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

// Middleware and utility imports
use tower_http::trace::TraceLayer;
use tracing::{error, info};

//------------------------------------------------------------------------------
// Application State
//------------------------------------------------------------------------------

// Shared application state containing clients for external services.
//
// This state is cloned and passed to each request handler, providing
// access to the Ollama client and security assessment functionality.
#[derive(Clone)]
pub struct AppState {
    // Client for communicating with Ollama API
    pub(crate) ollama_client: OllamaClient,
    // Client for performing security assessments
    pub(crate) security_client: SecurityClient,
}

impl AppState {
    // Creates a new builder for constructing AppState with a fluent API.
    pub fn builder() -> AppStateBuilder {
        AppStateBuilder::default()
    }
}

// Builder for creating AppState instances with a fluent API.
//
// This builder follows the builder pattern to provide a clean interface
// for initializing the application state with required components.
#[derive(Default)]
pub struct AppStateBuilder {
    // Optional Ollama client to be set before building
    ollama_client: Option<OllamaClient>,
    // Optional security client to be set before building
    security_client: Option<SecurityClient>,
}

impl AppStateBuilder {
    // Sets the Ollama client for the application state.
    pub fn with_ollama_client(mut self, client: OllamaClient) -> Self {
        self.ollama_client = Some(client);
        self
    }

    // Sets the security client for the application state.
    pub fn with_security_client(mut self, client: SecurityClient) -> Self {
        self.security_client = Some(client);
        self
    }

    // Builds the AppState from the configured components.
    //
    // # Errors
    //
    // Returns an error if any required component is missing.
    pub fn build(self) -> Result<AppState, &'static str> {
        let ollama_client = self.ollama_client.ok_or("OllamaClient is required")?;
        let security_client = self.security_client.ok_or("SecurityClient is required")?;

        Ok(AppState {
            ollama_client,
            security_client,
        })
    }
}

//------------------------------------------------------------------------------
// Application Entry Point
//------------------------------------------------------------------------------

// Application entry point that initializes and runs the server.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = config::load_config("config.yaml")?;

    // Initialize logging
    setup_logging(&config.server.debug_level);

    // Create application state
    let state = build_app_state(&config)?;
    info!("Application state initialized successfully");

    // Build router with all the Ollama API endpoints
    let app = build_router(state);
    info!("Router configured with all endpoints");

    // Start the server
    info!("Starting server with configuration: {:?}", config.server);
    start_server(app, &config.server).await?;

    Ok(())
}

//------------------------------------------------------------------------------
// Helper Functions
//------------------------------------------------------------------------------

/// Sets up logging with the configured level.
///
/// Initializes the tracing subscriber with the appropriate log level
/// based on the configuration setting.
///
/// # Arguments
///
/// * `debug_level_str` - The string representation of the desired log level
fn setup_logging(debug_level_str: &str) {
    let debug_level = tracing::Level::from_str(debug_level_str).unwrap_or_else(|_| {
        error!(
            "Unknown debug level: {}, defaulting to ERROR",
            debug_level_str
        );
        tracing::Level::ERROR
    });

    tracing_subscriber::fmt()
        .with_max_level(debug_level)
        .with_target(true) // Include module path in logs
        .with_thread_ids(true) // Include thread IDs for concurrent diagnostics
        .init();

    info!(
        "Starting panw-api-ollama server with log level: {}",
        debug_level
    );
}

/// Builds the application state with configured clients.
///
/// Creates and initializes the application state containing clients
/// for Ollama API and PANW security services.
///
/// # Arguments
///
/// * `config` - The application configuration
///
/// # Returns
///
/// * `Ok(AppState)` - Initialized application state
/// * `Err` - If client creation or initialization fails
fn build_app_state(config: &config::Config) -> Result<AppState, Box<dyn std::error::Error>> {
    info!("Building application state with configured clients");

    // Create Ollama client
    let ollama_client = OllamaClient::new(&config.ollama.base_url);
    info!(
        "Created Ollama client with base URL: {}",
        config.ollama.base_url
    );

    // Create security client
    let security_client = SecurityClient::new(&config.security);

    info!(
        "Created security client with base URL: {}",
        config.security.base_url
    );

    // Build the application state using the builder pattern
    let state = AppState::builder()
        .with_ollama_client(ollama_client)
        .with_security_client(security_client)
        .build()?;

    Ok(state)
}

/// Builds the router with all API endpoints.
///
/// Creates an Axum router with all the API endpoints and middleware.
///
/// # Arguments
///
/// * `state` - The application state to be shared with handlers
///
/// # Returns
///
/// An Axum router configured with all endpoints
fn build_router(state: AppState) -> Router {
    info!("Building API router with all endpoints");

    // Group endpoints by functionality
    let generation_routes = Router::new()
        .route("/api/generate", post(generate::handle_generate))
        .route("/api/chat", post(chat::handle_chat))
        .route("/api/embeddings", post(embeddings::handle_embeddings));

    let model_routes = Router::new()
        .route("/api/tags", get(models::handle_list_models))
        .route("/api/show", post(models::handle_show_model))
        .route("/api/create", post(models::handle_create_model))
        .route("/api/copy", post(models::handle_copy_model))
        .route("/api/delete", post(models::handle_delete_model))
        .route("/api/pull", post(models::handle_pull_model))
        .route("/api/push", post(models::handle_push_model));

    let utility_routes = Router::new().route("/api/version", get(version::handle_version));

    // Combine all routes
    let app = Router::new()
        .merge(generation_routes)
        .merge(model_routes)
        .merge(utility_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    app
}

/// Starts the HTTP server with the configured router.
///
/// Binds to the configured address and port and starts serving requests.
///
/// # Arguments
///
/// * `app` - The configured Axum router
/// * `server_config` - Server configuration settings
///
/// # Returns
///
/// * `Ok(())` - If the server starts and runs successfully
/// * `Err` - If binding fails or the server encounters an error
async fn start_server(
    app: Router,
    server_config: &config::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::new(IpAddr::from_str(&server_config.host)?, server_config.port);

    info!("Binding server to {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Server started successfully on {}", addr);

    info!("Waiting for incoming connections...");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
