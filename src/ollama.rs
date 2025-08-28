// Client for interacting with Ollama API services.
//
// This module provides a client for communicating with Ollama's API endpoints,
// supporting both regular request/response patterns and streaming responses.
//
// # Overview
//
// The OllamaClient abstracts communication with Ollama API:
// - Forwards requests to appropriate Ollama endpoints
// - Handles both streaming and non-streaming responses
// - Processes and transforms API errors into structured types
// - Manages HTTP connection details
use bytes::Bytes;
use futures_util::Stream;
use reqwest::{Client, Response, StatusCode};
use serde::Serialize;
use thiserror::Error;
use tracing::{debug, error};

// Errors that can occur when interacting with the Ollama API.
//
// This enum represents various failure modes when communicating with
// Ollama services, including network issues and API-level errors.
#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum OllamaError {
    // HTTP request errors (connection failures, timeouts, etc.)
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    // API-level errors returned by the Ollama service
    #[error("Ollama API error: {status} - {message}")]
    ApiError {
        // HTTP status code returned by the API
        status: StatusCode,
        // Error message provided by the API
        message: String,
    },

    // Configuration or initialization errors
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

// Client for interacting with the Ollama API.
//
// This client provides methods for sending requests to Ollama endpoints
// and handles the transformation of responses into appropriate formats.
#[derive(Clone)]
pub struct OllamaClient {
    // HTTP client for making API requests
    client: Client,

    // Base URL for the Ollama API service
    base_url: String,
}

impl OllamaClient {
    //--------------------------------------------------------------------------
    // Construction and Initialization
    //--------------------------------------------------------------------------

    // Creates a new Ollama API client.
    //
    // # Arguments
    //
    // * `base_url` - The base URL of the Ollama API service (e.g., "http://localhost:11434")
    //
    // # Example
    //
    // ```
    // let client = OllamaClient::new("http://localhost:11434");
    // ```
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    //--------------------------------------------------------------------------
    // Public API Methods
    //--------------------------------------------------------------------------

    // Forwards a POST request to the specified Ollama API endpoint.
    //
    // # Arguments
    //
    // * `endpoint` - The API endpoint to call (e.g., "/api/chat")
    // * `body` - The request body to send, automatically serialized to JSON
    //
    // # Returns
    //
    // The raw HTTP response from the Ollama API if successful
    //
    // # Errors
    //
    // Returns an error if the request fails or the API returns an error status
    pub async fn forward<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<Response, OllamaError> {
        self.forward_request(endpoint, |url| self.client.post(url).json(body))
            .await
    }

    // Forwards a GET request to the specified Ollama API endpoint.
    //
    // # Arguments
    //
    // * `endpoint` - The API endpoint to call (e.g., "/api/tags")
    //
    // # Returns
    //
    // The raw HTTP response from the Ollama API if successful
    //
    // # Errors
    //
    // Returns an error if the request fails or the API returns an error status
    pub async fn forward_get(&self, endpoint: &str) -> Result<Response, OllamaError> {
        self.forward_request(endpoint, |url| self.client.get(url))
            .await
    }

    // Sets up a streaming request to the specified Ollama API endpoint.
    //
    // This method is used for endpoints that support server-sent events or
    // other streaming response formats.
    //
    // # Arguments
    //
    // * `endpoint` - The API endpoint to call (e.g., "/api/chat")
    // * `body` - The request body to send, automatically serialized to JSON
    //
    // # Returns
    //
    // A stream of bytes from the API response
    //
    // # Errors
    //
    // Returns an error if the request fails or the API returns an error status
    pub async fn stream<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<impl Stream<Item = Result<Bytes, reqwest::Error>>, OllamaError> {
        let response = self
            .forward_request(endpoint, |url| self.client.post(url).json(body))
            .await?;
        Ok(response.bytes_stream())
    }

    //--------------------------------------------------------------------------
    // Helper Methods
    //--------------------------------------------------------------------------

    // Generic method to handle both GET and POST requests, reducing code duplication.
    //
    // # Arguments
    //
    // * `endpoint` - The API endpoint to call
    // * `request_builder` - A function that configures the request
    //
    // # Returns
    //
    // The raw HTTP response if successful
    //
    // # Errors
    //
    // Returns an error if the request fails or the API returns an error status
    async fn forward_request<F>(
        &self,
        endpoint: &str,
        request_builder: F,
    ) -> Result<Response, OllamaError>
    where
        F: FnOnce(&str) -> reqwest::RequestBuilder,
    {
        let url = format!("{}{}", self.base_url, endpoint);
        debug!("Forwarding request to {}", url);

        let response = request_builder(&url).send().await.map_err(|e| {
            error!("Request to Ollama API failed: {}", e);
            OllamaError::RequestError(e)
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Ollama API error: {} - {}", status, message);
            return Err(OllamaError::ApiError { status, message });
        }

        debug!("Successfully received response from Ollama API");
        Ok(response)
    }
}
