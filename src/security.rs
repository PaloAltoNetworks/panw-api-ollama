// Security assessment and content filtering using PANW AI Runtime API.
//
// This module provides integration with Palo Alto Networks' AI Runtime security API
// to assess and filter content for security threats and policy violations.
//
// # Overview
//
// The security module implements:
// - Content assessment for both prompts and responses
// - Code block extraction and analysis
// - Integration with PANW AI Runtime security services
// - Policy-based content filtering
//
// # Usage
//
// ```rust
// let security_client = SecurityClient::new(
//     "https://api.paloaltonetworks.com",
//     "your-api-key",
//     "default-profile",
//     "my-app",
//     "user-123"
// );
//
// let assessment = security_client.assess_content(
//     "Content to analyze",
//     "llama3",
//     true
// ).await?;
//
// if !assessment.is_safe {
//     // Handle unsafe content
// }
// ```
use crate::{
    config::SecurityConfig,
    types::{AiProfile, Content, Metadata, ScanRequest, ScanResponse},
};
use reqwest::Client;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Represents errors that can occur during security assessments with the PANW AI Runtime API.
//
// This enum covers various failure modes when assessing content security using Palo Alto Networks'
// AI Runtime security services, including network failures, API errors, and content policy violations.
#[derive(Debug, Error)]
pub enum SecurityError {
    // Network or HTTP protocol errors
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    // Bad Request - Request data is invalid or malformed
    #[error("Bad Request - {0}")]
    BadRequest(String),

    // Authentication failed
    #[error("Authentication failed - Not authenticated")]
    Unauthenticated,

    // Invalid API Key or insufficient permissions
    #[error("Forbidden - Invalid API key or insufficient permissions")]
    Forbidden,

    // Requested resource not found
    #[error("Not Found - Resource not found")]
    NotFound,

    // HTTP method not allowed for this endpoint
    #[error("Method Not Allowed - The method is not allowed for this endpoint")]
    MethodNotAllowed,

    // Request payload too large
    #[error("Request Too Large - The request payload exceeds size limits")]
    RequestTooLarge,

    // Unsupported content type
    #[error("Unsupported Media Type - The content type is not supported")]
    UnsupportedMediaType,

    // Rate limit exceeded
    #[error("Too Many Requests - Rate limit exceeded. Retry after {0} {1}")]
    TooManyRequests(u32, String), // retry interval and unit (e.g., "5", "minute")

    // JSON parsing errors when handling API responses
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    // Content that has been blocked by security policy
    #[error("Content blocked by PANW AI security policy: {0}")]
    BlockedContent(String),

    // Generic assessment error for other cases
    #[error("PANW security assessment error: {0}")]
    AssessmentError(String),
}

// Represents the result of a security assessment from PANW AI Runtime API.
//
// This struct contains the outcome of evaluating content against Palo Alto Networks' security policies,
// including categorization of potential threats and recommended actions.
#[derive(Debug, Clone)]
pub struct Assessment {
    // Whether the assessed content is considered safe
    pub is_safe: bool,

    // Security category assigned to the content (e.g., "benign", "malicious")
    pub category: String,

    // Recommended action to take ("allow", "block", etc.)
    pub action: String,

    // The final content to use (original or masked version)
    pub final_content: String,

    // Whether the final_content is a masked version
    pub is_masked: bool,

    // Complete findings from the PANW AI security scan
    pub details: ScanResponse,
}

// Client for performing security assessments using the PANW AI Runtime API.
//
// This client connects to Palo Alto Networks' AI Runtime security API to evaluate prompts and responses
// for potential security threats, malicious content, or policy violations.
#[derive(Clone)]
pub struct SecurityClient {
    // HTTP client for making API requests
    client: Client,

    // Base URL for the PANW API service
    base_url: String,

    // API key for authenticating with PANW services
    api_key: String,

    // Security profile name to use for assessments
    profile_name: String,

    // Application name for telemetry and audit
    app_name: String,

    // Application user identifier
    app_user: String,

    // IP address of the end user (optional)
    user_ip: Option<String>,

    // Default context for grounding LLM responses. When not empty, grounding is enabled
    contextual_grounding_context: String,
}

impl Content {
    // Creates a new Content builder for constructing Content with a fluent API.
    pub fn builder() -> ContentBuilder {
        ContentBuilder::default()
    }

    // Creates a new Content object containing either a prompt or a response or both.
    //
    // # Arguments
    //
    // * `prompt` - Optional text representing a prompt to an AI model
    // * `response` - Optional text representing a response from an AI model
    // * `code_prompt` - Extracted code from prompt
    // * `code_response` - Extracted code from response
    // * `context` - Contextual grounding information
    //
    // # Returns
    //
    // * `Ok(Self)` - A valid Content object with at least one field populated
    // * `Err` - An error if all fields are None
    pub fn new(
        prompt: Option<String>,
        response: Option<String>,
        code_prompt: Option<String>,
        code_response: Option<String>,
        context: Option<String>,
    ) -> Result<Self, &'static str> {
        if prompt.is_none()
            && response.is_none()
            && code_prompt.is_none()
            && code_response.is_none()
        {
            return Err("Content must have at least one field populated");
        }
        Ok(Self {
            prompt,
            response,
            code_prompt,
            code_response,
            context,
        })
    }
}

// Builder for creating Content instances with a fluent API.
#[derive(Default)]
pub struct ContentBuilder {
    prompt: Option<String>,
    response: Option<String>,
    code_prompt: Option<String>,
    code_response: Option<String>,
    context: Option<String>,
}

impl ContentBuilder {
    // Sets the prompt text.
    pub fn with_prompt(mut self, prompt: String) -> Self {
        self.prompt = Some(prompt);
        self
    }

    // Sets the response text.
    pub fn with_response(mut self, response: String) -> Self {
        self.response = Some(response);
        self
    }

    // Sets the code extracted from the prompt.
    pub fn with_code_prompt(mut self, code: String) -> Self {
        self.code_prompt = Some(code);
        self
    }

    // Sets the code extracted from the response.
    pub fn with_code_response(mut self, code: String) -> Self {
        self.code_response = Some(code);
        self
    }

    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }

    // Builds the Content from the configured components.
    //
    // # Errors
    //
    // Returns an error if no fields were populated.
    pub fn build(self) -> Result<Content, &'static str> {
        Content::new(
            self.prompt,
            self.response,
            self.code_prompt,
            self.code_response,
            self.context,
        )
    }
}

impl SecurityClient {
    //--------------------------------------------------------------------------
    // Construction and Initialization
    //--------------------------------------------------------------------------

    // Creates a new instance of the SecurityClient for performing content security assessments.
    //
    // # Arguments
    //
    // * `base_url` - The base URL of the PANW AI Runtime security API endpoint
    // * `api_key` - Palo Alto Networks API token for accessing the security services
    // * `profile_name` - Name of the AI security profile to use for assessments
    // * `app_name` - Name of the application using this security client
    // * `app_user` - Identifier for the user or context within the application
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            client: Client::new(),
            base_url: config.base_url,
            api_key: config.api_key,
            profile_name: config.profile_name,
            app_name: config.app_name,
            app_user: config.app_user,
            contextual_grounding_context: config.contextual_grounding,
            user_ip: None,
        }
    }

    //--------------------------------------------------------------------------
    // Public API Methods
    //--------------------------------------------------------------------------

    /// Returns the base URL of the security service
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Sets the user IP address for subsequent security assessments
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address of the end user making the request
    pub fn with_user_ip(&mut self, ip: impl Into<String>) -> &mut Self {
        self.user_ip = Some(ip.into());
        self
    }

    // Performs a security assessment on the provided content using PANW AI Runtime API.
    //
    // # Arguments
    //
    // * `content` - The text content to assess with PANW AI Runtime API
    // * `model_name` - Name of the AI model associated with this content
    // * `is_prompt` - If `true`, content is treated as a prompt to an AI; if `false`, as an AI response
    //
    // # Returns
    //
    // Security assessment results
    //
    // # Errors
    //
    // Returns error if assessment fails or content is blocked by security policy
    pub async fn assess_content(
        &self,
        content: &str,
        model_name: &str,
        is_prompt: bool,
    ) -> Result<Assessment, SecurityError> {
        let start_time = Instant::now();

        // Optimization: Skip assessment for empty content
        if content.trim().is_empty() {
            debug!("Skipping PANW assessment for empty content");
            return Ok(self.create_safe_assessment());
        }

        // Prepare content for assessment
        let content_obj = self.prepare_content(content, is_prompt)?;
        debug!("Prepared content for PANW assessment: {:#?}", content_obj);

        // Create and send the request payload
        let payload = self.create_scan_request(content_obj, model_name);
        let scan_result = self.send_security_request(&payload).await?;

        // Process results
        let result = self.process_scan_result(scan_result);

        let elapsed_time = start_time.elapsed();
        let content_type = if is_prompt { "prompt" } else { "response" };

        match &result {
            Ok(assessment) => {
                if assessment.is_safe {
                    if assessment.is_masked {
                        info!(
                            "Security assessment completed in {} ms - {} allowed with masked content: category={}",
                            elapsed_time.as_millis(),
                            content_type,
                            assessment.category
                        );
                    } else {
                        info!(
                            "Security assessment completed in {} ms - {} allowed without masking: category={}",
                            elapsed_time.as_millis(),
                            content_type,
                            assessment.category
                        );
                    }
                } else {
                    warn!(
                        "Security assessment completed in {} ms - {} blocked: category={}, action={}",
                        elapsed_time.as_millis(), content_type, assessment.category, assessment.action
                    );
                }
            }
            Err(e) => {
                error!(
                    "Security assessment failed in {} ms - error: {}",
                    elapsed_time.as_millis(),
                    e
                );
            }
        }

        result
    }

    // Performs a security assessment that includes both text and code content.
    //
    // # Arguments
    //
    // * `text_content` - The regular text content to assess
    // * `code_content` - The code block content to assess
    // * `model_name` - Name of the AI model associated with this content
    // * `is_prompt` - If `true`, content is treated as a prompt to an AI; if `false`, as an AI response
    //
    // # Returns
    //
    // Security assessment results
    //
    // # Errors
    //
    // Returns error if assessment fails or content is blocked by security policy
    pub async fn assess_content_with_code(
        &self,
        text_content: &str,
        code_content: &str,
        model_name: &str,
        is_prompt: bool,
    ) -> Result<Assessment, SecurityError> {
        let start_time = Instant::now();

        // Skip assessment for empty content
        if text_content.trim().is_empty() && code_content.trim().is_empty() {
            debug!("Skipping PANW assessment for empty text and code content");
            return Ok(self.create_safe_assessment());
        }

        // Create Content object directly without extracting code blocks
        let content_obj = if is_prompt {
            Content::builder()
                .with_prompt(text_content.to_string())
                .with_code_prompt(code_content.to_string())
                .build()
                .map_err(|e| SecurityError::AssessmentError(e.to_string()))?
        } else {
            Content::builder()
                .with_response(text_content.to_string())
                .with_code_response(code_content.to_string())
                .build()
                .map_err(|e| SecurityError::AssessmentError(e.to_string()))?
        };

        // Create and send the request payload
        let payload = self.create_scan_request(content_obj, model_name);
        let scan_result = self.send_security_request(&payload).await?;

        // Process results
        let result = self.process_scan_result(scan_result);

        let elapsed_time = start_time.elapsed();
        let content_type = if is_prompt { "prompt" } else { "response" };

        match &result {
            Ok(assessment) => {
                if assessment.is_safe {
                    info!(
                        "Security assessment with code completed in {} ms - {} passed security assessment",
                        elapsed_time.as_millis(), content_type
                    );
                } else {
                    warn!(
                        "Security assessment with code completed in {} ms - {} failed security assessment: category={}, action={}",
                        elapsed_time.as_millis(), content_type, assessment.category, assessment.action
                    );
                }
            }
            Err(e) => {
                error!(
                    "Security assessment with code failed in {} ms - error: {}",
                    elapsed_time.as_millis(),
                    e
                );
            }
        }

        result
    }

    //--------------------------------------------------------------------------
    // Content Processing Methods
    //--------------------------------------------------------------------------

    // Creates a default safe assessment for empty content.
    //
    // This is an optimization to avoid unnecessary API calls for empty content.
    fn create_safe_assessment(&self) -> Assessment {
        Assessment {
            is_safe: true,
            category: "benign".to_owned(),
            action: "allow".to_owned(),
            final_content: String::new(),
            is_masked: false,
            details: ScanResponse::default_safe_response(),
        }
    }

    // Extracts code blocks from text using Markdown code block syntax.
    //
    // This function parses the input text and extracts all content between
    // triple backtick (```) markers, which is the standard Markdown syntax
    // for code blocks.
    //
    // # Arguments
    //
    // * `content` - The text content to extract code blocks from
    //
    // # Returns
    //
    // A string containing all extracted code blocks concatenated together
    fn extract_code_blocks(&self, content: &str) -> String {
        let mut code_content = String::new();
        let mut in_code_block = false;
        let mut buffer = String::new();
        let mut language_marker = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // Check for code block delimiter
            if trimmed.starts_with("```") {
                if in_code_block {
                    // End of code block - add collected content to result
                    code_content.push_str(&buffer);
                    code_content.push('\n');
                    buffer.clear();
                    in_code_block = false;
                } else {
                    // Start of code block
                    in_code_block = true;
                    // If there's content after the ``` it's a language specifier, skip this line
                    language_marker = trimmed.len() > 3;
                }
            } else if in_code_block {
                // Skip the first line if it was just a language marker
                if language_marker {
                    language_marker = false;
                    continue;
                }

                // Inside a code block - collect content
                buffer.push_str(line);
                buffer.push('\n');
            }
        }

        // Handle case where the content ends with an unclosed code block
        if in_code_block && !buffer.is_empty() {
            code_content.push_str(&buffer);
            code_content.push('\n');
        }

        code_content
    }

    // Prepares a Content object for PANW assessment based on the provided text.
    //
    // # Arguments
    //
    // * `content` - The text content to be assessed
    // * `is_prompt` - If true, content is treated as a prompt; otherwise as a response
    //
    // # Returns
    //
    // Structured Content object ready for assessment
    fn prepare_content(&self, content: &str, is_prompt: bool) -> Result<Content, SecurityError> {
        // Extract any code blocks
        let code_blocks = self.extract_code_blocks(content);
        let has_code = !code_blocks.is_empty();

        // Remove code blocks from the main content to avoid duplication
        let text_content = if has_code {
            self.remove_code_blocks(content)
        } else {
            content.to_string()
        };

        // Use the builder pattern for creating content objects
        let builder = Content::builder();

        let content_builder = {
            let mut builder = if is_prompt {
                let mut b = builder.with_prompt(text_content);
                if has_code {
                    b = b.with_code_prompt(code_blocks);
                }
                b
            } else {
                let mut b = builder.with_response(text_content);
                if has_code {
                    b = b.with_code_response(code_blocks);
                }
                b
            };

            if !self.contextual_grounding_context.is_empty() {
                builder = builder.with_context(self.contextual_grounding_context.clone());
            }
            builder
        };

        content_builder
            .build()
            .map_err(|e| SecurityError::AssessmentError(e.to_string()))
    }

    // Removes code blocks from text, keeping only non-code content
    //
    // This function removes all content between triple backtick (```) markers
    // along with the markers themselves, returning only the non-code text.
    //
    // # Arguments
    //
    // * `content` - The text content to process
    //
    // # Returns
    //
    // A string with code blocks removed
    fn remove_code_blocks(&self, content: &str) -> String {
        let mut result = String::new();
        let mut in_code_block = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // Check for code block delimiter
            if trimmed.starts_with("```") {
                in_code_block = !in_code_block;
                // Don't add the delimiter line to the result
                continue;
            }

            // Only add lines that are not inside code blocks
            if !in_code_block {
                result.push_str(line);
                result.push('\n');
            }
        }

        result
    }

    // Processes scan results from the PANW AI Runtime API into an Assessment.
    //
    // # Arguments
    //
    // * `scan_result` - The scan response from the PANW AI Runtime API
    //
    // # Returns
    //
    // Assessment object with security evaluation results
    fn process_scan_result(&self, scan_result: ScanResponse) -> Result<Assessment, SecurityError> {
        // Content is considered safe unless explicitly blocked
        let is_safe = scan_result.action != "block";

        // Determine if we have masked content to use - only apply masking for non-blocked content
        let (final_content, is_masked) = if is_safe {
            if scan_result.prompt_detected.dlp && !scan_result.prompt_masked_data.data.is_empty() {
                // Use masked prompt content
                (scan_result.prompt_masked_data.data.clone(), true)
            } else if scan_result.response_detected.dlp
                && !scan_result.response_masked_data.data.is_empty()
            {
                // Use masked response content
                (scan_result.response_masked_data.data.clone(), true)
            } else {
                // Not masked, don't provide final_content as we'll keep using the original content
                (String::new(), false)
            }
        } else {
            // For blocked content, don't provide final_content
            (String::new(), false)
        };

        let assessment = Assessment {
            is_safe,
            category: scan_result.category.clone(),
            action: scan_result.action.clone(),
            final_content,
            is_masked,
            details: scan_result,
        };

        Ok(assessment)
    }

    //--------------------------------------------------------------------------
    // API Request Methods
    //--------------------------------------------------------------------------

    // Creates a scan request payload for the PANW AI Runtime API.
    //
    // # Arguments
    //
    // * `content_obj` - Content object containing text to assess
    // * `model_name` - Name of the AI model associated with this content
    fn create_scan_request(&self, content_obj: Content, model_name: &str) -> ScanRequest {
        ScanRequest {
            tr_id: Uuid::new_v4().to_string(),
            ai_profile: AiProfile {
                profile_name: self.profile_name.clone(),
            },
            metadata: Metadata {
                app_name: self.app_name.to_string(),
                app_user: self.app_user.to_string(),
                ai_model: model_name.to_string(),
                user_ip: self.user_ip.clone(),
            },
            contents: vec![content_obj],
        }
    }

    // Sends a security assessment request to the PANW AI Runtime API and processes the response.
    //
    // # Arguments
    //
    // * `payload` - The request payload to send
    //
    // # Returns
    //
    // Parsed scan response from the API
    async fn send_security_request(
        &self,
        payload: &ScanRequest,
    ) -> Result<ScanResponse, SecurityError> {
        let (status, body_text) = self.make_api_request(payload).await?;
        self.parse_api_response(status, body_text)
    }

    // Makes an HTTP request to the PANW AI Runtime API.
    //
    // # Arguments
    //
    // * `payload` - The request payload to send
    //
    // # Returns
    //
    // Status code and response body from the API
    async fn make_api_request(
        &self,
        payload: &ScanRequest,
    ) -> Result<(reqwest::StatusCode, String), SecurityError> {
        let endpoint = format!("{}/v1/scan/sync/request", self.base_url);
        debug!("Sending security assessment request to: {}", endpoint);

        let response = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("x-pan-token", &self.api_key)
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                error!("PANW security assessment request failed: {}", e);
                SecurityError::RequestError(e)
            })?;

        let status = response.status();
        let body_text = response.text().await.map_err(|e| {
            error!("Failed to read PANW response body: {}", e);
            SecurityError::RequestError(e)
        })?;

        Ok((status, body_text))
    }

    // Parses the PANW AI Runtime API response and handles different status codes.
    //
    // # Arguments
    //
    // * `status` - The HTTP status code from the API response
    // * `body_text` - The raw response body text
    //
    // # Returns
    //
    // Parsed scan response object
    fn parse_api_response(
        &self,
        status: reqwest::StatusCode,
        body_text: String,
    ) -> Result<ScanResponse, SecurityError> {
        // Log the raw response in debug mode
        debug!("PANW API response status: {}", status);
        debug!("Raw PANW response body:\n{}", body_text);

        // Handle error status codes based on OpenAPI specification
        if !status.is_success() {
            error!("PANW security assessment error: {} - {}", status, body_text);

            // Parse error response if possible
            let error_details = match serde_json::from_str::<serde_json::Value>(&body_text) {
                Ok(v) => v
                    .pointer("/error/message")
                    .and_then(|m| m.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| body_text.clone()),
                Err(_) => body_text.clone(),
            };

            return match status.as_u16() {
                400 => Err(SecurityError::BadRequest(error_details)),
                401 => Err(SecurityError::Unauthenticated),
                403 => Err(SecurityError::Forbidden),
                404 => Err(SecurityError::NotFound),
                405 => Err(SecurityError::MethodNotAllowed),
                413 => Err(SecurityError::RequestTooLarge),
                415 => Err(SecurityError::UnsupportedMediaType),
                429 => {
                    // Try to parse retry information
                    let retry_after = serde_json::from_str::<serde_json::Value>(&body_text)
                        .ok()
                        .and_then(|v| {
                            v.pointer("/error/retry_after").and_then(|r| {
                                let interval = r.get("interval")?.as_u64()? as u32;
                                let unit = r.get("unit")?.as_str()?;
                                Some((interval, unit.to_string()))
                            })
                        });

                    if let Some((interval, unit)) = retry_after {
                        Err(SecurityError::TooManyRequests(interval, unit))
                    } else {
                        Err(SecurityError::TooManyRequests(60, "second".to_string()))
                        // Default retry after 60 seconds if not specified
                    }
                }
                _ => Err(SecurityError::AssessmentError(format!(
                    "Status {}: {}",
                    status, error_details
                ))),
            };
        }

        // Parse JSON response
        serde_json::from_str(&body_text).map_err(|e| {
            error!("Failed to parse PANW security assessment response: {}", e);
            SecurityError::JsonError(e)
        })
    }
}
