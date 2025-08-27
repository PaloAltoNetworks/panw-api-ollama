/// Common type definitions used throughout the application.
///
/// This module defines the core data structures for both the Ollama API
/// integration and the PANW AI Runtime security services. These types
/// represent request and response formats for various API endpoints.
///
/// # Type Categories
///
/// The types are organized into two main categories:
/// - Ollama API types (requests and responses for text generation, chat, etc.)
/// - PANW security types (content assessment requests and responses)
use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

//------------------------------------------------------------------------------
// Ollama API Types
//------------------------------------------------------------------------------

/// Request parameters for generating text with Ollama models.
///
/// This struct encapsulates all parameters needed to make a text generation request
/// to the Ollama API, including the model to use, prompt text, and various optional
/// configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateRequest {
    /// Name of the Ollama model to use for generation
    pub model: String,

    /// The text prompt to send to the model
    pub prompt: String,

    /// Optional system message to guide model behavior
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,

    /// Optional template to format the prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,

    /// Optional context tokens from previous interactions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<u32>>,

    /// Optional flag to enable streaming responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,

    /// Optional flag to get raw, unfiltered model output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<bool>,

    /// Optional output format specification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Optional model-specific parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

/// Response from an Ollama text generation request.
///
/// Contains the generated text and related metadata returned by the Ollama API
/// after processing a generation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateResponse {
    /// Name of the model that generated the response
    pub model: String,

    /// Timestamp when the response was created
    pub created_at: String,

    /// The generated text content
    pub response: String,

    /// Optional context tokens for continuing the conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<u32>>,

    /// Indicates whether the generation is complete
    pub done: bool,
}

/// Request parameters for chat-based interactions with Ollama models.
///
/// This struct encapsulates all parameters needed for a multi-turn conversation
/// with an Ollama model, using the chat completion API format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Name of the Ollama model to use
    pub model: String,

    /// Array of conversation messages with roles and content
    pub messages: Vec<Message>,

    /// Optional flag to enable streaming responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,

    /// Optional output format specification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Optional model-specific parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

/// Represents a single message in a chat conversation.
///
/// Each message has a role (who is speaking) and content (what is said).
/// Common roles include "system", "user", and "assistant".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Identifies the sender of the message (e.g., "user", "assistant")
    pub role: String,

    /// The actual text content of the message
    pub content: String,
}

/// Response from an Ollama chat request.
///
/// Contains the model's reply as a message and related metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    /// Name of the model that generated the response
    pub model: String,

    /// Timestamp when the response was created
    pub created_at: String,

    /// The model's response as a Message object
    pub message: Message,

    /// Indicates whether the generation is complete
    pub done: bool,
}

/// Request parameters for generating text embeddings with Ollama models.
///
/// Text embeddings are vector representations of text that capture semantic meaning,
/// useful for similarity comparisons, clustering, and other NLP tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    /// Name of the Ollama embedding model to use
    pub model: String,

    /// The text to generate embeddings for
    pub prompt: String,

    /// Optional model-specific parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

/// Response containing vector embeddings generated by an Ollama model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsResponse {
    /// Vector of floating-point values representing the text embedding
    pub embedding: Vec<f32>,
}

/// Response containing a list of available models from the Ollama API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListModelsResponse {
    /// Array of ModelInfo objects with details about each available model
    pub models: Vec<ModelInfo>,
}

/// Detailed information about a specific Ollama model.
///
/// Contains both basic metadata and detailed specifications about the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// The model's name/identifier
    pub name: String,

    /// Timestamp when the model was last modified
    pub modified_at: String,

    /// Size of the model in bytes
    pub size: u64,

    /// Unique hash identifying this version of the model
    pub digest: String,

    /// Additional technical specifications of the model
    pub details: ModelDetails,
}

/// Technical specifications of an Ollama model.
///
/// Contains details about the model's architecture, size, and quantization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDetails {
    /// Model format (e.g., "gguf")
    pub format: String,

    /// Model family/architecture (e.g., "llama")
    pub family: String,

    /// All compatible model families
    pub families: Vec<String>,

    /// Human-readable parameter count (e.g., "7B")
    pub parameter_size: String,

    /// Level of precision reduction applied (e.g., "Q4_0")
    pub quantization_level: String,
}

/// Response containing the Ollama API version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    /// Version string of the Ollama API
    pub version: String,
}

//------------------------------------------------------------------------------
// PANW Security Types
//------------------------------------------------------------------------------

/// Request payload for PANW AI Runtime security assessment.
///
/// This struct contains all data needed to request a security scan of AI content,
/// including the content to scan, profile information, and metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ScanRequest {
    /// Transaction ID for tracking the request
    pub tr_id: String,

    /// Configuration profile for the security assessment
    pub ai_profile: AiProfile,

    /// Additional context about the application and user
    pub metadata: Metadata,

    /// Array of content objects to be scanned
    pub contents: Vec<Content>,
}

/// Response from a PANW AI Runtime security assessment.
///
/// Contains the results of evaluating content against security policies,
/// including categorization and detected issues.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanResponse {
    /// Unique identifier for the assessment report
    #[serde(default)]
    pub report_id: String,

    /// UUID of this particular scan
    #[serde(default)]
    pub scan_id: uuid::Uuid,

    /// Optional transaction ID matching the request
    #[serde(default)]
    pub tr_id: Option<String>,

    /// Optional identifier of the security profile used
    #[serde(default)]
    pub profile_id: Option<String>,

    /// Optional name of the security profile used
    #[serde(default)]
    pub profile_name: Option<String>,

    /// Security category assigned (e.g., "benign", "malicious")
    pub category: String,

    /// Recommended action ("allow", "block", etc.)
    pub action: String,

    /// Security issues found in the prompt
    #[serde(default)]
    pub prompt_detected: PromptDetected,

    /// Security issues found in the response
    #[serde(default)]
    pub response_detected: ResponseDetected,

    /// Masked sensitive data found in the prompt
    #[serde(default)]
    pub prompt_masked_data: MaskedData,

    /// Masked sensitive data found in the response
    #[serde(default)]
    pub response_masked_data: MaskedData,

    /// Detailed threat detection information for the prompt
    #[serde(default)]
    pub prompt_detection_details: PromptDetectionDetails,

    /// Detailed threat detection information for the response
    #[serde(default)]
    pub response_detection_details: ResponseDetectionDetails,

    /// Optional timestamp when assessment was created
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,

    /// Optional timestamp when assessment was completed
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

impl ScanResponse {
    /// Creates a default safe response for use when assessment isn't needed.
    ///
    /// This implementation method creates a pre-populated ScanResponse object
    /// that indicates content is safe, used for empty content or other scenarios
    /// where a full API scan is unnecessary.
    ///
    /// # Returns
    ///
    /// A ScanResponse object with default safe values.
    pub fn default_safe_response() -> Self {
        Self {
            report_id: String::new(),
            scan_id: uuid::Uuid::default(),
            tr_id: None,
            profile_id: None,
            profile_name: None,
            category: "benign".to_string(),
            action: "allow".to_string(),
            prompt_detected: PromptDetected::default(),
            response_detected: ResponseDetected::default(),
            prompt_masked_data: MaskedData::default(),
            response_masked_data: MaskedData::default(),
            prompt_detection_details: PromptDetectionDetails::default(),
            response_detection_details: ResponseDetectionDetails::default(),
            created_at: None,
            completed_at: None,
        }
    }
}

/// AI security profile configuration for PANW security scans.
///
/// Specifies which security profile should be used when evaluating content.
#[derive(Debug, Clone, Serialize)]
pub struct AiProfile {
    /// Name of the security profile to apply
    pub profile_name: String,
}

/// Metadata providing context for PANW security assessments.
///
/// Contains information about the application, user, and AI model involved
/// in generating or processing the content being assessed.
#[derive(Debug, Clone, Serialize)]
pub struct Metadata {
    /// Name of the application requesting the assessment
    pub app_name: String,

    /// Identifier of the user in the context of the application
    pub app_user: String,

    /// Name of the AI model that generated or will process the content
    pub ai_model: String,

    /// IP address of the end user using the AI application
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_ip: Option<String>,
}

/// Content to be assessed by the PANW AI Runtime security API.
///
/// This struct represents a content object that contains prompt, response, code blocks
/// and context for the security assessment. All fields are optional according to the API spec.
#[derive(Debug, Clone, Serialize)]
pub struct Content {
    /// Text representing a prompt to a LLM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,

    /// Text representing a response from a LLM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,

    /// Code snippet extracted from Prompt content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_prompt: Option<String>,

    /// Code snippet extracted from Response content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_response: Option<String>,

    /// Context for grounding LLM responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Security issues detected in a prompt during PANW assessment.
///
/// This struct contains flags for various types of security concerns
/// that may be present in a prompt submitted to LLM.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PromptDetected {
    /// Whether problematic URL categories were detected
    #[serde(default)]
    pub url_cats: bool,

    /// Whether data loss prevention issues were detected
    #[serde(default)]
    pub dlp: bool,

    /// Whether prompt injection attempts were detected
    #[serde(default)]
    pub injection: bool,

    /// Whether toxic or harmful content was detected
    #[serde(default)]
    pub toxic_content: bool,

    /// Whether malicious code was detected
    #[serde(default)]
    pub malicious_code: bool,

    /// Whether prompt contains any Agent related threats
    #[serde(default)]
    pub agent: bool,

    /// Whether the prompt contains content that violates topic guardrails
    #[serde(default)]
    pub topic_violation: bool,
}

/// A struct representing the locations of detected patterns in masked data.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OffsetObject(pub Vec<Vec<i32>>);

/// Detection information for specific patterns in masked data.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatternDetections {
    /// The pattern that was matched
    pub pattern: String,
    /// The locations where the pattern was found
    pub locations: OffsetObject,
}

/// Represents masked sensitive data with detection information.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MaskedData {
    /// Original data with sensitive patterns masked
    pub data: String,
    /// Information about detected patterns
    pub pattern_detections: Vec<PatternDetections>,
}

/// Topic guardrail violation details.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TopicGuardRails {
    /// List of allowed topics that matched the content
    #[serde(default)]
    pub allowed_topics: Vec<String>,
    /// List of blocked topics that matched the content
    #[serde(default)]
    pub blocked_topics: Vec<String>,
}

/// Detailed information about prompt threat detections.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PromptDetectionDetails {
    /// Details about topic guardrail violations
    #[serde(default)]
    pub topic_guardrails_details: Option<TopicGuardRails>,
}

/// Detailed information about response threat detections.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResponseDetectionDetails {
    /// Details about topic guardrail violations
    #[serde(default)]
    pub topic_guardrails_details: Option<TopicGuardRails>,
}

/// Security issues detected in a response during PANW assessment.
///
/// This struct contains flags for various types of security concerns
/// that may be present in a response generated by a LLM.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResponseDetected {
    /// Whether problematic URL categories were detected
    #[serde(default)]
    pub url_cats: bool,

    /// Whether data loss prevention issues were detected
    #[serde(default)]
    pub dlp: bool,

    /// Whether database security issues were detected
    #[serde(default)]
    pub db_security: bool,

    /// Whether toxic or harmful content was detected
    #[serde(default)]
    pub toxic_content: bool,

    /// Whether malicious code was detected
    #[serde(default)]
    pub malicious_code: bool,

    /// Whether response contains any Agent related threats
    #[serde(default)]
    pub agent: bool,

    /// Whether response contains any ungrounded content
    #[serde(default)]
    pub ungrounded: bool,

    /// Whether the response contains content that violates topic guardrails
    #[serde(default)]
    pub topic_violation: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("Security assessment error: {0}")]
    SecurityError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}
