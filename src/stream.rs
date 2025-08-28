use crate::{
    handlers::utils::{format_security_violation_message, log_llm_metrics},
    security::{Assessment, SecurityClient},
    types::{StreamError, Content},
};
use bytes::Bytes;
use futures_util::{ready, Future, Stream};
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

// Type alias for complex assessment future to improve readability
type AssessmentFuture = Pin<Box<dyn Future<Output = Result<Assessment, StreamError>> + Send>>;

/// Buffer for stream content that handles parsing, accumulation, and code extraction.
///
/// This struct maintains separate buffers for text and code content, tracks code block boundaries,
/// and manages the buffering of content for security assessment.
#[derive(Debug)]
struct StreamBuffer {
    text_buffer: String,
    code_buffer: String,
    in_code_block: bool,
    read_pos: usize,
    output_buffer: Vec<Bytes>,        // General output buffer
    text_buffer_complete: Vec<Bytes>, // Buffer for complete text responses
    code_buffer_complete: Vec<Bytes>, // Buffer for complete code blocks
    pending_buffer: Vec<Bytes>,       // Buffer for content waiting for assessment
    assessment_window: usize,
    sentence_boundary_chars: &'static [char],
    last_was_boundary: bool,
    waiting_for_assessment: bool, // Flag indicating we're waiting for assessment
    has_complete_text: bool,      // Flag indicating we have complete text
    has_complete_code: bool,      // Flag indicating we have complete code
    batch_ready: bool,            // Flag indicating a batch is ready to send
    accumulating: bool,           // Flag indicating we're accumulating chunks
    blocked: bool,                // Flag indicating content has been blocked
    last_assessed_text_pos: usize, // Position in text buffer that has already been assessed
    last_assessed_code_pos: usize, // Position in code buffer that has already been assessed
}

impl StreamBuffer {
    /// Creates a new StreamBuffer with default settings.
    ///
    /// Initializes all buffers as empty and sets default values for assessment
    /// parameters such as the assessment window size and sentence boundary characters.
    fn new() -> Self {
        // Constants for buffer sizing optimization
        const ASSESSMENT_WINDOW: usize = 100_000;
        const TEXT_INITIAL_CAPACITY: usize = ASSESSMENT_WINDOW / 10; // 10% of max assessment window
        const VEC_INITIAL_CAPACITY: usize = 8; // Default small vector capacity
        
        Self {
            text_buffer: String::with_capacity(TEXT_INITIAL_CAPACITY),
            code_buffer: String::with_capacity(TEXT_INITIAL_CAPACITY),
            in_code_block: false,
            read_pos: 0,
            output_buffer: Vec::with_capacity(VEC_INITIAL_CAPACITY),
            text_buffer_complete: Vec::with_capacity(VEC_INITIAL_CAPACITY),
            code_buffer_complete: Vec::with_capacity(VEC_INITIAL_CAPACITY),
            pending_buffer: Vec::with_capacity(VEC_INITIAL_CAPACITY),
            assessment_window: ASSESSMENT_WINDOW,
            sentence_boundary_chars: &['\n'],
            last_was_boundary: false,
            waiting_for_assessment: false,
            has_complete_text: false,
            has_complete_code: false,
            batch_ready: false,
            accumulating: false,
            blocked: false,
            last_assessed_text_pos: 0,
            last_assessed_code_pos: 0,
        }
    }

    /// Processes a string chunk from the stream, parsing it as JSON and extracting content.
    ///
    /// This method parses Ollama's JSON response chunks, identifies and separates regular text
    /// from code blocks, and maintains the state of code block detection between chunks.
    ///
    /// # Arguments
    ///
    /// * `chunk` - A string representing a JSON chunk from the Ollama API
    fn process(&mut self, chunk: &str) {
        // Parse Ollama's JSON response chunk
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
            if let Some(content) = json["message"]["content"].as_str() {
                // Look for code block markers in the incoming content
                if content.contains("```") {
                    // Contains a code block marker, need special processing
                    let parts: Vec<&str> = content.split("```").collect();
                    let mut in_block = self.in_code_block;

                    // Estimate total capacity needed to avoid multiple reallocations
                    let additional_text_needed = parts
                        .iter()
                        .enumerate()
                        .filter(|&(i, _)| i % 2 == (if in_block { 1 } else { 0 }))
                        .map(|(_, part)| part.len())
                        .sum::<usize>();

                    let additional_code_needed = parts
                        .iter()
                        .enumerate()
                        .filter(|&(i, _)| i % 2 == (if in_block { 0 } else { 1 }))
                        .map(|(_, part)| part.len())
                        .sum::<usize>();

                    // Reserve capacity before adding strings
                    self.text_buffer.reserve(additional_text_needed);
                    self.code_buffer.reserve(additional_code_needed);

                    for (i, part) in parts.iter().enumerate() {
                        if i == 0 && !in_block {
                            // First part before any code block
                            if !part.is_empty() {
                                self.text_buffer.push_str(part);
                            }
                        } else if i == 0 && in_block {
                            // First part is continuation of a code block
                            if !part.is_empty() {
                                self.code_buffer.push_str(part);
                            }
                        } else if in_block {
                            // This is code block content
                            if !part.is_empty() {
                                self.code_buffer.push_str(part);
                            }
                            in_block = false;
                        } else {
                            // This is regular text
                            if !part.is_empty() {
                                self.text_buffer.push_str(part);
                            }
                            in_block = true;
                        }
                    }

                    // Update the code block state
                    self.in_code_block = in_block;
                } else {
                    // No code block markers, add to the appropriate buffer
                    // Reserve capacity before adding content
                    if self.in_code_block {
                        self.code_buffer.reserve(content.len());
                        self.code_buffer.push_str(content);
                    } else {
                        self.text_buffer.reserve(content.len());
                        self.text_buffer.push_str(content);
                    }
                }
            }
        }
    }

    /// Detects code block markers in the current active buffer.
    ///
    /// This method looks for triple backtick (```) markers in either the text or code buffer
    /// (depending on the current state) and handles transitions between text and code content.
    fn detect_code_blocks(&mut self) {
        // Look for triple backticks in the current active buffer
        let active_buffer = if self.in_code_block {
            &self.code_buffer
        } else {
            &self.text_buffer
        };

        // Make a copy of the buffer to search to avoid borrow issues
        let buffer_copy = active_buffer.clone();

        // Find code block markers
        if let Some(pos) = buffer_copy.find("```") {
            if self.in_code_block {
                // End of a code block
                // Extract content before the marker and clear the buffer
                let code_content = active_buffer[..pos].to_string();
                if self.in_code_block {
                    self.code_buffer.clear();
                    self.code_buffer.push_str(&code_content);
                }

                // Add content after the marker to the text buffer
                if pos + 3 < buffer_copy.len() {
                    let remaining = &buffer_copy[pos + 3..];
                    self.text_buffer.push_str(remaining);
                }

                // Mark that we have a complete code block
                self.has_complete_code = true;
            } else {
                // Start of a code block
                // Extract content before the marker
                let text_content = active_buffer[..pos].to_string();
                if !self.in_code_block {
                    self.text_buffer.clear();
                    self.text_buffer.push_str(&text_content);
                }

                // Add content after the marker to the code buffer
                if pos + 3 < buffer_copy.len() {
                    let remaining = &buffer_copy[pos + 3..];
                    self.code_buffer.push_str(remaining);
                }
            }

            // Toggle code block state
            self.in_code_block = !self.in_code_block;
        }
    }

    /// Prepares content for security assessment based on the current buffer state.
    ///
    /// Creates a Content structure containing either prompt or response data along with
    /// any associated code blocks, depending on whether the content is a prompt or response.
    ///
    /// # Arguments
    ///
    /// * `is_prompt` - Boolean indicating if the content is a prompt (true) or response (false)
    ///
    /// # Returns
    ///
    /// A Content structure with the appropriate fields populated
    fn prepare_assessment_content(&mut self, is_prompt: bool) -> Content {
        // Get only the new (unassessed) portions of the text and code buffers
        let new_text = if self.text_buffer.len() > self.last_assessed_text_pos {
            &self.text_buffer[self.last_assessed_text_pos..]
        } else {
            ""
        };

        let new_code = if self.code_buffer.len() > self.last_assessed_code_pos {
            &self.code_buffer[self.last_assessed_code_pos..]
        } else {
            ""
        };

        let has_new_code = !new_code.is_empty();

        if is_prompt {
            // For prompt content
            Content {
                prompt: Some(new_text.to_string()),
                response: None,
                code_prompt: if has_new_code { Some(new_code.to_string()) } else { None },
                code_response: None,
                context: None,
            }
        } else {
            // For response content
            Content {
                prompt: None,
                response: Some(new_text.to_string()),
                code_prompt: None,
                code_response: if has_new_code { Some(new_code.to_string()) } else { None },
                context: None,
            }
        }
    }

    /// Determines if the current buffer state contains content that should be assessed.
    ///
    /// Content is considered assessable if it exceeds the assessment window size,
    /// contains a complete code block, or forms a complete sentence or paragraph.
    ///
    /// # Arguments
    ///
    /// * `is_prompt` - Boolean indicating if the content is a prompt (true) or response (false)
    ///
    /// # Returns
    ///
    /// Some(Content) if there is assessable content, None otherwise
    fn get_assessable_chunk(&mut self, is_prompt: bool) -> Option<Content> {
        let new_text_content = self.text_buffer.len() > self.last_assessed_text_pos;
        let new_code_content = self.code_buffer.len() > self.last_assessed_code_pos;

        // Check if there is any new content to assess
        if !new_text_content && !new_code_content {
            return None;
        }

        // Safety check - make sure positions are valid to prevent subtraction overflow
        if self.text_buffer.len() < self.last_assessed_text_pos {
            self.last_assessed_text_pos = 0;
        }
        if self.code_buffer.len() < self.last_assessed_code_pos {
            self.last_assessed_code_pos = 0;
        }

        // Always assess if we've accumulated a large amount of new content
        if (self.text_buffer.len() - self.last_assessed_text_pos) >= self.assessment_window
            || (self.code_buffer.len() - self.last_assessed_code_pos) >= self.assessment_window
        {
            return Some(self.prepare_assessment_content(is_prompt));
        }

        // If we've completed a code block, assess it
        if !self.in_code_block && new_code_content {
            return Some(self.prepare_assessment_content(is_prompt));
        }

        // Check for semantic boundaries in text
        if new_text_content {
            let last_char = self.text_buffer.chars().last().unwrap_or(' ');
            if self.sentence_boundary_chars.contains(&last_char)
                && self.text_buffer.len() > 15
                && !self.last_was_boundary
            {
                self.last_was_boundary = true;
                return Some(self.prepare_assessment_content(is_prompt));
            } else if !self.sentence_boundary_chars.contains(&last_char) {
                self.last_was_boundary = false;
            }
        }

        None
    }

    /// Commits the current buffer state after assessment.
    ///
    /// If the content is deemed safe, updates the read position and clears the code buffer.
    /// If not safe, keeps the buffers unchanged for potential modification.
    ///
    /// # Arguments
    ///
    /// * `is_safe` - Boolean indicating if the assessed content is safe
    fn commit(&mut self, is_safe: bool) {
        // If content is safe, we can reset buffers or handle accordingly
        if is_safe {
            self.read_pos = self.text_buffer.len();
            self.last_assessed_text_pos = self.text_buffer.len();
            self.last_assessed_code_pos = self.code_buffer.len();
            // Also clear the code buffer since it has been assessed
            self.code_buffer.clear(); // Reset code buffer and its assessed position
        }
        // If not safe, we keep buffers as is to potentially modify them
    }

    /// Adds a chunk to the pending buffer for later assessment.
    ///
    /// This method stores chunks that are waiting for security assessment before
    /// being released to the output stream.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw bytes to store in the pending buffer
    fn buffer_pending_chunk(&mut self, bytes: Bytes) {
        self.pending_buffer.push(bytes);
        self.waiting_for_assessment = true;
    }

    /// Moves content from the pending buffer to the appropriate destination buffer
    /// once security assessment is complete.
    ///
    /// This method determines whether the pending content contains code blocks and
    /// routes it to either the code buffer or text buffer accordingly.
    fn release_pending_chunks(&mut self) {
        // First, find what kind of content we have in pending buffer
        let mut has_code = false;

        for bytes in &self.pending_buffer {
            if let Ok(chunk) = std::str::from_utf8(bytes) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
                    if let Some(content) = json["message"]["content"].as_str() {
                        if content.contains("```") || self.in_code_block {
                            has_code = true;
                            break;
                        }
                    }
                }
            }
        }

        // Move pending chunks to the appropriate buffer based on content type
        if has_code {
            // Move to code buffer
            for chunk in self.pending_buffer.drain(..) {
                self.code_buffer_complete.push(chunk);
            }
            self.has_complete_code = true;
        } else {
            // Move to text buffer
            for chunk in self.pending_buffer.drain(..) {
                self.text_buffer_complete.push(chunk);
            }
            self.has_complete_text = true;
        }

        // Mark the content as ready to send
        self.mark_batch_ready();
        self.waiting_for_assessment = false;
    }

    /// Marks the current batch of content as ready to be returned.
    ///
    /// This method is called when either text or code content has been completed
    /// and is ready to be sent to the consumer.
    fn mark_batch_ready(&mut self) {
        // If we have completed code blocks or text, mark the batch as ready
        if self.has_complete_code || self.has_complete_text {
            self.batch_ready = true;
            self.accumulating = false;
        }
    }

    /// Creates a single response from all accumulated content in the relevant buffer.
    ///
    /// Combines chunks from either code, text, or general output buffers into a single
    /// response, prioritizing code content if available.
    ///
    /// # Returns
    ///
    /// Some(Bytes) if there is content to return, None otherwise
    fn create_complete_response(&mut self) -> Option<Bytes> {
        // Pre-calculate the total buffer size needed to avoid reallocations
        let total_size = if self.has_complete_code {
            self.code_buffer_complete
                .iter()
                .map(|b| b.len())
                .sum::<usize>()
        } else if self.has_complete_text {
            self.text_buffer_complete
                .iter()
                .map(|b| b.len())
                .sum::<usize>()
        } else {
            self.output_buffer.iter().map(|b| b.len()).sum::<usize>()
        };

        // Pre-allocate with the right size
        let mut combined_data = Vec::with_capacity(total_size);

        // If we have complete code, prioritize that
        if self.has_complete_code {
            // Combine all code chunks
            for chunk in self.code_buffer_complete.drain(..) {
                combined_data.extend_from_slice(&chunk);
            }
            self.has_complete_code = false;
        } else if self.has_complete_text {
            // Combine all text chunks
            for chunk in self.text_buffer_complete.drain(..) {
                combined_data.extend_from_slice(&chunk);
            }
            self.has_complete_text = false;
        } else {
            // Combine all general output chunks
            for chunk in self.output_buffer.drain(..) {
                combined_data.extend_from_slice(&chunk);
            }
        }

        self.batch_ready = false;

        if !combined_data.is_empty() {
            Some(Bytes::from(combined_data))
        } else {
            None
        }
    }

    /// Returns the next complete chunk if a batch is ready.
    ///
    /// This method only returns content when a complete batch is ready, as indicated
    /// by the batch_ready flag.
    ///
    /// # Returns
    ///
    /// Some(Bytes) if a complete batch is ready, None otherwise
    fn get_next_chunk(&mut self) -> Option<Bytes> {
        if self.batch_ready {
            return self.create_complete_response();
        }

        // Not returning individual chunks - accumulate until batch is ready
        None
    }
}

#[pin_project]
/// A stream wrapper that performs security assessment on content chunks.
///
/// This stream wraps any stream of bytes and performs security assessment on the content
/// before passing it on to consumers. It handles buffering, batching, and separating
/// text and code content for assessment.
pub struct SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
{
    #[pin]
    inner: S,
    security_client: SecurityClient,
    model_name: String,
    buffer: StreamBuffer,
    assessment_fut: Option<AssessmentFuture>,
    finished: bool,
    retry_count: u32,
    is_prompt: bool,
}

/// Creates a formatted response for blocked content.
///
/// This function generates a standardized message indicating that content has been
/// blocked by the security assessment system, including the category, action details,
/// and specific detection information.
///
/// # Arguments
///
/// * `assessment` - The complete security assessment result
///
/// # Returns
///
/// Bytes containing the formatted blocked content message
fn create_blocked_response(assessment: &Assessment) -> Bytes {
    // Format a JSON response that looks like a normal LLM response but contains our blocked message
    let blocked_json = serde_json::json!({
        "model": "security-filter", // Could be customized if needed
        "created_at": chrono::Utc::now().to_rfc3339(),
        "message": {
            "role": "assistant",
            "content": format_security_violation_message(assessment)
        },
        "done": true
    });

    // Convert to bytes
    Bytes::from(serde_json::to_vec(&blocked_json).unwrap_or_else(|_| {
        format!(
            "BLOCKED - Category: {}, Action: {}",
            assessment.category, assessment.action
        )
        .into_bytes()
    }))
}

/// Creates a future that will perform security assessment on buffered content.
///
/// This function prepares the content from the buffer and creates an asynchronous task
/// that will perform a security assessment using the provided security client.
///
/// # Arguments
///
/// * `buffer` - The StreamBuffer containing content to assess
/// * `security_client` - The client to use for security assessment
/// * `model_name` - The name of the AI model being used
/// * `is_prompt` - Whether the content is a prompt (true) or response (false)
///
/// # Returns
///
/// A pinned, boxed future that will resolve to an Assessment result
fn create_security_assessment_future(
    buffer: &StreamBuffer,
    security_client: &SecurityClient,
    model_name: &str,
    is_prompt: bool,
) -> AssessmentFuture {
    // Get the separate content buffers
    let text_content = buffer.text_buffer.clone();
    let code_content = buffer.code_buffer.clone();

    // Clone what we need for the async block
    let client = security_client.clone();
    let model = model_name.to_string();

    // Create assessment future with appropriate content based on what we have
    Box::pin(async move {
        // If we have code content, include it in the assessment
        if !code_content.is_empty() {
            client
                .assess_content_with_code(&text_content, &code_content, &model, is_prompt)
                .await
                .map_err(|e| StreamError::SecurityError(e.to_string()))
        } else {
            // Otherwise just assess the text
            client
                .assess_content(&text_content, &model, is_prompt)
                .await
                .map_err(|e| StreamError::SecurityError(e.to_string()))
        }
    })
}

impl<S> SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
{
    /// Creates a new SecurityAssessedStream wrapping an inner byte stream.
    ///
    /// This constructor initializes a new stream that will perform security assessment
    /// on content chunks from the inner stream before passing them on.
    ///
    /// # Arguments
    ///
    /// * `inner` - The inner stream to wrap, which produces bytes
    /// * `security_client` - Client for performing security assessments
    /// * `model_name` - Name of the AI model being used
    /// * `is_prompt` - Whether this stream contains prompt (true) or response (false) content
    ///
    /// # Returns
    ///
    /// A new SecurityAssessedStream instance
    pub fn new(
        inner: S,
        security_client: SecurityClient,
        model_name: String,
        is_prompt: bool,
    ) -> Self {
        Self {
            inner,
            security_client,
            model_name,
            buffer: StreamBuffer::new(),
            assessment_fut: None,
            finished: false,
            retry_count: 0,
            is_prompt,
        }
    }

    /// Processes the results of a security assessment on buffered content.
    ///
    /// This method handles what happens after a security assessment is completed,
    /// either passing content through if it's safe or blocking it if it's unsafe.
    ///
    /// # Arguments
    ///
    /// * `assessment` - The security assessment result
    /// * `buffer` - The buffer containing content that was assessed
    /// * `assessment_fut` - The future that produced the assessment (will be cleared)
    /// * `retry_count` - Counter for assessment retry attempts
    ///
    /// # Returns
    ///
    /// Some(Result) if a response should be sent immediately, None if processing should continue
    fn process_assessment_result(
        assessment: Assessment,
        buffer: &mut StreamBuffer,
        assessment_fut: &mut Option<AssessmentFuture>,
        retry_count: &mut u32,
    ) -> Option<Result<Bytes, StreamError>> {
        // Important: Always clear the future after processing to avoid "resumed after completion" panic
        *assessment_fut = None;

        if !assessment.is_safe {
            let blocked = create_blocked_response(&assessment);
            *retry_count = 0;
            // Clear the pending buffer since we're not going to send these chunks
            buffer.pending_buffer.clear();
            buffer.waiting_for_assessment = false;
            buffer.accumulating = false;
            buffer.blocked = true;
            return Some(Ok(blocked));
        }

        // Don't try to send content if the buffer is empty
        if buffer.text_buffer.is_empty()
            && buffer.code_buffer.is_empty()
            && buffer.pending_buffer.is_empty()
        {
            buffer.commit(true);
            return None;
        }

        // Mark the content as safe by updating the read position and clearing code buffer
        buffer.commit(true);

        // Release all pending chunks now that assessment is complete
        buffer.release_pending_chunks();

        // We don't return a result here - we'll let the chunks flow through via get_next_chunk
        None
    }

    /// Processes a single chunk from the stream.
    ///
    /// This method handles incoming bytes, processing them for content extraction
    /// and determining whether a security assessment is needed.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw bytes from the stream
    /// * `buffer` - The buffer to store processed content
    /// * `assessment_fut` - Optional future for pending assessments
    /// * `security_client` - Client for performing security assessments
    /// * `model_name` - Name of the AI model being used
    /// * `is_prompt` - Whether this is prompt or response content
    ///
    /// # Returns
    ///
    /// Some(Result) if a response should be sent immediately, None if processing should continue
    fn process_stream_chunk(
        bytes: Bytes,
        buffer: &mut StreamBuffer,
        assessment_fut: &mut Option<AssessmentFuture>,
        security_client: &SecurityClient,
        model_name: &str,
        is_prompt: bool,
    ) -> Option<Result<Bytes, StreamError>> {
        if let Ok(chunk) = std::str::from_utf8(&bytes) {
            // Check if this is the final chunk containing LLM metrics
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(chunk) {
                if json.get("done").and_then(|v| v.as_bool()).unwrap_or(false) {
                    // Use the shared utility function to log metrics
                    log_llm_metrics(&json, true);
                }
            }

            // Process the chunk which will now properly separate text and code for assessment
            buffer.process(chunk);

            // Call detect_code_blocks to find and handle code block markers
            buffer.detect_code_blocks();

            // Always buffer the chunk while we determine if assessment is needed
            buffer.buffer_pending_chunk(bytes);

            // Check if we need to trigger an assessment
            if buffer.get_assessable_chunk(is_prompt).is_some() {
                *assessment_fut = Some(create_security_assessment_future(
                    buffer,
                    security_client,
                    model_name,
                    is_prompt,
                ));
                // We're already buffering chunks - set the waiting flag
                buffer.waiting_for_assessment = true;
                return None;
            }

            // If we're not waiting for assessment, we should still assess this content
            // before sending it, so we'll create an assessment future anyway
            if !buffer.waiting_for_assessment {
                // Always perform some level of assessment before sending content
                buffer.waiting_for_assessment = true;
                *assessment_fut = Some(create_security_assessment_future(
                    buffer,
                    security_client,
                    model_name,
                    is_prompt,
                ));
            }

            return None;
        }

        // If we couldn't process as UTF-8, add to pending buffer to be safe
        buffer.buffer_pending_chunk(bytes);

        // If we're not waiting for assessment, trigger one anyway for safety
        if !buffer.waiting_for_assessment {
            buffer.waiting_for_assessment = true;
            *assessment_fut = Some(create_security_assessment_future(
                buffer,
                security_client,
                model_name,
                is_prompt,
            ));
        }

        None
    }

    /// Handles the end of a stream by performing a final assessment if needed.
    ///
    /// When the input stream ends, this method checks if there's any remaining content
    /// that needs security assessment before the stream can complete.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer containing any remaining content
    /// * `assessment_fut` - Optional future for pending assessments
    /// * `security_client` - Client for performing security assessments
    /// * `model_name` - Name of the AI model being used
    /// * `is_prompt` - Whether this is prompt or response content
    ///
    /// # Returns
    ///
    /// Some(Result) if a final response should be sent, None if processing should continue
    fn process_stream_end(
        buffer: &mut StreamBuffer,
        assessment_fut: &mut Option<AssessmentFuture>,
        security_client: &SecurityClient,
        model_name: &str,
        is_prompt: bool,
    ) -> Option<Result<Bytes, StreamError>> {
        // Check if there's any new content since the last assessment
        let new_text_content = buffer.text_buffer.len() > buffer.last_assessed_text_pos;
        let new_code_content = buffer.code_buffer.len() > buffer.last_assessed_code_pos;

        // Only trigger final assessment if we have new content
        if new_text_content || new_code_content {
            // Only log the new portions of text/code that will be assessed
            if new_text_content {
                &buffer.text_buffer[buffer.last_assessed_text_pos..]
            } else {
                ""
            };

            if new_code_content {
                &buffer.code_buffer[buffer.last_assessed_code_pos..]
            } else {
                ""
            };

            // Create assessment future for the new content
            *assessment_fut = Some(create_security_assessment_future(
                buffer,
                security_client,
                model_name,
                is_prompt,
            ));

            // Update tracking positions to avoid reassessing this content
            buffer.last_assessed_text_pos = buffer.text_buffer.len();
            buffer.last_assessed_code_pos = buffer.code_buffer.len();

            None
        } else {
            // No new content to assess
            None
        }
    }

    /// Implementation of the Stream::poll_next method.
    ///
    /// This method handles the stream polling logic, checking for buffered chunks,
    /// processing pending assessments, and handling the inner stream's data.
    ///
    /// # Arguments
    ///
    /// * `self` - Pinned mutable reference to self
    /// * `cx` - Task context for waking
    ///
    /// # Returns
    ///
    /// Poll indicating whether an item is ready or pending
    fn poll_next_impl(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, StreamError>>>
    where
        S: Unpin,
    {
        let mut this = self.project();

        // Check if content has been blocked, if so we should stop processing and close the stream
        if this.buffer.blocked {
            *this.finished = true;
            return Poll::Ready(None);
        }

        // First check if we have any buffered chunks ready to return
        if let Some(bytes) = this.buffer.get_next_chunk() {
            return Poll::Ready(Some(Ok(bytes)));
        }

        loop {
            if *this.finished {
                return Poll::Ready(None);
            }

            // Process pending security assessments
            if let Some(fut) = this.assessment_fut.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(assessment)) => {
                        if let Some(result) = Self::process_assessment_result(
                            assessment,
                            this.buffer,
                            this.assessment_fut,
                            this.retry_count,
                        ) {
                            // If content has been blocked, return the blocked message
                            // and mark the stream as finished on the next poll
                            if this.buffer.blocked {
                                return Poll::Ready(Some(result));
                            }
                            return Poll::Ready(Some(result));
                        }
                        // After processing assessment, check if we have buffered chunks to return
                        if let Some(bytes) = this.buffer.get_next_chunk() {
                            return Poll::Ready(Some(Ok(bytes)));
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        this.assessment_fut.take();
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Process incoming stream chunks
            match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(Ok(bytes)) => {
                    Self::process_stream_chunk(
                        bytes,
                        this.buffer,
                        this.assessment_fut,
                        this.security_client,
                        this.model_name,
                        *this.is_prompt,
                    );

                    // After processing the chunk, check if we have any completed content to return
                    if this.assessment_fut.is_some() {
                        // If we started an assessment, wait for it to complete
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    } else if let Some(bytes) = this.buffer.get_next_chunk() {
                        // If we have a chunk ready to return, return it
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                    // Otherwise continue processing more chunks
                    continue;
                }
                Some(Err(e)) => {
                    return Poll::Ready(Some(Err(StreamError::NetworkError(e.to_string()))));
                }
                None => {
                    // Final assessment on stream end
                    if let Some(result) = Self::process_stream_end(
                        this.buffer,
                        this.assessment_fut,
                        this.security_client,
                        this.model_name,
                        *this.is_prompt,
                    ) {
                        return Poll::Ready(Some(result));
                    } else if this.assessment_fut.is_some() {
                        // If we started a final assessment, wait for it to complete
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    } else if let Some(bytes) = this.buffer.get_next_chunk() {
                        // Try to return any remaining buffered chunks
                        return Poll::Ready(Some(Ok(bytes)));
                    } else {
                        *this.finished = true;
                        return Poll::Ready(None);
                    }
                }
            }
        }
    }
}

impl<S> Stream for SecurityAssessedStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    type Item = Result<Bytes, StreamError>;

    /// Polls this stream for the next item.
    ///
    /// This implementation satisfies the Stream trait by delegating to the poll_next_impl method.
    /// It handles asynchronous polling of the wrapped stream, including security assessment of content.
    ///
    /// # Arguments
    ///
    /// * `self` - Pinned mutable reference to self
    /// * `cx` - Task context for waking
    ///
    /// # Returns
    ///
    /// Poll indicating whether an item is ready or pending
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_next_impl(cx)
    }
}
