//! Streaming token counting for SSE (Server-Sent Events) responses.
//!
//! LLM APIs use SSE for streaming responses. This module:
//! - Parses SSE chunks to extract content deltas
//! - Accumulates text content across chunks
//! - Provides final token count using tiktoken
//!
//! # SSE Formats
//!
//! ## OpenAI
//! ```text
//! data: {"id":"...","choices":[{"delta":{"content":"Hello"}}]}
//! data: {"id":"...","choices":[{"delta":{"content":" world"}}]}
//! data: [DONE]
//! ```
//!
//! ## Anthropic
//! ```text
//! event: content_block_delta
//! data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let mut counter = StreamingTokenCounter::new("openai", Some("gpt-4"));
//! counter.process_chunk(chunk1);
//! counter.process_chunk(chunk2);
//! let tokens = counter.finalize();
//! ```

use serde_json::Value;
use tracing::{trace, warn};

use super::tiktoken::tiktoken_manager;
use zentinel_config::InferenceProvider;

/// Streaming token counter for SSE responses.
///
/// Accumulates content from SSE chunks and provides final token count.
#[derive(Debug)]
pub struct StreamingTokenCounter {
    /// Provider type for format detection
    provider: InferenceProvider,
    /// Model name for tiktoken encoding selection
    model: Option<String>,
    /// Accumulated content text
    content_buffer: String,
    /// Whether the stream has completed
    completed: bool,
    /// Number of chunks processed
    chunks_processed: u32,
    /// Bytes processed
    bytes_processed: u64,
    /// Final usage from API (if provided in stream)
    api_usage: Option<ApiUsage>,
    /// Partial SSE line buffer (for chunks that split across boundaries)
    line_buffer: String,
}

/// Usage information from API response (when provided).
#[derive(Debug, Clone)]
pub struct ApiUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}

/// Result of processing an SSE chunk.
#[derive(Debug)]
pub struct ChunkResult {
    /// Content extracted from this chunk
    pub content: Option<String>,
    /// Whether this chunk indicates stream completion
    pub is_done: bool,
    /// Usage info if present in this chunk
    pub usage: Option<ApiUsage>,
}

impl StreamingTokenCounter {
    /// Create a new streaming token counter.
    pub fn new(provider: InferenceProvider, model: Option<String>) -> Self {
        Self {
            provider,
            model,
            content_buffer: String::with_capacity(4096),
            completed: false,
            chunks_processed: 0,
            bytes_processed: 0,
            api_usage: None,
            line_buffer: String::new(),
        }
    }

    /// Process an SSE chunk from the response body.
    ///
    /// Extracts content deltas and accumulates them.
    /// Returns information about what was extracted.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> ChunkResult {
        self.chunks_processed += 1;
        self.bytes_processed += chunk.len() as u64;

        let chunk_str = match std::str::from_utf8(chunk) {
            Ok(s) => s,
            Err(_) => {
                warn!("Invalid UTF-8 in SSE chunk");
                return ChunkResult {
                    content: None,
                    is_done: false,
                    usage: None,
                };
            }
        };

        // Append to line buffer and process complete lines
        self.line_buffer.push_str(chunk_str);

        let mut result = ChunkResult {
            content: None,
            is_done: false,
            usage: None,
        };

        let mut content_parts = Vec::new();

        // Process complete lines
        while let Some(newline_pos) = self.line_buffer.find('\n') {
            let line = self.line_buffer[..newline_pos].trim();

            if !line.is_empty() {
                let line_result = self.process_sse_line(line);

                if let Some(content) = line_result.content {
                    content_parts.push(content);
                }
                if line_result.is_done {
                    result.is_done = true;
                    self.completed = true;
                }
                if line_result.usage.is_some() {
                    result.usage = line_result.usage.clone();
                    self.api_usage = line_result.usage;
                }
            }

            // Remove processed line from buffer
            self.line_buffer = self.line_buffer[newline_pos + 1..].to_string();
        }

        if !content_parts.is_empty() {
            let combined = content_parts.join("");
            self.content_buffer.push_str(&combined);
            result.content = Some(combined);
        }

        result
    }

    /// Process a single SSE line.
    fn process_sse_line(&self, line: &str) -> ChunkResult {
        // SSE format: "data: {...}" or "event: ..." or just data
        let data = if line.starts_with("data: ") {
            &line[6..]
        } else if line.starts_with("data:") {
            &line[5..]
        } else {
            // Skip event lines, comments, etc.
            return ChunkResult {
                content: None,
                is_done: false,
                usage: None,
            };
        };

        let data = data.trim();

        // Check for stream completion marker
        if data == "[DONE]" {
            return ChunkResult {
                content: None,
                is_done: true,
                usage: None,
            };
        }

        // Parse JSON
        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => {
                trace!(data = data, "Failed to parse SSE data as JSON");
                return ChunkResult {
                    content: None,
                    is_done: false,
                    usage: None,
                };
            }
        };

        match self.provider {
            InferenceProvider::OpenAi => self.parse_openai_chunk(&json),
            InferenceProvider::Anthropic => self.parse_anthropic_chunk(&json),
            InferenceProvider::Generic => {
                // Try OpenAI format first, then Anthropic
                let result = self.parse_openai_chunk(&json);
                if result.content.is_some() || result.is_done || result.usage.is_some() {
                    result
                } else {
                    self.parse_anthropic_chunk(&json)
                }
            }
        }
    }

    /// Parse OpenAI streaming chunk format.
    ///
    /// Format: {"choices":[{"delta":{"content":"..."}}],"usage":{...}}
    fn parse_openai_chunk(&self, json: &Value) -> ChunkResult {
        let mut result = ChunkResult {
            content: None,
            is_done: false,
            usage: None,
        };

        // Extract content from choices[0].delta.content
        if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
            if let Some(first_choice) = choices.first() {
                // Check for finish_reason indicating completion
                if let Some(finish_reason) = first_choice.get("finish_reason") {
                    if !finish_reason.is_null() {
                        result.is_done = true;
                    }
                }

                // Extract delta content
                if let Some(delta) = first_choice.get("delta") {
                    if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
                        result.content = Some(content.to_string());
                    }
                }
            }
        }

        // Extract usage if present (OpenAI includes this in the final chunk)
        if let Some(usage) = json.get("usage") {
            let prompt_tokens = usage
                .get("prompt_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            let completion_tokens = usage
                .get("completion_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            let total_tokens = usage
                .get("total_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(prompt_tokens + completion_tokens);

            if total_tokens > 0 {
                result.usage = Some(ApiUsage {
                    input_tokens: prompt_tokens,
                    output_tokens: completion_tokens,
                    total_tokens,
                });
            }
        }

        result
    }

    /// Parse Anthropic streaming chunk format.
    ///
    /// Format: {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
    fn parse_anthropic_chunk(&self, json: &Value) -> ChunkResult {
        let mut result = ChunkResult {
            content: None,
            is_done: false,
            usage: None,
        };

        let event_type = json.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match event_type {
            "content_block_delta" => {
                // Extract text from delta
                if let Some(delta) = json.get("delta") {
                    if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                        result.content = Some(text.to_string());
                    }
                }
            }
            "message_stop" => {
                result.is_done = true;
            }
            "message_delta" => {
                // Anthropic includes usage in message_delta at the end
                if let Some(usage) = json.get("usage") {
                    let output_tokens = usage
                        .get("output_tokens")
                        .and_then(|t| t.as_u64())
                        .unwrap_or(0);

                    if output_tokens > 0 {
                        result.usage = Some(ApiUsage {
                            input_tokens: 0, // Not provided in delta
                            output_tokens,
                            total_tokens: output_tokens,
                        });
                    }
                }
            }
            "message_start" => {
                // Anthropic includes input tokens in message_start
                if let Some(message) = json.get("message") {
                    if let Some(usage) = message.get("usage") {
                        let input_tokens = usage
                            .get("input_tokens")
                            .and_then(|t| t.as_u64())
                            .unwrap_or(0);

                        if input_tokens > 0 {
                            result.usage = Some(ApiUsage {
                                input_tokens,
                                output_tokens: 0,
                                total_tokens: input_tokens,
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        result
    }

    /// Check if the stream has completed.
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Get the accumulated content so far.
    pub fn content(&self) -> &str {
        &self.content_buffer
    }

    /// Get the number of chunks processed.
    pub fn chunks_processed(&self) -> u32 {
        self.chunks_processed
    }

    /// Get the bytes processed.
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Get API-provided usage if available.
    pub fn api_usage(&self) -> Option<&ApiUsage> {
        self.api_usage.as_ref()
    }

    /// Finalize and get the output token count.
    ///
    /// Uses API-provided usage if available, otherwise counts tokens
    /// in the accumulated content using tiktoken.
    pub fn finalize(&self) -> StreamingTokenResult {
        let manager = tiktoken_manager();

        // Prefer API-provided usage
        if let Some(usage) = &self.api_usage {
            trace!(
                input_tokens = usage.input_tokens,
                output_tokens = usage.output_tokens,
                total_tokens = usage.total_tokens,
                chunks = self.chunks_processed,
                "Using API-provided token counts for streaming response"
            );

            return StreamingTokenResult {
                output_tokens: usage.output_tokens,
                input_tokens: Some(usage.input_tokens),
                total_tokens: Some(usage.total_tokens),
                source: TokenCountSource::ApiProvided,
                content_length: self.content_buffer.len(),
            };
        }

        // Count tokens in accumulated content
        let output_tokens = manager.count_tokens(self.model.as_deref(), &self.content_buffer);

        trace!(
            output_tokens = output_tokens,
            content_len = self.content_buffer.len(),
            chunks = self.chunks_processed,
            model = ?self.model,
            "Counted tokens in streaming response content"
        );

        StreamingTokenResult {
            output_tokens,
            input_tokens: None,
            total_tokens: None,
            source: TokenCountSource::Tiktoken,
            content_length: self.content_buffer.len(),
        }
    }
}

/// Source of token count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCountSource {
    /// Token count provided by the API in the stream
    ApiProvided,
    /// Token count calculated using tiktoken
    Tiktoken,
}

/// Result of streaming token counting.
#[derive(Debug)]
pub struct StreamingTokenResult {
    /// Output tokens (completion tokens)
    pub output_tokens: u64,
    /// Input tokens (prompt tokens) if known
    pub input_tokens: Option<u64>,
    /// Total tokens if known
    pub total_tokens: Option<u64>,
    /// Source of the token count
    pub source: TokenCountSource,
    /// Length of accumulated content in bytes
    pub content_length: usize,
}

/// Check if a response appears to be SSE based on content type.
pub fn is_sse_response(content_type: Option<&str>) -> bool {
    content_type
        .is_some_and(|ct| ct.contains("text/event-stream") || ct.contains("application/x-ndjson"))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_streaming() {
        let mut counter =
            StreamingTokenCounter::new(InferenceProvider::OpenAi, Some("gpt-4".to_string()));

        // Simulate OpenAI SSE chunks
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n";
        let chunk2 = b"data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n";
        let chunk3 = b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n";
        let chunk4 = b"data: [DONE]\n\n";

        let r1 = counter.process_chunk(chunk1);
        assert_eq!(r1.content, Some("Hello".to_string()));
        assert!(!r1.is_done);

        let r2 = counter.process_chunk(chunk2);
        assert_eq!(r2.content, Some(" world".to_string()));
        assert!(!r2.is_done);

        let r3 = counter.process_chunk(chunk3);
        assert!(r3.is_done);
        assert!(r3.usage.is_some());
        let usage = r3.usage.unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 2);
        assert_eq!(usage.total_tokens, 12);

        let r4 = counter.process_chunk(chunk4);
        assert!(r4.is_done);

        assert_eq!(counter.content(), "Hello world");
        assert!(counter.is_completed());

        let result = counter.finalize();
        assert_eq!(result.output_tokens, 2);
        assert_eq!(result.input_tokens, Some(10));
        assert_eq!(result.source, TokenCountSource::ApiProvided);
    }

    #[test]
    fn test_anthropic_streaming() {
        let mut counter = StreamingTokenCounter::new(
            InferenceProvider::Anthropic,
            Some("claude-3-opus".to_string()),
        );

        // Simulate Anthropic SSE chunks
        let chunk1 = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":25}}}\n\n";
        let chunk2 = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n";
        let chunk3 = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}\n\n";
        let chunk4 = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\n";
        let chunk5 = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

        counter.process_chunk(chunk1);
        let r2 = counter.process_chunk(chunk2);
        assert_eq!(r2.content, Some("Hello".to_string()));

        let r3 = counter.process_chunk(chunk3);
        assert_eq!(r3.content, Some(" there".to_string()));

        let r4 = counter.process_chunk(chunk4);
        assert!(r4.usage.is_some());
        assert_eq!(r4.usage.unwrap().output_tokens, 3);

        let r5 = counter.process_chunk(chunk5);
        assert!(r5.is_done);

        assert_eq!(counter.content(), "Hello there");
        assert!(counter.is_completed());
    }

    #[test]
    fn test_tiktoken_fallback() {
        let mut counter =
            StreamingTokenCounter::new(InferenceProvider::OpenAi, Some("gpt-4".to_string()));

        // Chunks without usage info
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello world\"}}]}\n\n";
        let chunk2 = b"data: [DONE]\n\n";

        counter.process_chunk(chunk1);
        counter.process_chunk(chunk2);

        let result = counter.finalize();
        assert_eq!(result.source, TokenCountSource::Tiktoken);
        // "Hello world" is 2 tokens with cl100k_base
        assert!(result.output_tokens > 0);
    }

    #[test]
    fn test_split_chunks() {
        let mut counter =
            StreamingTokenCounter::new(InferenceProvider::OpenAi, Some("gpt-4".to_string()));

        // Data split across chunk boundaries
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"content\":\"He";
        let chunk2 = b"llo\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n";

        let r1 = counter.process_chunk(chunk1);
        assert!(r1.content.is_none()); // No complete line yet

        let r2 = counter.process_chunk(chunk2);
        // Should get both "Hello" and " world" as the line completes
        assert!(r2.content.is_some());
        assert!(counter.content().contains("Hello"));
        assert!(counter.content().contains(" world"));
    }

    #[test]
    fn test_is_sse_response() {
        assert!(is_sse_response(Some("text/event-stream")));
        assert!(is_sse_response(Some("text/event-stream; charset=utf-8")));
        assert!(is_sse_response(Some("application/x-ndjson")));
        assert!(!is_sse_response(Some("application/json")));
        assert!(!is_sse_response(None));
    }

    #[test]
    fn test_generic_provider() {
        let mut counter = StreamingTokenCounter::new(InferenceProvider::Generic, None);

        // Should handle OpenAI format
        let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"Test\"}}]}\n\n";
        let result = counter.process_chunk(chunk);
        assert_eq!(result.content, Some("Test".to_string()));
    }
}
