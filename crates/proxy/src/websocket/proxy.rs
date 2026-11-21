//! WebSocket proxy handler for frame-level inspection.
//!
//! This module provides WebSocket frame inspection by intercepting data
//! in Pingora's body filters after a 101 upgrade. Frames are parsed from
//! the byte stream, sent to agents for inspection, and filtered based on
//! agent decisions.
//!
//! # Architecture
//!
//! After a 101 upgrade, Pingora treats the bidirectional data as "body" bytes.
//! We intercept these in `request_body_filter` (client→server) and
//! `response_body_filter` (server→client), parse WebSocket frames, and
//! apply agent decisions.
//!
//! ```text
//! Client → [body_filter] → Frame Parser → Agent → Forward/Drop/Close
//!                                ↓
//! Server ← [body_filter] ← Frame Parser ← Agent ← Forward/Drop/Close
//! ```

use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use super::codec::{WebSocketCodec, WebSocketFrame};
use super::inspector::{InspectionResult, WebSocketInspector};

/// Trait for WebSocket frame inspection.
///
/// This trait abstracts the frame inspection logic, allowing for
/// easy testing with mock implementations.
#[async_trait::async_trait]
pub trait FrameInspector: Send + Sync {
    /// Inspect a frame from client to server
    async fn inspect_client_frame(&self, frame: &WebSocketFrame) -> InspectionResult;

    /// Inspect a frame from server to client
    async fn inspect_server_frame(&self, frame: &WebSocketFrame) -> InspectionResult;

    /// Get the correlation ID for logging
    fn correlation_id(&self) -> &str;
}

/// Implementation of FrameInspector that delegates to WebSocketInspector
#[async_trait::async_trait]
impl FrameInspector for WebSocketInspector {
    async fn inspect_client_frame(&self, frame: &WebSocketFrame) -> InspectionResult {
        WebSocketInspector::inspect_client_frame(self, frame).await
    }

    async fn inspect_server_frame(&self, frame: &WebSocketFrame) -> InspectionResult {
        WebSocketInspector::inspect_server_frame(self, frame).await
    }

    fn correlation_id(&self) -> &str {
        WebSocketInspector::correlation_id(self)
    }
}

/// WebSocket frame handler for body filter integration.
///
/// This handler accumulates bytes from Pingora's body filters, parses them
/// into WebSocket frames, and applies agent inspection decisions.
pub struct WebSocketHandler<I: FrameInspector = WebSocketInspector> {
    /// Frame parser/codec
    codec: WebSocketCodec,
    /// Frame inspector for agent integration
    inspector: Arc<I>,
    /// Buffer for incomplete frames (client → server)
    client_buffer: Mutex<BytesMut>,
    /// Buffer for incomplete frames (server → client)
    server_buffer: Mutex<BytesMut>,
    /// Whether the connection should be closed, and why
    should_close: Mutex<Option<Closing>>,
}

/// Why the connection is closing.
#[derive(Debug, Clone)]
enum Closing {
    /// An agent asked for it.
    Agent(CloseReason),
    /// A frame could not be decoded.
    Undecodable(CloseReason),
}

impl Closing {
    fn reason(&self) -> &CloseReason {
        match self {
            Self::Agent(reason) | Self::Undecodable(reason) => reason,
        }
    }

    fn into_result(self) -> ProcessResult {
        match self {
            Self::Agent(reason) => ProcessResult::Close(reason),
            Self::Undecodable(reason) => ProcessResult::Undecodable {
                reason,
                forward: Bytes::new(),
            },
        }
    }
}

/// Reason for closing the WebSocket connection
#[derive(Debug, Clone)]
pub struct CloseReason {
    pub code: u16,
    pub reason: String,
}

/// Result of processing WebSocket data
#[derive(Debug)]
pub enum ProcessResult {
    /// Forward the (possibly modified) data
    Forward(Option<Bytes>),
    /// Close the connection with the given code and reason, because an agent
    /// asked for it
    Close(CloseReason),
    /// Close the connection with the given code and reason, because a frame
    /// could not be decoded. Nothing of the undecodable frame, or of what
    /// follows it, is to be forwarded.
    Undecodable {
        /// Why, and with which status, the connection is closed.
        reason: CloseReason,
        /// The frames that came before the undecodable one in the same data
        /// and were allowed: they are forwarded first. Empty after the first
        /// result.
        forward: Bytes,
    },
}

impl<I: FrameInspector> WebSocketHandler<I> {
    /// Create a new WebSocket handler with a custom inspector
    pub fn with_inspector(inspector: Arc<I>, max_frame_size: usize) -> Self {
        debug!(
            correlation_id = %inspector.correlation_id(),
            max_frame_size = max_frame_size,
            "Creating WebSocket handler"
        );

        Self {
            codec: WebSocketCodec::new(max_frame_size),
            inspector,
            client_buffer: Mutex::new(BytesMut::with_capacity(4096)),
            server_buffer: Mutex::new(BytesMut::with_capacity(4096)),
            should_close: Mutex::new(None),
        }
    }
}

impl WebSocketHandler<WebSocketInspector> {
    /// Create a new WebSocket handler with the default WebSocketInspector
    pub fn new(inspector: Arc<WebSocketInspector>, max_frame_size: usize) -> Self {
        Self::with_inspector(inspector, max_frame_size)
    }
}

impl<I: FrameInspector> WebSocketHandler<I> {
    /// Process data from client to server (request body)
    ///
    /// Returns the data to forward (may be modified or None if all frames were dropped)
    pub async fn process_client_data(&self, data: Option<Bytes>) -> ProcessResult {
        // Check if we should close
        if let Some(closing) = self.should_close.lock().await.clone() {
            return closing.into_result();
        }

        let Some(data) = data else {
            // End of stream
            return ProcessResult::Forward(None);
        };

        self.process_data(data, true).await
    }

    /// Process data from server to client (response body)
    ///
    /// Returns the data to forward (may be modified or None if all frames were dropped)
    pub async fn process_server_data(&self, data: Option<Bytes>) -> ProcessResult {
        // Check if we should close
        if let Some(closing) = self.should_close.lock().await.clone() {
            return closing.into_result();
        }

        let Some(data) = data else {
            // End of stream
            return ProcessResult::Forward(None);
        };

        self.process_data(data, false).await
    }

    /// Internal data processing
    async fn process_data(&self, data: Bytes, client_to_server: bool) -> ProcessResult {
        let buffer = if client_to_server {
            &self.client_buffer
        } else {
            &self.server_buffer
        };

        let mut buf = buffer.lock().await;
        buf.extend_from_slice(&data);

        let mut output = BytesMut::new();
        let mut frames_processed = 0;
        let mut frames_dropped = 0;

        // Parse and process frames from the buffer
        loop {
            // Try to decode a frame
            match self.codec.decode_frame(&buf) {
                Ok(Some((frame, consumed))) => {
                    frames_processed += 1;

                    // Inspect the frame
                    let result = if client_to_server {
                        self.inspector.inspect_client_frame(&frame).await
                    } else {
                        self.inspector.inspect_server_frame(&frame).await
                    };

                    match result {
                        InspectionResult::Allow => {
                            // Forward the frame - copy the raw bytes
                            output.extend_from_slice(&buf[..consumed]);
                        }
                        InspectionResult::Drop => {
                            frames_dropped += 1;
                            trace!(
                                correlation_id = %self.inspector.correlation_id(),
                                opcode = ?frame.opcode,
                                direction = if client_to_server { "c2s" } else { "s2c" },
                                "Dropping WebSocket frame"
                            );
                            // Don't forward this frame
                        }
                        InspectionResult::Close { code, reason } => {
                            debug!(
                                correlation_id = %self.inspector.correlation_id(),
                                code = code,
                                reason = %reason,
                                "Agent requested WebSocket close"
                            );

                            // Store close reason
                            *self.should_close.lock().await = Some(Closing::Agent(CloseReason {
                                code,
                                reason: reason.clone(),
                            }));

                            // Create and forward a close frame
                            let close_frame = WebSocketFrame::close(code, &reason);
                            if let Ok(encoded) =
                                self.codec.encode_frame(&close_frame, !client_to_server)
                            {
                                output.extend_from_slice(&encoded);
                            }

                            // Remove consumed bytes and return
                            let _ = buf.split_to(consumed);
                            return ProcessResult::Close(CloseReason { code, reason });
                        }
                    }

                    // Remove consumed bytes from buffer
                    let _ = buf.split_to(consumed);
                }
                Ok(None) => {
                    // Need more data - incomplete frame
                    break;
                }
                Err(e) => {
                    // The frame cannot be read, so neither can anything
                    // after it, and no agent has seen it. Neither it nor
                    // what follows is forwarded: the connection is closed,
                    // whatever the agents' failure mode. The frames before
                    // it in this data were allowed, and go first.
                    let reason = CloseReason {
                        code: e.close_code(),
                        reason: e.close_reason().to_string(),
                    };
                    warn!(
                        correlation_id = %self.inspector.correlation_id(),
                        error = %e,
                        code = reason.code,
                        direction = if client_to_server { "c2s" } else { "s2c" },
                        "WebSocket frame could not be decoded, closing the connection"
                    );
                    *self.should_close.lock().await = Some(Closing::Undecodable(reason.clone()));
                    buf.clear();
                    return ProcessResult::Undecodable {
                        reason,
                        forward: output.freeze(),
                    };
                }
            }
        }

        if frames_processed > 0 {
            trace!(
                correlation_id = %self.inspector.correlation_id(),
                frames_processed = frames_processed,
                frames_dropped = frames_dropped,
                output_len = output.len(),
                buffer_remaining = buf.len(),
                direction = if client_to_server { "c2s" } else { "s2c" },
                "Processed WebSocket frames"
            );
        }

        if output.is_empty() && frames_dropped > 0 {
            // All frames were dropped, return empty
            ProcessResult::Forward(Some(Bytes::new()))
        } else if output.is_empty() {
            // No complete frames yet, buffer more data
            // Return empty bytes to signal "nothing to forward yet"
            ProcessResult::Forward(Some(Bytes::new()))
        } else {
            ProcessResult::Forward(Some(output.freeze()))
        }
    }

    /// Check if the connection should be closed
    pub async fn should_close(&self) -> Option<CloseReason> {
        self.should_close
            .lock()
            .await
            .as_ref()
            .map(|closing| closing.reason().clone())
    }

    /// The bytes of a close frame carrying `reason`.
    ///
    /// Control frames are small, so they are not held to the maximum frame
    /// size of data frames.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be encoded.
    pub fn close_frame(&self, reason: &CloseReason, masked: bool) -> std::io::Result<Vec<u8>> {
        let frame = WebSocketFrame::close(reason.code, &reason.reason);
        WebSocketCodec::new(usize::MAX).encode_frame(&frame, masked)
    }

    /// Get the correlation ID
    pub fn correlation_id(&self) -> &str {
        self.inspector.correlation_id()
    }
}

/// Builder for WebSocketHandler
pub struct WebSocketHandlerBuilder {
    inspector: Option<Arc<WebSocketInspector>>,
    max_frame_size: usize,
}

impl Default for WebSocketHandlerBuilder {
    fn default() -> Self {
        Self {
            inspector: None,
            max_frame_size: 1024 * 1024, // 1MB default
        }
    }
}

impl WebSocketHandlerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the inspector
    pub fn inspector(mut self, inspector: Arc<WebSocketInspector>) -> Self {
        self.inspector = Some(inspector);
        self
    }

    /// Set the maximum frame size
    pub fn max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Build the handler
    pub fn build(self) -> Option<WebSocketHandler> {
        Some(WebSocketHandler::new(self.inspector?, self.max_frame_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::websocket::codec::Opcode;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock inspector for testing that returns configurable decisions
    struct MockInspector {
        /// Decision to return for client frames
        client_decision: InspectionResult,
        /// Decision to return for server frames
        server_decision: InspectionResult,
        /// Count of inspected client frames
        client_frame_count: AtomicUsize,
        /// Count of inspected server frames
        server_frame_count: AtomicUsize,
    }

    impl MockInspector {
        fn new(client_decision: InspectionResult, server_decision: InspectionResult) -> Self {
            Self {
                client_decision,
                server_decision,
                client_frame_count: AtomicUsize::new(0),
                server_frame_count: AtomicUsize::new(0),
            }
        }

        fn allowing() -> Self {
            Self::new(InspectionResult::Allow, InspectionResult::Allow)
        }

        fn dropping_client() -> Self {
            Self::new(InspectionResult::Drop, InspectionResult::Allow)
        }

        fn dropping_server() -> Self {
            Self::new(InspectionResult::Allow, InspectionResult::Drop)
        }

        fn closing_client(code: u16, reason: &str) -> Self {
            Self::new(
                InspectionResult::Close {
                    code,
                    reason: reason.to_string(),
                },
                InspectionResult::Allow,
            )
        }

        fn client_frames_inspected(&self) -> usize {
            self.client_frame_count.load(Ordering::SeqCst)
        }

        fn server_frames_inspected(&self) -> usize {
            self.server_frame_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl FrameInspector for MockInspector {
        async fn inspect_client_frame(&self, _frame: &WebSocketFrame) -> InspectionResult {
            self.client_frame_count.fetch_add(1, Ordering::SeqCst);
            self.client_decision.clone()
        }

        async fn inspect_server_frame(&self, _frame: &WebSocketFrame) -> InspectionResult {
            self.server_frame_count.fetch_add(1, Ordering::SeqCst);
            self.server_decision.clone()
        }

        fn correlation_id(&self) -> &str {
            "test-correlation-id"
        }
    }

    /// Helper to create a text frame as bytes
    fn make_text_frame(text: &str, masked: bool) -> Bytes {
        let codec = WebSocketCodec::new(1024 * 1024);
        let frame = WebSocketFrame::new(Opcode::Text, text.as_bytes().to_vec());
        Bytes::from(codec.encode_frame(&frame, masked).unwrap())
    }

    #[test]
    fn test_close_reason() {
        let reason = CloseReason {
            code: 1000,
            reason: "Normal closure".to_string(),
        };
        assert_eq!(reason.code, 1000);
        assert_eq!(reason.reason, "Normal closure");
    }

    #[test]
    fn test_builder_defaults() {
        let builder = WebSocketHandlerBuilder::new();
        assert_eq!(builder.max_frame_size, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_frame_allow() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024 * 1024);

        // Send a text frame
        let frame_data = make_text_frame("Hello", false);
        let result = handler.process_client_data(Some(frame_data.clone())).await;

        match result {
            ProcessResult::Forward(Some(data)) => {
                // Frame should be forwarded as-is
                assert_eq!(data, frame_data);
            }
            _ => panic!("Expected Forward result"),
        }

        assert_eq!(inspector.client_frames_inspected(), 1);
    }

    #[tokio::test]
    async fn test_frame_drop_client() {
        let inspector = Arc::new(MockInspector::dropping_client());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024 * 1024);

        // Send a text frame
        let frame_data = make_text_frame("Hello", false);
        let result = handler.process_client_data(Some(frame_data)).await;

        match result {
            ProcessResult::Forward(Some(data)) => {
                // Frame should be dropped (empty output)
                assert!(data.is_empty(), "Dropped frame should produce empty output");
            }
            _ => panic!("Expected Forward with empty data"),
        }

        assert_eq!(inspector.client_frames_inspected(), 1);
    }

    #[tokio::test]
    async fn test_frame_drop_server() {
        let inspector = Arc::new(MockInspector::dropping_server());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024 * 1024);

        // Send a text frame from server
        let frame_data = make_text_frame("Server message", false);
        let result = handler.process_server_data(Some(frame_data)).await;

        match result {
            ProcessResult::Forward(Some(data)) => {
                // Frame should be dropped (empty output)
                assert!(data.is_empty(), "Dropped frame should produce empty output");
            }
            _ => panic!("Expected Forward with empty data"),
        }

        assert_eq!(inspector.server_frames_inspected(), 1);
    }

    #[tokio::test]
    async fn test_frame_close() {
        let inspector = Arc::new(MockInspector::closing_client(1008, "Policy violation"));
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024 * 1024);

        // Send a text frame
        let frame_data = make_text_frame("Malicious content", false);
        let result = handler.process_client_data(Some(frame_data)).await;

        match result {
            ProcessResult::Close(reason) => {
                assert_eq!(reason.code, 1008);
                assert_eq!(reason.reason, "Policy violation");
            }
            _ => panic!("Expected Close result"),
        }

        assert_eq!(inspector.client_frames_inspected(), 1);

        // Subsequent calls should also return Close
        let result = handler
            .process_client_data(Some(make_text_frame("More data", false)))
            .await;
        match result {
            ProcessResult::Close(_) => {}
            _ => panic!("Expected Close result on subsequent call"),
        }
    }

    #[tokio::test]
    async fn test_multiple_frames_mixed_decisions() {
        // Use allowing inspector for multiple frames
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024 * 1024);

        // Send first frame
        let frame1 = make_text_frame("Frame 1", false);
        let result = handler.process_client_data(Some(frame1.clone())).await;
        assert!(matches!(result, ProcessResult::Forward(Some(_))));

        // Send second frame
        let frame2 = make_text_frame("Frame 2", false);
        let result = handler.process_client_data(Some(frame2.clone())).await;
        assert!(matches!(result, ProcessResult::Forward(Some(_))));

        assert_eq!(inspector.client_frames_inspected(), 2);
    }

    #[tokio::test]
    async fn test_end_of_stream() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector, 1024 * 1024);

        // Send None to indicate end of stream
        let result = handler.process_client_data(None).await;
        match result {
            ProcessResult::Forward(None) => {}
            _ => panic!("Expected Forward(None) for end of stream"),
        }
    }

    #[tokio::test]
    async fn test_partial_frame_buffering() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024 * 1024);

        // Create a frame and split it
        let full_frame = make_text_frame("Hello World", false);
        let (part1, part2) = full_frame.split_at(full_frame.len() / 2);

        // Send first part - should return empty (buffering)
        let result = handler
            .process_client_data(Some(Bytes::from(part1.to_vec())))
            .await;
        match result {
            ProcessResult::Forward(Some(data)) => {
                assert!(data.is_empty(), "Partial frame should not produce output");
            }
            _ => panic!("Expected Forward with empty data for partial frame"),
        }
        assert_eq!(
            inspector.client_frames_inspected(),
            0,
            "Partial frame should not be inspected"
        );

        // Send second part - should return complete frame
        let result = handler
            .process_client_data(Some(Bytes::from(part2.to_vec())))
            .await;
        match result {
            ProcessResult::Forward(Some(data)) => {
                assert_eq!(data, full_frame, "Complete frame should be forwarded");
            }
            _ => panic!("Expected Forward with complete frame"),
        }
        assert_eq!(
            inspector.client_frames_inspected(),
            1,
            "Complete frame should be inspected"
        );
    }

    #[tokio::test]
    async fn test_bidirectional_independence() {
        // Client drops, server allows
        let inspector = Arc::new(MockInspector::new(
            InspectionResult::Drop,
            InspectionResult::Allow,
        ));
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024 * 1024);

        // Client frame should be dropped
        let client_frame = make_text_frame("Client", false);
        let result = handler.process_client_data(Some(client_frame)).await;
        match result {
            ProcessResult::Forward(Some(data)) => assert!(data.is_empty()),
            _ => panic!("Expected empty forward for dropped client frame"),
        }

        // Server frame should be allowed
        let server_frame = make_text_frame("Server", false);
        let original_len = server_frame.len();
        let result = handler.process_server_data(Some(server_frame)).await;
        match result {
            ProcessResult::Forward(Some(data)) => assert_eq!(data.len(), original_len),
            _ => panic!("Expected forward for allowed server frame"),
        }

        assert_eq!(inspector.client_frames_inspected(), 1);
        assert_eq!(inspector.server_frames_inspected(), 1);
    }

    /// The header of a frame that announces `len` payload bytes, and `sent` of
    /// them.
    fn frame_prefix(first_byte: u8, len: usize, sent: usize) -> Bytes {
        let mut data = vec![first_byte, 127];
        data.extend_from_slice(&(len as u64).to_be_bytes());
        data.extend(std::iter::repeat_n(b'x', sent));
        Bytes::from(data)
    }

    fn undecodable_with_forward(result: ProcessResult) -> (CloseReason, Bytes) {
        match result {
            ProcessResult::Undecodable { reason, forward } => (reason, forward),
            other => panic!("expected Undecodable, got {other:?}"),
        }
    }

    fn undecodable(result: ProcessResult) -> CloseReason {
        undecodable_with_forward(result).0
    }

    #[tokio::test]
    async fn a_frame_over_the_limit_closes_with_1009_in_both_directions() {
        for client_to_server in [true, false] {
            let inspector = Arc::new(MockInspector::allowing());
            let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024);

            let data = frame_prefix(0x82, 1025, 10);
            let result = if client_to_server {
                handler.process_client_data(Some(data)).await
            } else {
                handler.process_server_data(Some(data)).await
            };

            let reason = undecodable(result);
            assert_eq!(reason.code, 1009, "client_to_server: {client_to_server}");
            assert_eq!(reason.reason, "frame too large");
            assert_eq!(inspector.client_frames_inspected(), 0);
            assert_eq!(inspector.server_frames_inspected(), 0);
        }
    }

    #[tokio::test]
    async fn a_frame_with_an_rsv_bit_closes_with_1002_in_both_directions() {
        for client_to_server in [true, false] {
            let inspector = Arc::new(MockInspector::allowing());
            let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024);

            // RSV1 set, as in a compressed text frame.
            let data = Bytes::from_static(&[0xC1, 0x02, b'h', b'i']);
            let result = if client_to_server {
                handler.process_client_data(Some(data)).await
            } else {
                handler.process_server_data(Some(data)).await
            };

            let reason = undecodable(result);
            assert_eq!(reason.code, 1002, "client_to_server: {client_to_server}");
            assert_eq!(reason.reason, "unsupported RSV bits");
            assert_eq!(inspector.client_frames_inspected(), 0);
            assert_eq!(inspector.server_frames_inspected(), 0);
        }
    }

    #[tokio::test]
    async fn after_an_undecodable_frame_nothing_is_forwarded_or_inspected() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024);

        undecodable(
            handler
                .process_client_data(Some(frame_prefix(0x82, 2048, 16)))
                .await,
        );

        // What follows, in either direction, is not read as frames: the
        // rest of the oversized payload would parse as arbitrary headers.
        for _ in 0..2 {
            let reason = undecodable(
                handler
                    .process_client_data(Some(make_text_frame("after", true)))
                    .await,
            );
            assert_eq!(reason.code, 1009);
            let reason = undecodable(
                handler
                    .process_server_data(Some(make_text_frame("after", false)))
                    .await,
            );
            assert_eq!(reason.code, 1009);
        }
        assert_eq!(inspector.client_frames_inspected(), 0);
        assert_eq!(inspector.server_frames_inspected(), 0);
        assert_eq!(handler.should_close().await.map(|r| r.code), Some(1009));
    }

    #[tokio::test]
    async fn frames_before_an_undecodable_frame_are_inspected_and_forwarded_first() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024);

        let good = make_text_frame("fine", true);
        let mut data = good.to_vec();
        data.extend_from_slice(&[0xC1, 0x00]);
        data.extend_from_slice(&make_text_frame("after", true));
        let result = handler.process_client_data(Some(Bytes::from(data))).await;

        let (reason, forward) = undecodable_with_forward(result);
        assert_eq!(reason.code, 1002);
        assert_eq!(forward, good, "only the frame before the undecodable one");
        assert_eq!(inspector.client_frames_inspected(), 1);

        // Nothing is forwarded after that.
        let (_, forward) = undecodable_with_forward(
            handler
                .process_client_data(Some(make_text_frame("later", true)))
                .await,
        );
        assert!(forward.is_empty());
    }

    #[tokio::test]
    async fn a_frame_before_an_undecodable_frame_that_an_agent_dropped_is_not_forwarded() {
        let inspector = Arc::new(MockInspector::dropping_client());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 1024);

        let mut data = make_text_frame("dropped", true).to_vec();
        data.extend_from_slice(&[0xC1, 0x00]);
        let result = handler.process_client_data(Some(Bytes::from(data))).await;

        let (_, forward) = undecodable_with_forward(result);
        assert!(forward.is_empty());
        assert_eq!(inspector.client_frames_inspected(), 1);
    }

    #[tokio::test]
    async fn an_undecodable_frame_split_across_chunks_is_reported_once_its_header_is_read() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector, 1024);

        // One byte of a header cannot be judged yet.
        let result = handler
            .process_client_data(Some(Bytes::from_static(&[0xC1])))
            .await;
        assert!(matches!(result, ProcessResult::Forward(Some(ref data)) if data.is_empty()));

        let result = handler
            .process_client_data(Some(Bytes::from_static(&[0x80])))
            .await;
        assert_eq!(undecodable(result).code, 1002);
    }

    #[tokio::test]
    async fn a_frame_of_exactly_the_limit_is_inspected_and_forwarded() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector.clone(), 5);

        let frame = make_text_frame("Hello", false);
        let result = handler.process_client_data(Some(frame.clone())).await;

        assert!(matches!(result, ProcessResult::Forward(Some(ref data)) if *data == frame));
        assert_eq!(inspector.client_frames_inspected(), 1);
    }

    #[tokio::test]
    async fn a_close_frame_is_not_held_to_the_frame_size_limit() {
        let inspector = Arc::new(MockInspector::allowing());
        let handler = WebSocketHandler::with_inspector(inspector, 1);
        let reason = CloseReason {
            code: 1009,
            reason: "frame too large".to_string(),
        };

        let bytes = handler.close_frame(&reason, false).unwrap();

        let codec = WebSocketCodec::new(1024);
        let (frame, consumed) = codec
            .decode_frame(&BytesMut::from(&bytes[..]))
            .unwrap()
            .unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(
            frame.close_code_and_reason(),
            Some((1009, "frame too large".to_string()))
        );
    }
}
