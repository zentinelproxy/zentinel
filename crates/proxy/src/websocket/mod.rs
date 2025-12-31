//! WebSocket frame handling for frame-level inspection.
//!
//! This module provides WebSocket frame parsing and encoding per RFC 6455,
//! enabling agents to inspect individual WebSocket frames for security purposes.
//!
//! # Architecture
//!
//! After a WebSocket upgrade (101 response), Sentinel can optionally intercept
//! the bidirectional byte stream and parse it into frames for inspection:
//!
//! ```text
//! Client <-> [Frame Parser] <-> Sentinel <-> [Frame Parser] <-> Upstream
//!                 |                                |
//!                 v                                v
//!          WebSocketFrame                   WebSocketFrame
//!                          \               /
//!                           v             v
//!                        Agent Inspector
//!                     (Allow/Drop/Close)
//! ```
//!
//! # Features
//!
//! - RFC 6455 compliant frame parsing
//! - Masking/unmasking support (client frames are masked)
//! - Configurable maximum frame size
//! - Frame-level agent inspection

pub mod codec;
pub mod inspector;
pub mod proxy;

pub use codec::{Opcode, WebSocketCodec, WebSocketFrame};
pub use inspector::{InspectionResult, WebSocketInspector};
pub use proxy::{CloseReason, FrameInspector, ProcessResult, WebSocketHandler};
