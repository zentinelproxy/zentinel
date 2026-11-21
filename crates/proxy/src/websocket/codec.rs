//! WebSocket frame codec implementing RFC 6455.
//!
//! Provides frame parsing and encoding for WebSocket connections.

use bytes::{Buf, BufMut, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};
use tracing::trace;

/// Maximum allowed frame size (1MB default)
pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Why [`WebSocketCodec::decode_frame`] could not decode a frame.
///
/// Neither is recoverable: the frame cannot be read, so the position of the
/// next one in the stream is unknown. The connection has to be closed, with
/// the status [`FrameError::close_code`] gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The payload is larger than the maximum frame size.
    #[error("Frame size {size} exceeds maximum {max}")]
    TooLarge {
        /// The payload size the frame header announced.
        size: usize,
        /// The maximum frame size.
        max: usize,
    },
    /// An RSV bit is set. The proxy negotiates no extension, so none may be.
    #[error("Non-zero RSV bits without extension")]
    ReservedBits,
}

impl FrameError {
    /// The close status code (RFC 6455, section 7.4.1) for this error:
    /// 1009 (message too big) or 1002 (protocol error).
    pub fn close_code(&self) -> u16 {
        match self {
            Self::TooLarge { .. } => 1009,
            Self::ReservedBits => 1002,
        }
    }

    /// A short reason for the close frame.
    pub fn close_reason(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "frame too large",
            Self::ReservedBits => "unsupported RSV bits",
        }
    }
}

impl From<FrameError> for io::Error {
    fn from(error: FrameError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

/// WebSocket frame opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// Continuation frame (0x0)
    Continuation,
    /// Text frame (0x1)
    Text,
    /// Binary frame (0x2)
    Binary,
    /// Connection close (0x8)
    Close,
    /// Ping (0x9)
    Ping,
    /// Pong (0xA)
    Pong,
    /// Reserved/unknown opcode
    Reserved(u8),
}

impl Opcode {
    /// Parse opcode from byte value
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            other => Self::Reserved(other),
        }
    }

    /// Convert to byte value
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
            Self::Reserved(v) => *v,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Continuation => "continuation",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Reserved(_) => "reserved",
        }
    }

    /// Check if this is a control frame
    pub fn is_control(&self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    /// Check if this is a data frame
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Continuation | Self::Text | Self::Binary)
    }
}

/// A parsed WebSocket frame
#[derive(Debug, Clone)]
pub struct WebSocketFrame {
    /// FIN bit - true if this is the final frame of a message
    pub fin: bool,
    /// Frame opcode
    pub opcode: Opcode,
    /// Masking key (only for client-to-server frames)
    pub mask: Option<[u8; 4]>,
    /// Frame payload data (unmasked)
    pub payload: Vec<u8>,
}

impl WebSocketFrame {
    /// Create a new frame
    pub fn new(opcode: Opcode, payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode,
            mask: None,
            payload,
        }
    }

    /// Create a close frame
    pub fn close(code: u16, reason: &str) -> Self {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        Self {
            fin: true,
            opcode: Opcode::Close,
            mask: None,
            payload,
        }
    }

    /// Create a ping frame
    pub fn ping(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: Opcode::Ping,
            mask: None,
            payload: data,
        }
    }

    /// Create a pong frame
    pub fn pong(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: Opcode::Pong,
            mask: None,
            payload: data,
        }
    }

    /// Set the masking key (for client frames)
    pub fn with_mask(mut self, mask: [u8; 4]) -> Self {
        self.mask = Some(mask);
        self
    }

    /// Set the FIN bit
    pub fn with_fin(mut self, fin: bool) -> Self {
        self.fin = fin;
        self
    }

    /// Parse close code and reason from payload
    pub fn close_code_and_reason(&self) -> Option<(u16, String)> {
        if self.opcode != Opcode::Close || self.payload.len() < 2 {
            return None;
        }
        let code = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        let reason = if self.payload.len() > 2 {
            String::from_utf8_lossy(&self.payload[2..]).to_string()
        } else {
            String::new()
        };
        Some((code, reason))
    }
}

/// WebSocket frame codec for tokio streams
///
/// Handles parsing and encoding of WebSocket frames per RFC 6455.
pub struct WebSocketCodec {
    /// Maximum allowed frame size
    max_frame_size: usize,
    /// Whether we expect masked frames (true for server receiving from client)
    expect_masked: bool,
    /// Whether we should mask outgoing frames (true for client sending to server)
    mask_outgoing: bool,
}

impl WebSocketCodec {
    /// Create a new codec with specified max frame size.
    ///
    /// Uses permissive settings for proxy use:
    /// - Does not enforce masking (handles both masked and unmasked)
    /// - Does not mask outgoing frames
    pub fn new(max_frame_size: usize) -> Self {
        Self {
            max_frame_size,
            expect_masked: false, // Permissive for proxy
            mask_outgoing: false,
        }
    }

    /// Create a new codec for server-side use (receiving client frames)
    ///
    /// - Expects masked frames from client
    /// - Does not mask frames to client
    pub fn server() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            expect_masked: true,
            mask_outgoing: false,
        }
    }

    /// Create a new codec for client-side use (sending to server)
    ///
    /// - Does not expect masked frames from server
    /// - Masks frames to server
    pub fn client() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            expect_masked: false,
            mask_outgoing: true,
        }
    }

    /// Set maximum frame size
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Apply XOR mask to data in-place
    fn apply_mask(data: &mut [u8], mask: [u8; 4]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }

    /// Decode a frame from a byte slice, returning the frame and bytes consumed.
    ///
    /// This is a non-mutating version for use with the proxy handler.
    /// Returns `Ok(None)` if more data is needed.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::ReservedBits`] if an RSV bit is set, and
    /// [`FrameError::TooLarge`] if the header announces a payload larger than
    /// the maximum frame size. Both are reported as soon as the header is
    /// read, before the payload has arrived.
    pub fn decode_frame(
        &self,
        src: &BytesMut,
    ) -> Result<Option<(WebSocketFrame, usize)>, FrameError> {
        // Need at least 2 bytes for the header
        if src.len() < 2 {
            return Ok(None);
        }

        // Parse first two bytes
        let first_byte = src[0];
        let second_byte = src[1];

        let fin = (first_byte & 0x80) != 0;
        let rsv = (first_byte & 0x70) >> 4;
        let opcode = Opcode::from_u8(first_byte & 0x0F);
        let masked = (second_byte & 0x80) != 0;
        let payload_len_byte = second_byte & 0x7F;

        // Check RSV bits (must be 0 unless extension negotiated)
        if rsv != 0 {
            return Err(FrameError::ReservedBits);
        }

        // Calculate header size and payload length
        let (header_size, payload_len) = match payload_len_byte {
            0..=125 => (2, payload_len_byte as usize),
            126 => {
                if src.len() < 4 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([src[2], src[3]]) as usize;
                (4, len)
            }
            127 => {
                if src.len() < 10 {
                    return Ok(None);
                }
                let len = u64::from_be_bytes([
                    src[2], src[3], src[4], src[5], src[6], src[7], src[8], src[9],
                ]);
                // A length that does not fit in usize is over any limit.
                (10, usize::try_from(len).unwrap_or(usize::MAX))
            }
            _ => unreachable!(),
        };

        // Check frame size limit
        if payload_len > self.max_frame_size {
            return Err(FrameError::TooLarge {
                size: payload_len,
                max: self.max_frame_size,
            });
        }

        // Calculate total frame size
        let mask_size = if masked { 4 } else { 0 };
        let total_size = header_size + mask_size + payload_len;

        // Wait for complete frame
        if src.len() < total_size {
            return Ok(None);
        }

        // Extract masking key if present
        let mask = if masked {
            let mask_start = header_size;
            Some([
                src[mask_start],
                src[mask_start + 1],
                src[mask_start + 2],
                src[mask_start + 3],
            ])
        } else {
            None
        };

        // Extract and unmask payload
        let payload_start = header_size + mask_size;
        let mut payload = src[payload_start..payload_start + payload_len].to_vec();
        if let Some(m) = mask {
            Self::apply_mask(&mut payload, m);
        }

        Ok(Some((
            WebSocketFrame {
                fin,
                opcode,
                mask,
                payload,
            },
            total_size,
        )))
    }

    /// Encode a frame to bytes.
    ///
    /// If `masked` is true, the frame will be masked with a random key.
    pub fn encode_frame(
        &self,
        frame: &WebSocketFrame,
        masked: bool,
    ) -> Result<Vec<u8>, std::io::Error> {
        let payload_len = frame.payload.len();

        // Check frame size
        if payload_len > self.max_frame_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Frame size {} exceeds maximum {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        // Calculate sizes
        let header_len: usize = match payload_len {
            0..=125 => 2,
            126..=65535 => 4,
            _ => 10,
        };
        let mask_len = if masked { 4 } else { 0 };
        let total_len = header_len + mask_len + payload_len;

        let mut dst = Vec::with_capacity(total_len);

        // First byte: FIN + RSV (0) + opcode
        let first_byte = (if frame.fin { 0x80 } else { 0x00 }) | (frame.opcode.as_u8() & 0x0F);
        dst.push(first_byte);

        // Second byte: MASK + payload length
        let mask_bit = if masked { 0x80 } else { 0x00 };
        match payload_len {
            0..=125 => {
                dst.push(mask_bit | (payload_len as u8));
            }
            126..=65535 => {
                dst.push(mask_bit | 126);
                dst.extend_from_slice(&(payload_len as u16).to_be_bytes());
            }
            _ => {
                dst.push(mask_bit | 127);
                dst.extend_from_slice(&(payload_len as u64).to_be_bytes());
            }
        }

        // Masking key and payload
        if masked {
            let mask: [u8; 4] = rand::random();
            dst.extend_from_slice(&mask);
            let mut masked_payload = frame.payload.clone();
            Self::apply_mask(&mut masked_payload, mask);
            dst.extend_from_slice(&masked_payload);
        } else {
            dst.extend_from_slice(&frame.payload);
        }

        Ok(dst)
    }
}

impl Decoder for WebSocketCodec {
    type Item = WebSocketFrame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 2 bytes for the header
        if src.len() < 2 {
            return Ok(None);
        }

        // Parse first two bytes
        let first_byte = src[0];
        let second_byte = src[1];

        let fin = (first_byte & 0x80) != 0;
        let rsv = (first_byte & 0x70) >> 4;
        let opcode = Opcode::from_u8(first_byte & 0x0F);
        let masked = (second_byte & 0x80) != 0;
        let payload_len_byte = second_byte & 0x7F;

        // Check RSV bits (must be 0 unless extension negotiated)
        if rsv != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Non-zero RSV bits without extension",
            ));
        }

        // Check masking requirement
        if self.expect_masked && !masked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected masked frame from client",
            ));
        }
        if !self.expect_masked && masked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected masked frame from server",
            ));
        }

        // Calculate header size and payload length
        let (header_size, payload_len) = match payload_len_byte {
            0..=125 => (2, payload_len_byte as usize),
            126 => {
                if src.len() < 4 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([src[2], src[3]]) as usize;
                (4, len)
            }
            127 => {
                if src.len() < 10 {
                    return Ok(None);
                }
                let len = u64::from_be_bytes([
                    src[2], src[3], src[4], src[5], src[6], src[7], src[8], src[9],
                ]) as usize;
                (10, len)
            }
            _ => unreachable!(),
        };

        // Check frame size limit
        if payload_len > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Frame size {} exceeds maximum {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        // Calculate total frame size
        let mask_size = if masked { 4 } else { 0 };
        let total_size = header_size + mask_size + payload_len;

        // Wait for complete frame
        if src.len() < total_size {
            src.reserve(total_size - src.len());
            return Ok(None);
        }

        // Extract masking key if present
        let mask = if masked {
            let mask_start = header_size;
            Some([
                src[mask_start],
                src[mask_start + 1],
                src[mask_start + 2],
                src[mask_start + 3],
            ])
        } else {
            None
        };

        // Extract and unmask payload
        let payload_start = header_size + mask_size;
        let mut payload = src[payload_start..payload_start + payload_len].to_vec();
        if let Some(m) = mask {
            Self::apply_mask(&mut payload, m);
        }

        // Consume the frame from the buffer
        src.advance(total_size);

        trace!(
            fin = fin,
            opcode = ?opcode,
            masked = masked,
            payload_len = payload_len,
            "Decoded WebSocket frame"
        );

        Ok(Some(WebSocketFrame {
            fin,
            opcode,
            mask,
            payload,
        }))
    }
}

impl Encoder<WebSocketFrame> for WebSocketCodec {
    type Error = io::Error;

    fn encode(&mut self, frame: WebSocketFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = frame.payload.len();

        // Check frame size
        if payload_len > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Frame size {} exceeds maximum {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        // Calculate header size
        let (header_len, extended_len_bytes): (usize, usize) = match payload_len {
            0..=125 => (2, 0),
            126..=65535 => (4, 2),
            _ => (10, 8),
        };

        let should_mask = self.mask_outgoing;
        let mask_len = if should_mask { 4 } else { 0 };
        let total_len = header_len + mask_len + payload_len;

        dst.reserve(total_len);

        // First byte: FIN + RSV (0) + opcode
        let first_byte = (if frame.fin { 0x80 } else { 0x00 }) | (frame.opcode.as_u8() & 0x0F);
        dst.put_u8(first_byte);

        // Second byte: MASK + payload length
        let mask_bit = if should_mask { 0x80 } else { 0x00 };
        match payload_len {
            0..=125 => {
                dst.put_u8(mask_bit | (payload_len as u8));
            }
            126..=65535 => {
                dst.put_u8(mask_bit | 126);
                dst.put_u16(payload_len as u16);
            }
            _ => {
                dst.put_u8(mask_bit | 127);
                dst.put_u64(payload_len as u64);
            }
        }

        // Masking key and payload
        if should_mask {
            // Generate random mask
            let mask: [u8; 4] = rand::random();
            dst.put_slice(&mask);

            // Mask and write payload
            let mut masked_payload = frame.payload;
            Self::apply_mask(&mut masked_payload, mask);
            dst.put_slice(&masked_payload);
        } else {
            dst.put_slice(&frame.payload);
        }

        trace!(
            fin = frame.fin,
            opcode = ?frame.opcode,
            masked = should_mask,
            payload_len = payload_len,
            "Encoded WebSocket frame"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_round_trip() {
        for i in 0..=15 {
            let opcode = Opcode::from_u8(i);
            if !matches!(opcode, Opcode::Reserved(_)) {
                assert_eq!(opcode.as_u8(), i);
            }
        }
    }

    #[test]
    fn test_decode_unmasked_text_frame() {
        let mut codec = WebSocketCodec {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            expect_masked: false,
            mask_outgoing: false,
        };

        // FIN=1, opcode=text, no mask, len=5, payload="Hello"
        let data = [0x81, 0x05, b'H', b'e', b'l', b'l', b'o'];
        let mut buf = BytesMut::from(&data[..]);

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload, b"Hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_masked_text_frame() {
        let mut codec = WebSocketCodec::server();

        // FIN=1, opcode=text, masked, len=5, mask + masked payload
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let payload = b"Hello";
        let mut masked_payload = payload.to_vec();
        WebSocketCodec::apply_mask(&mut masked_payload, mask);

        let mut data = vec![0x81, 0x85]; // FIN + opcode, mask bit + len
        data.extend_from_slice(&mask);
        data.extend_from_slice(&masked_payload);

        let mut buf = BytesMut::from(&data[..]);
        let frame = codec.decode(&mut buf).unwrap().unwrap();

        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload, b"Hello");
    }

    #[test]
    fn test_decode_close_frame() {
        let mut codec = WebSocketCodec {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            expect_masked: false,
            mask_outgoing: false,
        };

        // FIN=1, opcode=close, no mask, len=2, code=1000
        let data = [0x88, 0x02, 0x03, 0xE8];
        let mut buf = BytesMut::from(&data[..]);

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Close);
        let (code, reason) = frame.close_code_and_reason().unwrap();
        assert_eq!(code, 1000);
        assert!(reason.is_empty());
    }

    #[test]
    fn test_encode_text_frame() {
        let mut codec = WebSocketCodec {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            expect_masked: false,
            mask_outgoing: false,
        };

        let frame = WebSocketFrame::new(Opcode::Text, b"Hello".to_vec());
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        assert_eq!(&buf[..], &[0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_frame_size_limit() {
        let mut codec = WebSocketCodec {
            max_frame_size: 10,
            expect_masked: false,
            mask_outgoing: false,
        };

        // Try to decode a frame claiming 100 bytes
        let data = [0x81, 0x64]; // len=100
        let mut buf = BytesMut::from(&data[..]);

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_frame_reports_a_frame_over_the_limit_from_its_header_alone() {
        let codec = WebSocketCodec::new(10);

        // A header that announces 100 bytes, and none of them yet.
        let buf = BytesMut::from(&[0x81, 0x64][..]);
        let error = codec.decode_frame(&buf).unwrap_err();

        assert_eq!(error, FrameError::TooLarge { size: 100, max: 10 });
        assert_eq!(error.close_code(), 1009);
        assert_eq!(error.to_string(), "Frame size 100 exceeds maximum 10");
    }

    #[test]
    fn decode_frame_reports_the_largest_64_bit_length_as_too_large() {
        let codec = WebSocketCodec::new(DEFAULT_MAX_FRAME_SIZE);

        let mut header = vec![0x82, 127];
        header.extend_from_slice(&u64::MAX.to_be_bytes());
        let error = codec
            .decode_frame(&BytesMut::from(&header[..]))
            .unwrap_err();

        assert!(matches!(error, FrameError::TooLarge { .. }), "{error:?}");
        assert_eq!(error.close_code(), 1009);
    }

    #[test]
    fn decode_frame_accepts_a_frame_of_exactly_the_limit() {
        let codec = WebSocketCodec::new(5);

        let buf = BytesMut::from(&[0x81, 0x05, b'H', b'e', b'l', b'l', b'o'][..]);
        let (frame, consumed) = codec.decode_frame(&buf).unwrap().unwrap();

        assert_eq!(frame.payload, b"Hello");
        assert_eq!(consumed, 7);
    }

    #[test]
    fn decode_frame_reports_each_rsv_bit_as_a_protocol_error() {
        let codec = WebSocketCodec::new(DEFAULT_MAX_FRAME_SIZE);

        // RSV1 is what a compressed frame sets; RSV2 and RSV3 are reserved.
        for first_byte in [0xC1u8, 0xA1, 0x91] {
            let buf = BytesMut::from(&[first_byte, 0x00][..]);
            let error = codec.decode_frame(&buf).unwrap_err();

            assert_eq!(error, FrameError::ReservedBits, "{first_byte:#x}");
            assert_eq!(error.close_code(), 1002);
        }
    }

    #[test]
    fn frame_error_becomes_an_invalid_data_io_error_with_its_message() {
        let error = io::Error::from(FrameError::ReservedBits);

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "Non-zero RSV bits without extension");
    }

    #[test]
    fn test_close_frame_construction() {
        let frame = WebSocketFrame::close(1001, "Going away");
        assert_eq!(frame.opcode, Opcode::Close);

        let (code, reason) = frame.close_code_and_reason().unwrap();
        assert_eq!(code, 1001);
        assert_eq!(reason, "Going away");
    }
}
