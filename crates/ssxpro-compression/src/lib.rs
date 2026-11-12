#![forbid(unsafe_code)]

//! Bounded block compression for the stream-4 PTY byte stream.
//!
//! The compression algorithm is selected by the server during `Hello`/`AuthChallenge`
//! negotiation. Once compression is enabled, every stream-4 payload after the
//! one-byte open marker is a sequence of self-contained frames:
//!
//! ```text
//! format:u8 | uncompressed_len:u32be | payload_len:u32be | payload[payload_len]
//! ```
//!
//! `format` is 0 for a stored block and 1 for a block compressed with the
//! negotiated algorithm. A stored block always has `payload_len ==
//! uncompressed_len`. Blocks are bounded so a peer can never force an
//! unbounded allocation, and every frame is decoded independently.

use ssxpro_proto::Compression;
use std::fmt;

/// Largest uncompressed block produced or accepted by this module.
pub const MAX_BLOCK_SIZE: usize = 64 * 1024;
/// Bound for any compressed or stored payload. Zstd's worst-case expansion for
/// a 64 KiB block is comfortably below this.
pub const MAX_COMPRESSED_BLOCK: usize = 128 * 1024;
/// `format:u8`, `uncompressed_len:u32`, `payload_len:u32`.
pub const FRAME_HEADER_LEN: usize = 9;
/// Largest complete frame accepted by the decoder.
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_COMPRESSED_BLOCK;

const FORMAT_STORED: u8 = 0;
const FORMAT_COMPRESSED: u8 = 1;
const ZSTD_HIGH_LEVEL: i32 = 19;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    Unsupported(Compression),
    InvalidFormat(u8),
    InvalidLength,
    TruncatedFrame,
    Compressor(String),
    Decompressor(String),
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(compression) => {
                write!(f, "compression {compression:?} does not use framed blocks")
            }
            Self::InvalidFormat(format) => write!(f, "unknown compression block format {format}"),
            Self::InvalidLength => f.write_str("invalid compression block length"),
            Self::TruncatedFrame => f.write_str("truncated compressed stream"),
            Self::Compressor(message) => write!(f, "compression failed: {message}"),
            Self::Decompressor(message) => write!(f, "decompression failed: {message}"),
        }
    }
}

impl std::error::Error for CompressionError {}

/// Per-direction compressor. Zstd keeps its context so level 19 does not pay
/// context-creation cost for every PTY read; LZ4 and Snappy are stateless.
pub struct Encoder {
    compression: Compression,
    zstd: Option<zstd::bulk::Compressor<'static>>,
    snappy: Option<snap::raw::Encoder>,
    scratch: Vec<u8>,
}

impl Encoder {
    pub fn new(compression: Compression) -> Result<Self, CompressionError> {
        let mut encoder = Self {
            compression,
            zstd: None,
            snappy: None,
            scratch: Vec::new(),
        };
        match compression {
            Compression::Off => return Err(CompressionError::Unsupported(compression)),
            Compression::Fast => {}
            Compression::Standard => {
                encoder.snappy = Some(snap::raw::Encoder::new());
            }
            Compression::High => {
                encoder.zstd = Some(
                    zstd::bulk::Compressor::new(ZSTD_HIGH_LEVEL)
                        .map_err(|error| CompressionError::Compressor(error.to_string()))?,
                );
            }
        }
        Ok(encoder)
    }

    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Encode `input` as one or more complete frames. Empty input produces no
    /// bytes; the stream FIN is the end-of-stream signal.
    pub fn encode(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = Vec::with_capacity(
            input
                .len()
                .saturating_add(input.len() / 8)
                .saturating_add(FRAME_HEADER_LEN),
        );
        for block in input.chunks(MAX_BLOCK_SIZE) {
            self.encode_block(block, &mut output)?;
        }
        Ok(output)
    }

    fn encode_block(&mut self, block: &[u8], output: &mut Vec<u8>) -> Result<(), CompressionError> {
        debug_assert!(!block.is_empty() && block.len() <= MAX_BLOCK_SIZE);
        let compressed = match self.compression {
            Compression::Fast => {
                let bound = lz4_flex::block::get_maximum_output_size(block.len());
                self.scratch.resize(bound, 0);
                let length = lz4_flex::block::compress_into(block, &mut self.scratch)
                    .map_err(|error| CompressionError::Compressor(error.to_string()))?;
                self.scratch.truncate(length);
                length
            }
            Compression::Standard => {
                let bound = snap::raw::max_compress_len(block.len());
                self.scratch.resize(bound, 0);
                let length = self
                    .snappy
                    .as_mut()
                    .expect("Snappy encoder is initialized")
                    .compress(block, &mut self.scratch)
                    .map_err(|error| CompressionError::Compressor(error.to_string()))?;
                self.scratch.truncate(length);
                length
            }
            Compression::High => {
                let bound = zstd::zstd_safe::compress_bound(block.len());
                self.scratch.clear();
                self.scratch.reserve(bound);
                let length = self
                    .zstd
                    .as_mut()
                    .expect("Zstd encoder is initialized")
                    .compress_to_buffer(block, &mut self.scratch)
                    .map_err(|error| CompressionError::Compressor(error.to_string()))?;
                length
            }
            Compression::Off => return Err(CompressionError::Unsupported(Compression::Off)),
        };
        if compressed >= block.len() {
            write_frame(output, FORMAT_STORED, block, block)?;
        } else {
            write_frame(
                output,
                FORMAT_COMPRESSED,
                block,
                &self.scratch[..compressed],
            )?;
        }
        Ok(())
    }
}

fn write_frame(
    output: &mut Vec<u8>,
    format: u8,
    uncompressed: &[u8],
    payload: &[u8],
) -> Result<(), CompressionError> {
    if uncompressed.is_empty()
        || uncompressed.len() > MAX_BLOCK_SIZE
        || payload.is_empty()
        || payload.len() > MAX_COMPRESSED_BLOCK
        || (format == FORMAT_STORED && payload.len() != uncompressed.len())
    {
        return Err(CompressionError::InvalidLength);
    }
    output.push(format);
    output.extend_from_slice(&(uncompressed.len() as u32).to_be_bytes());
    output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

/// Per-direction decompressor. Incoming QUIC stream bytes may be fragmented at
/// arbitrary boundaries, so incomplete frames are retained until complete.
pub struct Decoder {
    compression: Compression,
    zstd: Option<zstd::bulk::Decompressor<'static>>,
    snappy: Option<snap::raw::Decoder>,
    partial: Vec<u8>,
    scratch: Vec<u8>,
}

impl Decoder {
    pub fn new(compression: Compression) -> Result<Self, CompressionError> {
        let mut decoder = Self {
            compression,
            zstd: None,
            snappy: None,
            partial: Vec::new(),
            scratch: Vec::new(),
        };
        match compression {
            Compression::Off => return Err(CompressionError::Unsupported(compression)),
            Compression::Fast => {}
            Compression::Standard => {
                decoder.snappy = Some(snap::raw::Decoder::new());
            }
            Compression::High => {
                let mut zstd = zstd::bulk::Decompressor::new()
                    .map_err(|error| CompressionError::Decompressor(error.to_string()))?;
                // Our encoder never needs a window larger than one block;
                // rejecting larger windows denies crafted frames an oversized
                // internal allocation.
                zstd.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(
                    MAX_BLOCK_SIZE.trailing_zeros(),
                ))
                .map_err(|error| CompressionError::Decompressor(error.to_string()))?;
                decoder.zstd = Some(zstd);
            }
        }
        Ok(decoder)
    }

    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Decode every complete frame in the newly supplied bytes and append the
    /// decompressed data to `output`.
    pub fn push(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<(), CompressionError> {
        self.push_bounded(input, output, usize::MAX).map(|_| ())
    }

    /// Append at most `capacity` decoded bytes. Returns true if a complete
    /// frame is retained for lack of output space. While true, callers must
    /// drain output and retry with empty input before supplying more bytes.
    pub fn push_bounded(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        capacity: usize,
    ) -> Result<bool, CompressionError> {
        let initial_len = output.len();
        let mut blocked = false;
        // Move the partial frame buffer out so decoded payload slices do not
        // overlap the mutable codec state.
        let mut partial = std::mem::take(&mut self.partial);
        partial.extend_from_slice(input);
        let mut offset = 0;
        loop {
            let remaining = &partial[offset..];
            if remaining.len() < FRAME_HEADER_LEN {
                break;
            }
            let format = remaining[0];
            let uncompressed_len = u32::from_be_bytes(
                remaining[1..5]
                    .try_into()
                    .expect("four-byte uncompressed length"),
            ) as usize;
            let payload_len = u32::from_be_bytes(
                remaining[5..9]
                    .try_into()
                    .expect("four-byte payload length"),
            ) as usize;
            if uncompressed_len == 0
                || uncompressed_len > MAX_BLOCK_SIZE
                || payload_len == 0
                || payload_len > MAX_COMPRESSED_BLOCK
            {
                return Err(CompressionError::InvalidLength);
            }
            let total_len = FRAME_HEADER_LEN
                .checked_add(payload_len)
                .ok_or(CompressionError::InvalidLength)?;
            if remaining.len() < total_len {
                break;
            }
            if uncompressed_len > capacity.saturating_sub(output.len() - initial_len) {
                blocked = true;
                break;
            }
            let payload = &remaining[FRAME_HEADER_LEN..total_len];
            match format {
                FORMAT_STORED => {
                    if payload_len != uncompressed_len {
                        return Err(CompressionError::InvalidLength);
                    }
                    output.extend_from_slice(payload);
                }
                FORMAT_COMPRESSED => {
                    self.decompress(payload, uncompressed_len, output)?;
                }
                other => return Err(CompressionError::InvalidFormat(other)),
            }
            offset += total_len;
        }
        if offset > 0 {
            partial.drain(..offset);
        }
        if !blocked && partial.len() > MAX_FRAME_LEN {
            return Err(CompressionError::InvalidLength);
        }
        self.partial = partial;
        Ok(blocked)
    }

    /// Verify that the peer ended on a frame boundary.
    pub fn finish(&self) -> Result<(), CompressionError> {
        if self.partial.is_empty() {
            Ok(())
        } else {
            Err(CompressionError::TruncatedFrame)
        }
    }

    fn decompress(
        &mut self,
        payload: &[u8],
        uncompressed_len: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), CompressionError> {
        match self.compression {
            Compression::Fast => {
                self.scratch.resize(uncompressed_len, 0);
                let length = lz4_flex::block::decompress_into(payload, &mut self.scratch)
                    .map_err(|error| CompressionError::Decompressor(error.to_string()))?;
                if length != uncompressed_len {
                    return Err(CompressionError::Decompressor(
                        "LZ4 output length mismatch".to_owned(),
                    ));
                }
                output.extend_from_slice(&self.scratch[..length]);
            }
            Compression::Standard => {
                self.scratch.resize(uncompressed_len, 0);
                let length = self
                    .snappy
                    .as_mut()
                    .expect("Snappy decoder is initialized")
                    .decompress(payload, &mut self.scratch)
                    .map_err(|error| CompressionError::Decompressor(error.to_string()))?;
                if length != uncompressed_len {
                    return Err(CompressionError::Decompressor(
                        "Snappy output length mismatch".to_owned(),
                    ));
                }
                output.extend_from_slice(&self.scratch[..length]);
            }
            Compression::High => {
                self.scratch.clear();
                self.scratch.reserve(uncompressed_len);
                let length = self
                    .zstd
                    .as_mut()
                    .expect("Zstd decoder is initialized")
                    .decompress_to_buffer(payload, &mut self.scratch)
                    .map_err(|error| CompressionError::Decompressor(error.to_string()))?;
                if length != uncompressed_len {
                    return Err(CompressionError::Decompressor(
                        "Zstd output length mismatch".to_owned(),
                    ));
                }
                output.extend_from_slice(&self.scratch[..length]);
            }
            Compression::Off => return Err(CompressionError::Unsupported(Compression::Off)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(compression: Compression, data: &[u8]) {
        let mut encoder = Encoder::new(compression).unwrap();
        let mut decoder = Decoder::new(compression).unwrap();
        let encoded = encoder.encode(data).unwrap();
        let mut decoded = Vec::new();
        decoder.push(&encoded, &mut decoded).unwrap();
        decoder.finish().unwrap();
        assert_eq!(decoded, data, "{compression:?}");
    }

    #[test]
    fn all_algorithms_round_trip_repetitive_and_random_data() {
        let mut random = Vec::new();
        let mut state = 0x1234_5678u32;
        for _ in 0..(MAX_BLOCK_SIZE * 2 + 37) {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            random.push((state >> 24) as u8);
        }
        let repetitive = vec![b'x'; MAX_BLOCK_SIZE + 3];
        for compression in [Compression::Fast, Compression::Standard, Compression::High] {
            round_trip(compression, b"");
            round_trip(compression, b"a");
            round_trip(compression, b"hello, terminal\r\n");
            round_trip(compression, &repetitive);
            round_trip(compression, &random);
        }
    }

    #[test]
    fn incompressible_data_uses_stored_blocks() {
        let mut data = Vec::new();
        let mut state = 0x9e37_79b9u32;
        for _ in 0..1024 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((state >> 24) as u8);
        }
        let mut encoder = Encoder::new(Compression::Fast).unwrap();
        let encoded = encoder.encode(&data).unwrap();
        assert_eq!(encoded[0], FORMAT_STORED);
        let uncompressed_len = u32::from_be_bytes(encoded[1..5].try_into().unwrap()) as usize;
        let payload_len = u32::from_be_bytes(encoded[5..9].try_into().unwrap()) as usize;
        assert_eq!(uncompressed_len, data.len());
        assert_eq!(payload_len, data.len());
        assert_eq!(&encoded[FRAME_HEADER_LEN..], data.as_slice());
    }

    #[test]
    fn fragmented_and_concatenated_frames_decode() {
        let data = vec![b'z'; MAX_BLOCK_SIZE + 4096];
        for compression in [Compression::Fast, Compression::Standard, Compression::High] {
            let mut encoder = Encoder::new(compression).unwrap();
            let encoded = encoder.encode(&data).unwrap();
            let mut decoder = Decoder::new(compression).unwrap();
            let mut decoded = Vec::new();
            for byte in &encoded {
                decoder
                    .push(std::slice::from_ref(byte), &mut decoded)
                    .unwrap();
            }
            decoder.finish().unwrap();
            assert_eq!(decoded, data, "{compression:?}");
        }
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let mut decoder = Decoder::new(Compression::Fast).unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            decoder.push(&[9, 0, 0, 0, 1, 0, 0, 0, 1, 0], &mut output),
            Err(CompressionError::InvalidFormat(9))
        ));

        let mut decoder = Decoder::new(Compression::Fast).unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            decoder.push(&[FORMAT_STORED, 0, 0, 0, 1, 0, 0, 0, 2, 7, 7], &mut output),
            Err(CompressionError::InvalidLength)
        ));

        let mut decoder = Decoder::new(Compression::Fast).unwrap();
        let mut output = Vec::new();
        decoder
            .push(&[FORMAT_STORED, 0, 0, 0, 2, 0, 0, 0], &mut output)
            .unwrap();
        assert!(matches!(
            decoder.finish(),
            Err(CompressionError::TruncatedFrame)
        ));

        let mut decoder = Decoder::new(Compression::Fast).unwrap();
        let mut output = Vec::new();
        assert!(decoder
            .push(
                &[FORMAT_COMPRESSED, 0, 0, 0, 4, 0, 0, 0, 3, 1, 2, 3],
                &mut output
            )
            .is_err());
    }

    #[test]
    fn bounded_decode_retains_frames_until_output_drains() {
        for compression in [Compression::Fast, Compression::Standard, Compression::High] {
            let data = vec![b'x'; MAX_BLOCK_SIZE * 8];
            let encoded = Encoder::new(compression).unwrap().encode(&data).unwrap();
            let mut decoder = Decoder::new(compression).unwrap();
            let mut output = Vec::new();
            assert!(decoder
                .push_bounded(&encoded, &mut output, MAX_BLOCK_SIZE - 1)
                .unwrap());
            assert!(output.is_empty());
            let mut all = Vec::new();
            loop {
                output.clear();
                let blocked = decoder
                    .push_bounded(&[], &mut output, MAX_BLOCK_SIZE)
                    .unwrap();
                assert!(output.len() <= MAX_BLOCK_SIZE);
                all.extend_from_slice(&output);
                if !blocked {
                    break;
                }
            }
            decoder.finish().unwrap();
            assert_eq!(all, data);
        }
    }

    #[test]
    fn off_mode_is_not_a_framed_codec() {
        assert!(Encoder::new(Compression::Off).is_err());
        assert!(Decoder::new(Compression::Off).is_err());
    }
}
