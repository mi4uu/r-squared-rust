//! High-performance binary data parsing
//!
//! This module provides optimized parsing functionality for binary data,
//! focusing on performance and memory efficiency for blockchain operations.

use crate::error::{SerializerError, SerializerResult};
use crate::serializer::SerializerUtils;
use std::collections::HashMap;
use std::io::Read;

/// High-performance binary data parser
pub struct FastParser {
    /// Internal buffer for parsing
    buffer: Vec<u8>,
    /// Current position in the buffer
    position: usize,
    /// Type lookup cache for faster parsing
    type_cache: HashMap<u8, &'static str>,
}

impl FastParser {
    /// Create a new fast parser
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            position: 0,
            type_cache: SerializerUtils::create_type_lookup_table(),
        }
    }

    /// Create a new fast parser with initial capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            position: 0,
            type_cache: SerializerUtils::create_type_lookup_table(),
        }
    }

    /// Create a fast parser from existing data
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            buffer: data,
            position: 0,
            type_cache: SerializerUtils::create_type_lookup_table(),
        }
    }

    /// Reset the parser with new data
    pub fn reset(&mut self, data: Vec<u8>) {
        self.buffer = data;
        self.position = 0;
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// Check if there are more bytes to read
    pub fn has_remaining(&self) -> bool {
        self.position < self.buffer.len()
    }

    /// Seek to a specific position
    pub fn seek(&mut self, position: usize) -> SerializerResult<()> {
        if position > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: format!("Seek position {} exceeds buffer length {}", position, self.buffer.len()),
            });
        }
        self.position = position;
        Ok(())
    }

    /// Skip a number of bytes
    pub fn skip(&mut self, bytes: usize) -> SerializerResult<()> {
        if self.position + bytes > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: format!("Cannot skip {} bytes, only {} remaining", bytes, self.remaining()),
            });
        }
        self.position += bytes;
        Ok(())
    }

    /// Peek at the next byte without advancing position
    pub fn peek_u8(&self) -> SerializerResult<u8> {
        if self.position >= self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: "No more bytes to peek".to_string(),
            });
        }
        Ok(self.buffer[self.position])
    }

    /// Read a single byte
    pub fn read_u8(&mut self) -> SerializerResult<u8> {
        if self.position >= self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: "No more bytes to read".to_string(),
            });
        }
        let value = self.buffer[self.position];
        self.position += 1;
        Ok(value)
    }

    /// Read a 16-bit unsigned integer (little-endian)
    pub fn read_u16(&mut self) -> SerializerResult<u16> {
        if self.position + 2 > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: "Not enough bytes for u16".to_string(),
            });
        }
        let bytes = &self.buffer[self.position..self.position + 2];
        self.position += 2;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a 32-bit unsigned integer (little-endian)
    pub fn read_u32(&mut self) -> SerializerResult<u32> {
        if self.position + 4 > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: "Not enough bytes for u32".to_string(),
            });
        }
        let bytes = &self.buffer[self.position..self.position + 4];
        self.position += 4;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a 64-bit unsigned integer (little-endian)
    pub fn read_u64(&mut self) -> SerializerResult<u64> {
        if self.position + 8 > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: "Not enough bytes for u64".to_string(),
            });
        }
        let bytes = &self.buffer[self.position..self.position + 8];
        self.position += 8;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a 64-bit signed integer (little-endian)
    pub fn read_i64(&mut self) -> SerializerResult<i64> {
        if self.position + 8 > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: "Not enough bytes for i64".to_string(),
            });
        }
        let bytes = &self.buffer[self.position..self.position + 8];
        self.position += 8;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a boolean value
    pub fn read_bool(&mut self) -> SerializerResult<bool> {
        let value = self.read_u8()?;
        Ok(value != 0)
    }

    /// Read a variable-length integer
    pub fn read_varint(&mut self) -> SerializerResult<u64> {
        let remaining_data = &self.buffer[self.position..];
        let (value, bytes_read) = SerializerUtils::decode_varint(remaining_data)?;
        self.position += bytes_read;
        Ok(value)
    }

    /// Read a length-prefixed string
    pub fn read_string(&mut self) -> SerializerResult<String> {
        let remaining_data = &self.buffer[self.position..];
        let (string, bytes_read) = SerializerUtils::decode_string(remaining_data)?;
        self.position += bytes_read;
        Ok(string)
    }

    /// Read a fixed number of bytes
    pub fn read_bytes(&mut self, count: usize) -> SerializerResult<Vec<u8>> {
        if self.position + count > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: format!("Not enough bytes: need {}, have {}", count, self.remaining()),
            });
        }
        let bytes = self.buffer[self.position..self.position + count].to_vec();
        self.position += count;
        Ok(bytes)
    }

    /// Read a length-prefixed byte array
    pub fn read_byte_array(&mut self) -> SerializerResult<Vec<u8>> {
        let length = self.read_u32()? as usize;
        if length > super::constants::MAX_ARRAY_LENGTH {
            return Err(SerializerError::BufferError {
                reason: format!("Byte array too large: {} > {}", length, super::constants::MAX_ARRAY_LENGTH),
            });
        }
        self.read_bytes(length)
    }

    /// Read a type identifier and return the type name
    pub fn read_type_id(&mut self) -> SerializerResult<&'static str> {
        let type_id = self.read_u8()?;
        self.type_cache.get(&type_id).copied().ok_or_else(|| {
            SerializerError::TypeConversionError {
                from: format!("Type ID {}", type_id),
                to: "Known type name".to_string(),
            }
        })
    }

    /// Read and validate magic bytes
    pub fn read_magic_bytes(&mut self) -> SerializerResult<()> {
        let magic = self.read_bytes(super::constants::MAGIC_BYTES.len())?;
        if magic != super::constants::MAGIC_BYTES {
            return Err(SerializerError::InvalidFormat {
                expected: format!("Magic bytes: {:?}", super::constants::MAGIC_BYTES),
                actual: format!("Found: {:?}", magic),
            });
        }
        Ok(())
    }

    /// Read and validate version
    pub fn read_version(&mut self) -> SerializerResult<u8> {
        let version = self.read_u8()?;
        if version != super::constants::SERIALIZATION_VERSION {
            return Err(SerializerError::InvalidFormat {
                expected: format!("Version {}", super::constants::SERIALIZATION_VERSION),
                actual: format!("Version {}", version),
            });
        }
        Ok(version)
    }

    /// Fast bulk read operations
    pub fn bulk_read_u32(&mut self, count: usize) -> SerializerResult<Vec<u32>> {
        let bytes_needed = count * 4;
        if self.position + bytes_needed > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: format!("Not enough bytes for {} u32 values", count),
            });
        }

        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(self.read_u32()?);
        }
        Ok(result)
    }

    /// Fast bulk read operations for bytes
    pub fn bulk_read_bytes(&mut self, sizes: &[usize]) -> SerializerResult<Vec<Vec<u8>>> {
        let total_bytes: usize = sizes.iter().sum();
        if self.position + total_bytes > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: format!("Not enough bytes for bulk read: need {}, have {}", total_bytes, self.remaining()),
            });
        }

        let mut result = Vec::with_capacity(sizes.len());
        for &size in sizes {
            result.push(self.read_bytes(size)?);
        }
        Ok(result)
    }

    /// Parse a structured header
    pub fn parse_header(&mut self) -> SerializerResult<ParsedHeader> {
        let magic_valid = if self.remaining() >= super::constants::MAGIC_BYTES.len() {
            let magic = &self.buffer[self.position..self.position + super::constants::MAGIC_BYTES.len()];
            magic == super::constants::MAGIC_BYTES
        } else {
            false
        };

        if magic_valid {
            self.read_magic_bytes()?;
            let version = self.read_version()?;
            Ok(ParsedHeader {
                has_magic: true,
                version,
                data_start: self.position,
            })
        } else {
            Ok(ParsedHeader {
                has_magic: false,
                version: 0,
                data_start: self.position,
            })
        }
    }

    /// Parse with error recovery
    pub fn parse_with_recovery<F, T>(&mut self, parser_fn: F) -> SerializerResult<T>
    where
        F: FnOnce(&mut Self) -> SerializerResult<T>,
    {
        let checkpoint = self.position;
        match parser_fn(self) {
            Ok(result) => Ok(result),
            Err(e) => {
                // Restore position on error
                self.position = checkpoint;
                Err(e)
            }
        }
    }

    /// Get a slice of the remaining buffer without advancing position
    pub fn peek_remaining(&self) -> &[u8] {
        &self.buffer[self.position..]
    }

    /// Get a slice of a specific range without advancing position
    pub fn peek_range(&self, start: usize, end: usize) -> SerializerResult<&[u8]> {
        if start > self.buffer.len() || end > self.buffer.len() || start > end {
            return Err(SerializerError::BufferError {
                reason: format!("Invalid range: {}..{} for buffer of length {}", start, end, self.buffer.len()),
            });
        }
        Ok(&self.buffer[start..end])
    }

    /// Create a sub-parser for a specific range
    pub fn create_sub_parser(&self, start: usize, end: usize) -> SerializerResult<FastParser> {
        let slice = self.peek_range(start, end)?;
        Ok(FastParser::from_data(slice.to_vec()))
    }

    /// Validate remaining data structure
    pub fn validate_remaining_structure(&self) -> SerializerResult<()> {
        if self.remaining() == 0 {
            return Ok(());
        }

        // Basic validation - check if remaining data looks valid
        let remaining_data = self.peek_remaining();
        
        // Check for reasonable structure
        if remaining_data.len() > super::constants::MAX_SERIALIZED_SIZE {
            return Err(SerializerError::BufferError {
                reason: "Remaining data too large".to_string(),
            });
        }

        Ok(())
    }

    /// Get parsing statistics
    pub fn get_stats(&self) -> ParsingStats {
        ParsingStats {
            total_bytes: self.buffer.len(),
            bytes_parsed: self.position,
            bytes_remaining: self.remaining(),
            parse_progress: if self.buffer.is_empty() {
                100.0
            } else {
                (self.position as f64 / self.buffer.len() as f64) * 100.0
            },
        }
    }

    /// Reset to beginning
    pub fn rewind(&mut self) {
        self.position = 0;
    }

    /// Check if we're at the end
    pub fn is_at_end(&self) -> bool {
        self.position >= self.buffer.len()
    }

    /// Get the underlying buffer (read-only)
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume the parser and return the buffer
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }
}

impl Default for FastParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed header information
#[derive(Debug, Clone)]
pub struct ParsedHeader {
    /// Whether magic bytes were found
    pub has_magic: bool,
    /// Serialization version
    pub version: u8,
    /// Position where actual data starts
    pub data_start: usize,
}

/// Parsing statistics
#[derive(Debug, Clone)]
pub struct ParsingStats {
    /// Total bytes in buffer
    pub total_bytes: usize,
    /// Bytes parsed so far
    pub bytes_parsed: usize,
    /// Bytes remaining
    pub bytes_remaining: usize,
    /// Parse progress as percentage
    pub parse_progress: f64,
}

/// Streaming parser for large data
pub struct StreamingParser<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    buffer_size: usize,
    position: usize,
    total_read: usize,
}

impl<R: Read> StreamingParser<R> {
    /// Create a new streaming parser
    pub fn new(reader: R, buffer_size: usize) -> Self {
        Self {
            reader,
            buffer: vec![0; buffer_size],
            buffer_size,
            position: 0,
            total_read: 0,
        }
    }

    /// Fill the buffer from the reader
    pub fn fill_buffer(&mut self) -> SerializerResult<usize> {
        let bytes_read = self.reader.read(&mut self.buffer).map_err(|e| {
            SerializerError::BufferError {
                reason: format!("Failed to read from stream: {}", e),
            }
        })?;
        
        self.position = 0;
        self.total_read += bytes_read;
        Ok(bytes_read)
    }

    /// Get total bytes read
    pub fn total_read(&self) -> usize {
        self.total_read
    }

    /// Create a fast parser from current buffer
    pub fn create_parser(&self, length: usize) -> SerializerResult<FastParser> {
        if length > self.buffer.len() {
            return Err(SerializerError::BufferError {
                reason: format!("Requested length {} exceeds buffer size {}", length, self.buffer.len()),
            });
        }
        
        Ok(FastParser::from_data(self.buffer[..length].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_parsing() {
        let data = vec![
            0x12, 0x34, // u16: 0x3412 (little-endian)
            0x56, 0x78, 0x9A, 0xBC, // u32: 0xBC9A7856
            0x01, // bool: true
        ];
        
        let mut parser = FastParser::from_data(data);
        
        assert_eq!(parser.read_u16().unwrap(), 0x3412);
        assert_eq!(parser.read_u32().unwrap(), 0xBC9A7856);
        assert_eq!(parser.read_bool().unwrap(), true);
        assert!(parser.is_at_end());
    }

    #[test]
    fn test_string_parsing() {
        let test_string = "Hello, R-Squared!";
        let encoded = SerializerUtils::encode_string(test_string);
        
        let mut parser = FastParser::from_data(encoded);
        let decoded = parser.read_string().unwrap();
        
        assert_eq!(decoded, test_string);
    }

    #[test]
    fn test_varint_parsing() {
        let values = [0u64, 127, 128, 255, 256, 16383, 16384];
        
        for &value in &values {
            let encoded = SerializerUtils::encode_varint(value);
            let mut parser = FastParser::from_data(encoded);
            let decoded = parser.read_varint().unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn test_header_parsing() {
        let mut data = super::super::constants::MAGIC_BYTES.to_vec();
        data.push(super::super::constants::SERIALIZATION_VERSION);
        data.extend_from_slice(&[1, 2, 3, 4]);
        
        let mut parser = FastParser::from_data(data);
        let header = parser.parse_header().unwrap();
        
        assert!(header.has_magic);
        assert_eq!(header.version, super::super::constants::SERIALIZATION_VERSION);
        assert_eq!(header.data_start, 5);
    }

    #[test]
    fn test_error_recovery() {
        let data = vec![1, 2, 3];
        let mut parser = FastParser::from_data(data);
        
        // This should fail and restore position
        let result = parser.parse_with_recovery(|p| {
            p.read_u32() // Not enough bytes
        });
        
        assert!(result.is_err());
        assert_eq!(parser.position(), 0); // Position should be restored
    }

    #[test]
    fn test_bulk_operations() {
        let data = vec![
            0x01, 0x00, 0x00, 0x00, // u32: 1
            0x02, 0x00, 0x00, 0x00, // u32: 2
            0x03, 0x00, 0x00, 0x00, // u32: 3
        ];
        
        let mut parser = FastParser::from_data(data);
        let values = parser.bulk_read_u32(3).unwrap();
        
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn test_peek_operations() {
        let data = vec![1, 2, 3, 4, 5];
        let parser = FastParser::from_data(data);
        
        assert_eq!(parser.peek_u8().unwrap(), 1);
        assert_eq!(parser.position(), 0); // Position unchanged
        
        let slice = parser.peek_range(1, 4).unwrap();
        assert_eq!(slice, &[2, 3, 4]);
    }

    #[test]
    fn test_sub_parser() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let parser = FastParser::from_data(data);
        
        let mut sub_parser = parser.create_sub_parser(2, 6).unwrap();
        assert_eq!(sub_parser.buffer(), &[3, 4, 5, 6]);
        assert_eq!(sub_parser.read_u8().unwrap(), 3);
    }

    #[test]
    fn test_parsing_stats() {
        let data = vec![1, 2, 3, 4, 5];
        let mut parser = FastParser::from_data(data);
        
        parser.read_u8().unwrap();
        parser.read_u8().unwrap();
        
        let stats = parser.get_stats();
        assert_eq!(stats.total_bytes, 5);
        assert_eq!(stats.bytes_parsed, 2);
        assert_eq!(stats.bytes_remaining, 3);
        assert_eq!(stats.parse_progress, 40.0);
    }

    #[test]
    fn test_streaming_parser() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let cursor = Cursor::new(data);
        let mut streaming_parser = StreamingParser::new(cursor, 4);
        
        let bytes_read = streaming_parser.fill_buffer().unwrap();
        assert_eq!(bytes_read, 4);
        
        let parser = streaming_parser.create_parser(4).unwrap();
        assert_eq!(parser.buffer(), &[1, 2, 3, 4]);
    }
}