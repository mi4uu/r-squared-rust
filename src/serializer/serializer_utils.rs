//! Utility functions for serialization operations
//!
//! This module provides utility functions for common serialization tasks,
//! including compression, validation helpers, and data transformation utilities.

use crate::error::{SerializerError, SerializerResult};
use std::collections::HashMap;
use std::io::{Read, Write};

/// Utility functions for serialization operations
pub struct SerializerUtils;

impl SerializerUtils {
    /// Compress data using a simple compression algorithm
    pub fn compress(data: &[u8]) -> SerializerResult<Vec<u8>> {
        // For now, implement a simple run-length encoding
        // In production, you might want to use a proper compression library
        let mut compressed = Vec::new();
        
        if data.is_empty() {
            return Ok(compressed);
        }
        
        let mut current_byte = data[0];
        let mut count = 1u8;
        
        for &byte in &data[1..] {
            if byte == current_byte && count < 255 {
                count += 1;
            } else {
                compressed.push(count);
                compressed.push(current_byte);
                current_byte = byte;
                count = 1;
            }
        }
        
        // Add the last run
        compressed.push(count);
        compressed.push(current_byte);
        
        Ok(compressed)
    }
    
    /// Decompress data that was compressed with the compress function
    pub fn decompress(data: &[u8]) -> SerializerResult<Vec<u8>> {
        let mut decompressed = Vec::new();
        
        if data.len() % 2 != 0 {
            return Err(SerializerError::DeserializationFailed {
                reason: "Invalid compressed data length".to_string(),
            });
        }
        
        for chunk in data.chunks_exact(2) {
            let count = chunk[0];
            let byte = chunk[1];
            
            for _ in 0..count {
                decompressed.push(byte);
            }
        }
        
        Ok(decompressed)
    }
    
    /// Calculate checksum for data integrity
    pub fn calculate_checksum(data: &[u8]) -> u32 {
        // Simple CRC32-like checksum
        let mut checksum = 0u32;
        for &byte in data {
            checksum = checksum.wrapping_mul(31).wrapping_add(byte as u32);
        }
        checksum
    }
    
    /// Verify data integrity using checksum
    pub fn verify_checksum(data: &[u8], expected_checksum: u32) -> bool {
        Self::calculate_checksum(data) == expected_checksum
    }
    
    /// Convert bytes to hex string for debugging
    pub fn bytes_to_hex(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }
    
    /// Convert hex string to bytes
    pub fn hex_to_bytes(hex: &str) -> SerializerResult<Vec<u8>> {
        if hex.len() % 2 != 0 {
            return Err(SerializerError::DeserializationFailed {
                reason: "Hex string must have even length".to_string(),
            });
        }
        
        let mut bytes = Vec::new();
        for chunk in hex.as_bytes().chunks_exact(2) {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| {
                SerializerError::DeserializationFailed {
                    reason: "Invalid UTF-8 in hex string".to_string(),
                }
            })?;
            
            let byte = u8::from_str_radix(hex_str, 16).map_err(|_| {
                SerializerError::DeserializationFailed {
                    reason: format!("Invalid hex digit: {}", hex_str),
                }
            })?;
            
            bytes.push(byte);
        }
        
        Ok(bytes)
    }
    
    /// Pad data to a specific alignment
    pub fn pad_to_alignment(data: &mut Vec<u8>, alignment: usize) {
        let remainder = data.len() % alignment;
        if remainder != 0 {
            let padding = alignment - remainder;
            data.extend(vec![0u8; padding]);
        }
    }
    
    /// Remove padding from aligned data
    pub fn remove_padding(data: &[u8]) -> &[u8] {
        // Remove trailing zeros
        let mut end = data.len();
        while end > 0 && data[end - 1] == 0 {
            end -= 1;
        }
        &data[..end]
    }
    
    /// Encode variable-length integer (varint)
    pub fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut result = Vec::new();
        
        while value >= 0x80 {
            result.push((value & 0x7F) as u8 | 0x80);
            value >>= 7;
        }
        result.push(value as u8);
        
        result
    }
    
    /// Decode variable-length integer (varint)
    pub fn decode_varint(data: &[u8]) -> SerializerResult<(u64, usize)> {
        let mut result = 0u64;
        let mut shift = 0;
        let mut bytes_read = 0;
        
        for &byte in data {
            bytes_read += 1;
            
            if shift >= 64 {
                return Err(SerializerError::DeserializationFailed {
                    reason: "Varint too long".to_string(),
                });
            }
            
            result |= ((byte & 0x7F) as u64) << shift;
            
            if byte & 0x80 == 0 {
                return Ok((result, bytes_read));
            }
            
            shift += 7;
        }
        
        Err(SerializerError::DeserializationFailed {
            reason: "Incomplete varint".to_string(),
        })
    }
    
    /// Encode string with length prefix
    pub fn encode_string(s: &str) -> SerializerResult<Vec<u8>> {
        let bytes = s.as_bytes();
        if bytes.len() > super::constants::MAX_STRING_LENGTH {
            return Err(SerializerError::BufferError {
                reason: format!("String too long: {} > {}", bytes.len(), super::constants::MAX_STRING_LENGTH),
            });
        }
        
        let mut result = Self::encode_varint(bytes.len() as u64);
        result.extend_from_slice(bytes);
        Ok(result)
    }
    
    /// Decode string with length prefix
    pub fn decode_string(data: &[u8]) -> SerializerResult<(String, usize)> {
        let (length, varint_size) = Self::decode_varint(data)?;
        
        if length > super::constants::MAX_STRING_LENGTH as u64 {
            return Err(SerializerError::BufferError {
                reason: format!("String too long: {} > {}", length, super::constants::MAX_STRING_LENGTH),
            });
        }
        
        let string_start = varint_size;
        let string_end = string_start + length as usize;
        
        if string_end > data.len() {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for string".to_string(),
            });
        }
        
        let string_bytes = &data[string_start..string_end];
        let string = String::from_utf8(string_bytes.to_vec()).map_err(|_| {
            SerializerError::DeserializationFailed {
                reason: "Invalid UTF-8 in string".to_string(),
            }
        })?;
        
        Ok((string, string_end))
    }
    
    /// Create a buffer writer with initial capacity
    pub fn create_buffer_writer(capacity: usize) -> Vec<u8> {
        Vec::with_capacity(capacity)
    }
    
    /// Merge multiple byte vectors efficiently
    pub fn merge_byte_vectors(vectors: &[Vec<u8>]) -> Vec<u8> {
        let total_size: usize = vectors.iter().map(|v| v.len()).sum();
        let mut result = Vec::with_capacity(total_size);
        
        for vector in vectors {
            result.extend_from_slice(vector);
        }
        
        result
    }
    
    /// Split byte vector into chunks of specified size
    pub fn split_into_chunks(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        if chunk_size == 0 {
            return vec![data.to_vec()];
        }
        
        data.chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }
    
    /// Validate data size constraints
    pub fn validate_size_constraints(data: &[u8], max_size: usize) -> SerializerResult<()> {
        if data.len() > max_size {
            return Err(SerializerError::BufferError {
                reason: format!("Data size {} exceeds maximum {}", data.len(), max_size),
            });
        }
        Ok(())
    }
    
    /// Create a lookup table for fast deserialization
    pub fn create_type_lookup_table() -> HashMap<u8, &'static str> {
        let mut table = HashMap::new();
        table.insert(0x01, "Transaction");
        table.insert(0x02, "Block");
        table.insert(0x03, "Account");
        table.insert(0x04, "Asset");
        table.insert(0x05, "Operation");
        table.insert(0x06, "Authority");
        table.insert(0x07, "Memo");
        table.insert(0x08, "Price");
        table.insert(0x09, "AssetAmount");
        table.insert(0x0A, "ObjectId");
        table
    }
    
    /// Get type ID for a type name
    pub fn get_type_id(type_name: &str) -> Option<u8> {
        match type_name {
            "Transaction" => Some(0x01),
            "Block" => Some(0x02),
            "Account" => Some(0x03),
            "Asset" => Some(0x04),
            "Operation" => Some(0x05),
            "Authority" => Some(0x06),
            "Memo" => Some(0x07),
            "Price" => Some(0x08),
            "AssetAmount" => Some(0x09),
            "ObjectId" => Some(0x0A),
            _ => None,
        }
    }
    
    /// Escape binary data for safe string representation
    pub fn escape_binary_data(data: &[u8]) -> String {
        let mut result = String::new();
        for &byte in data {
            if byte.is_ascii_graphic() || byte == b' ' {
                result.push(byte as char);
            } else {
                result.push_str(&format!("\\x{:02x}", byte));
            }
        }
        result
    }
    
    /// Calculate optimal buffer size for serialization
    pub fn calculate_optimal_buffer_size(estimated_size: usize) -> usize {
        // Add 25% overhead and round up to nearest power of 2
        let with_overhead = estimated_size + (estimated_size / 4);
        let mut size = 1;
        while size < with_overhead {
            size <<= 1;
        }
        size.max(super::constants::DEFAULT_BUFFER_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_decompression() {
        let data = b"aaabbbcccdddeee";
        let compressed = SerializerUtils::compress(data).unwrap();
        let decompressed = SerializerUtils::decompress(&compressed).unwrap();
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_checksum() {
        let data = b"test data";
        let checksum = SerializerUtils::calculate_checksum(data);
        assert!(SerializerUtils::verify_checksum(data, checksum));
        assert!(!SerializerUtils::verify_checksum(data, checksum + 1));
    }

    #[test]
    fn test_hex_conversion() {
        let data = b"hello";
        let hex = SerializerUtils::bytes_to_hex(data);
        assert_eq!(hex, "68656c6c6f");
        
        let bytes = SerializerUtils::hex_to_bytes(&hex).unwrap();
        assert_eq!(bytes, data.to_vec());
    }

    #[test]
    fn test_varint_encoding() {
        let values = [0, 127, 128, 255, 256, 16383, 16384, u64::MAX];
        
        for &value in &values {
            let encoded = SerializerUtils::encode_varint(value);
            let (decoded, _) = SerializerUtils::decode_varint(&encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_string_encoding() {
        let test_string = "Hello, R-Squared!";
        let encoded = SerializerUtils::encode_string(test_string).unwrap();
        let (decoded, _) = SerializerUtils::decode_string(&encoded).unwrap();
        assert_eq!(test_string, decoded);
    }

    #[test]
    fn test_padding() {
        let mut data = vec![1, 2, 3];
        SerializerUtils::pad_to_alignment(&mut data, 4);
        assert_eq!(data.len(), 4);
        assert_eq!(data, vec![1, 2, 3, 0]);
        
        let unpadded = SerializerUtils::remove_padding(&data);
        assert_eq!(unpadded, &[1, 2, 3]);
    }

    #[test]
    fn test_type_lookup() {
        let table = SerializerUtils::create_type_lookup_table();
        assert_eq!(table.get(&0x01), Some(&"Transaction"));
        assert_eq!(table.get(&0x02), Some(&"Block"));
        
        assert_eq!(SerializerUtils::get_type_id("Transaction"), Some(0x01));
        assert_eq!(SerializerUtils::get_type_id("Unknown"), None);
    }

    #[test]
    fn test_buffer_operations() {
        let vectors = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        ];
        
        let merged = SerializerUtils::merge_byte_vectors(&vectors);
        assert_eq!(merged, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        
        let chunks = SerializerUtils::split_into_chunks(&merged, 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], vec![1, 2, 3]);
        assert_eq!(chunks[1], vec![4, 5, 6]);
        assert_eq!(chunks[2], vec![7, 8, 9]);
    }

    #[test]
    fn test_size_validation() {
        let data = vec![1, 2, 3, 4, 5];
        assert!(SerializerUtils::validate_size_constraints(&data, 10).is_ok());
        assert!(SerializerUtils::validate_size_constraints(&data, 3).is_err());
    }

    #[test]
    fn test_optimal_buffer_size() {
        assert_eq!(SerializerUtils::calculate_optimal_buffer_size(100), 128);
        assert_eq!(SerializerUtils::calculate_optimal_buffer_size(1000), 1024);
        assert_eq!(SerializerUtils::calculate_optimal_buffer_size(10), super::constants::DEFAULT_BUFFER_SIZE);
    }
}