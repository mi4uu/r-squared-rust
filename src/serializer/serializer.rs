//! Main serializer implementation
//!
//! This module provides the core serialization functionality for the R-Squared
//! blockchain, supporting multiple formats and providing high-level APIs.

use crate::error::{SerializerError, SerializerResult};
use crate::serializer::{SerializerValidation, SerializerUtils};
use std::time::Instant;

#[cfg(feature = "serde_support")]
use serde::{Serialize, de::DeserializeOwned};

/// Main serializer for blockchain data
pub struct Serializer {
    /// Buffer capacity for serialization operations
    buffer_capacity: usize,
}

impl Serializer {
    /// Create a new serializer with default buffer capacity
    pub fn new() -> Self {
        Self {
            buffer_capacity: super::constants::DEFAULT_BUFFER_SIZE,
        }
    }

    /// Create a new serializer with specified buffer capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer_capacity: capacity,
        }
    }

    /// Serialize data to bytes using the default binary format
    pub fn serialize<T>(&self, data: &T) -> SerializerResult<Vec<u8>>
    where
        T: Serialize + bincode::Encode,
    {
        self.serialize_binary(data)
    }

    /// Deserialize data from bytes using the default binary format
    pub fn deserialize<T>(&self, bytes: &[u8]) -> SerializerResult<T>
    where
        T: DeserializeOwned + bincode::Decode<()>,
    {
        Self::deserialize_binary(bytes)
    }

    /// Serialize data to binary format using bincode
    pub fn serialize_binary<T>(&self, data: &T) -> SerializerResult<Vec<u8>>
    where
        T: Serialize + bincode::Encode,
    {
        let start_time = Instant::now();
        
        // Validate before serialization
        SerializerValidation::validate_before_serialization(data)?;

        // Use bincode for binary serialization
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();

        let result = bincode::encode_to_vec(data, config).map_err(|e| {
            SerializerError::SerializationFailed {
                reason: format!("Bincode serialization failed: {}", e),
            }
        })?;

        // Add magic bytes and version
        let mut final_result = super::constants::MAGIC_BYTES.to_vec();
        final_result.push(super::constants::SERIALIZATION_VERSION);
        final_result.extend_from_slice(&result);

        // Validate size constraints
        SerializerUtils::validate_size_constraints(&final_result, super::constants::MAX_SERIALIZED_SIZE)?;

        let elapsed = start_time.elapsed();
        tracing::debug!(
            "Binary serialization completed in {}μs, {} bytes",
            elapsed.as_micros(),
            final_result.len()
        );

        Ok(final_result)
    }

    /// Deserialize data from binary format using bincode
    pub fn deserialize_binary<T>(bytes: &[u8]) -> SerializerResult<T>
    where
        T: DeserializeOwned + bincode::Decode<()>,
    {
        let start_time = Instant::now();

        // Validate serialized data
        SerializerValidation::validate_serialized_data(bytes)?;

        // Check for magic bytes and version
        let data_start = if bytes.len() >= 5 && &bytes[0..4] == super::constants::MAGIC_BYTES {
            let version = bytes[4];
            if version != super::constants::SERIALIZATION_VERSION {
                return Err(SerializerError::InvalidFormat {
                    expected: format!("Version {}", super::constants::SERIALIZATION_VERSION),
                    actual: format!("Version {}", version),
                });
            }
            5
        } else {
            0
        };

        let data = &bytes[data_start..];

        // Use bincode for binary deserialization
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();

        let (result, _) = bincode::decode_from_slice(data, config).map_err(|e| {
            SerializerError::DeserializationFailed {
                reason: format!("Bincode deserialization failed: {}", e),
            }
        })?;

        // Validate after deserialization
        SerializerValidation::validate_after_deserialization(&result)?;

        let elapsed = start_time.elapsed();
        tracing::debug!(
            "Binary deserialization completed in {}μs",
            elapsed.as_micros()
        );

        Ok(result)
    }

    /// Serialize data to JSON format
    pub fn serialize_json<T>(&self, data: &T) -> SerializerResult<Vec<u8>>
    where
        T: Serialize,
    {
        #[cfg(feature = "serde_support")]
        {
            let start_time = Instant::now();
            
            SerializerValidation::validate_before_serialization(data)?;

            let json_string = serde_json::to_string(data).map_err(|e| {
                SerializerError::SerializationFailed {
                    reason: format!("JSON serialization failed: {}", e),
                }
            })?;

            let result = json_string.into_bytes();
            SerializerUtils::validate_size_constraints(&result, super::constants::MAX_SERIALIZED_SIZE)?;

            let elapsed = start_time.elapsed();
            tracing::debug!(
                "JSON serialization completed in {}μs, {} bytes",
                elapsed.as_micros(),
                result.len()
            );

            Ok(result)
        }

        #[cfg(not(feature = "serde_support"))]
        {
            Err(SerializerError::SerializationFailed {
                reason: "JSON serialization requires serde_support feature".to_string(),
            })
        }
    }

    /// Deserialize data from JSON format
    pub fn deserialize_json<T>(bytes: &[u8]) -> SerializerResult<T>
    where
        T: DeserializeOwned,
    {
        #[cfg(feature = "serde_support")]
        {
            let start_time = Instant::now();

            let json_str = std::str::from_utf8(bytes).map_err(|_| {
                SerializerError::DeserializationFailed {
                    reason: "Invalid UTF-8 in JSON data".to_string(),
                }
            })?;

            let result: T = serde_json::from_str(json_str).map_err(|e| {
                SerializerError::DeserializationFailed {
                    reason: format!("JSON deserialization failed: {}", e),
                }
            })?;

            SerializerValidation::validate_after_deserialization(&result)?;

            let elapsed = start_time.elapsed();
            tracing::debug!(
                "JSON deserialization completed in {}μs",
                elapsed.as_micros()
            );

            Ok(result)
        }

        #[cfg(not(feature = "serde_support"))]
        {
            Err(SerializerError::DeserializationFailed {
                reason: "JSON deserialization requires serde_support feature".to_string(),
            })
        }
    }

    /// Serialize data to compact binary format
    pub fn serialize_compact<T>(&self, data: &T) -> SerializerResult<Vec<u8>>
    where
        T: Serialize + bincode::Encode,
    {
        let start_time = Instant::now();
        
        SerializerValidation::validate_before_serialization(data)?;

        // First serialize to binary
        let binary_data = self.serialize_binary(data)?;
        
        // Then compress
        let compressed = SerializerUtils::compress(&binary_data)?;
        
        // Add compact format marker
        let mut result = vec![0xC0, 0x01]; // Compact format marker
        result.extend_from_slice(&compressed);

        SerializerUtils::validate_size_constraints(&result, super::constants::MAX_SERIALIZED_SIZE)?;

        let elapsed = start_time.elapsed();
        tracing::debug!(
            "Compact serialization completed in {}μs, {} bytes ({}% of original)",
            elapsed.as_micros(),
            result.len(),
            (result.len() * 100) / binary_data.len()
        );

        Ok(result)
    }

    /// Deserialize data from compact binary format
    pub fn deserialize_compact<T>(bytes: &[u8]) -> SerializerResult<T>
    where
        T: DeserializeOwned + bincode::Decode<()>,
    {
        let start_time = Instant::now();

        if bytes.len() < 2 || &bytes[0..2] != [0xC0, 0x01] {
            return Err(SerializerError::InvalidFormat {
                expected: "Compact format marker".to_string(),
                actual: "Missing or invalid marker".to_string(),
            });
        }

        let compressed_data = &bytes[2..];
        let decompressed = SerializerUtils::decompress(compressed_data)?;
        
        let result = Self::deserialize_binary(&decompressed)?;

        let elapsed = start_time.elapsed();
        tracing::debug!(
            "Compact deserialization completed in {}μs",
            elapsed.as_micros()
        );

        Ok(result)
    }

    /// Serialize with automatic format detection based on data size
    pub fn serialize_auto<T>(&self, data: &T) -> SerializerResult<Vec<u8>>
    where
        T: Serialize + bincode::Encode,
    {
        // Try binary first
        let binary_result = self.serialize_binary(data)?;
        
        // If data is large, try compact format
        if binary_result.len() > 1024 {
            let compact_result = self.serialize_compact(data)?;
            if compact_result.len() < binary_result.len() {
                return Ok(compact_result);
            }
        }
        
        Ok(binary_result)
    }

    /// Deserialize with automatic format detection
    pub fn deserialize_auto<T>(bytes: &[u8]) -> SerializerResult<T>
    where
        T: DeserializeOwned + bincode::Decode<()>,
    {
        // Check for compact format marker
        if bytes.len() >= 2 && &bytes[0..2] == [0xC0, 0x01] {
            return Self::deserialize_compact(bytes);
        }
        
        // Check for magic bytes (binary format)
        if bytes.len() >= 4 && &bytes[0..4] == super::constants::MAGIC_BYTES {
            return Self::deserialize_binary(bytes);
        }
        
        // Try JSON format
        if bytes[0] == b'{' || bytes[0] == b'[' {
            return Self::deserialize_json(bytes);
        }
        
        // Default to binary
        Self::deserialize_binary(bytes)
    }

    /// Serialize with checksum for integrity verification
    pub fn serialize_with_checksum<T>(&self, data: &T) -> SerializerResult<Vec<u8>>
    where
        T: Serialize + bincode::Encode,
    {
        let serialized = self.serialize_binary(data)?;
        let checksum = SerializerUtils::calculate_checksum(&serialized);
        
        let mut result = Vec::with_capacity(serialized.len() + 4);
        result.extend_from_slice(&serialized);
        result.extend_from_slice(&checksum.to_le_bytes());
        
        Ok(result)
    }

    /// Deserialize with checksum verification
    pub fn deserialize_with_checksum<T>(bytes: &[u8]) -> SerializerResult<T>
    where
        T: DeserializeOwned + bincode::Decode<()>,
    {
        if bytes.len() < 4 {
            return Err(SerializerError::InvalidFormat {
                expected: "Data with checksum (at least 4 bytes)".to_string(),
                actual: format!("Only {} bytes", bytes.len()),
            });
        }
        
        let data_len = bytes.len() - 4;
        let data = &bytes[..data_len];
        let checksum_bytes = &bytes[data_len..];
        
        let expected_checksum = u32::from_le_bytes([
            checksum_bytes[0],
            checksum_bytes[1], 
            checksum_bytes[2],
            checksum_bytes[3],
        ]);
        
        if !SerializerUtils::verify_checksum(data, expected_checksum) {
            return Err(SerializerError::InvalidFormat {
                expected: "Valid checksum".to_string(),
                actual: "Checksum mismatch".to_string(),
            });
        }
        
        Self::deserialize_binary(data)
    }

    /// Get serialization statistics
    pub fn get_format_info(bytes: &[u8]) -> SerializerResult<String> {
        if bytes.is_empty() {
            return Ok("Empty data".to_string());
        }
        
        if bytes.len() >= 2 && &bytes[0..2] == [0xC0, 0x01] {
            return Ok("Compact binary format".to_string());
        }
        
        if bytes.len() >= 4 && &bytes[0..4] == super::constants::MAGIC_BYTES {
            let version = if bytes.len() >= 5 { bytes[4] } else { 0 };
            return Ok(format!("Binary format v{}", version));
        }
        
        if bytes[0] == b'{' || bytes[0] == b'[' {
            return Ok("JSON format".to_string());
        }
        
        Ok("Unknown format".to_string())
    }

    /// Estimate serialized size without actually serializing
    pub fn estimate_size<T>(_data: &T) -> usize
    where
        T: Serialize,
    {
        // This is a rough estimate - in practice you'd implement
        // size calculation based on the type structure
        std::mem::size_of::<T>() * 2 // Conservative estimate
    }

    /// Batch serialize multiple items
    pub fn serialize_batch<T>(&self, items: &[T]) -> SerializerResult<Vec<u8>>
    where
        T: Serialize + bincode::Encode,
    {
        let start_time = Instant::now();
        
        if items.len() > super::constants::MAX_ARRAY_LENGTH {
            return Err(SerializerError::BufferError {
                reason: format!("Too many items: {} > {}", items.len(), super::constants::MAX_ARRAY_LENGTH),
            });
        }

        let mut result = Vec::new();
        
        // Write item count
        result.extend_from_slice(&(items.len() as u32).to_le_bytes());
        
        // Serialize each item
        for item in items {
            let item_data = self.serialize_binary(item)?;
            result.extend_from_slice(&(item_data.len() as u32).to_le_bytes());
            result.extend_from_slice(&item_data);
        }

        let elapsed = start_time.elapsed();
        tracing::debug!(
            "Batch serialization of {} items completed in {}μs",
            items.len(),
            elapsed.as_micros()
        );

        Ok(result)
    }

    /// Batch deserialize multiple items
    pub fn deserialize_batch<T>(bytes: &[u8]) -> SerializerResult<Vec<T>>
    where
        T: DeserializeOwned + bincode::Decode<()>,
    {
        let start_time = Instant::now();
        let mut offset = 0;

        if bytes.len() < 4 {
            return Err(SerializerError::DeserializationFailed {
                reason: "Not enough data for item count".to_string(),
            });
        }

        let item_count = u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3]
        ]) as usize;
        offset += 4;

        if item_count > super::constants::MAX_ARRAY_LENGTH {
            return Err(SerializerError::BufferError {
                reason: format!("Too many items: {} > {}", item_count, super::constants::MAX_ARRAY_LENGTH),
            });
        }

        let mut items = Vec::with_capacity(item_count);

        for _ in 0..item_count {
            if offset + 4 > bytes.len() {
                return Err(SerializerError::DeserializationFailed {
                    reason: "Not enough data for item length".to_string(),
                });
            }

            let item_len = u32::from_le_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]
            ]) as usize;
            offset += 4;

            if offset + item_len > bytes.len() {
                return Err(SerializerError::DeserializationFailed {
                    reason: "Not enough data for item".to_string(),
                });
            }

            let item_data = &bytes[offset..offset + item_len];
            let item = Self::deserialize_binary(item_data)?;
            items.push(item);
            offset += item_len;
        }

        let elapsed = start_time.elapsed();
        tracing::debug!(
            "Batch deserialization of {} items completed in {}μs",
            items.len(),
            elapsed.as_micros()
        );

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq, bincode::Encode, bincode::Decode)]
    struct TestData {
        id: u32,
        name: String,
        values: Vec<i32>,
    }

    #[test]
    fn test_binary_serialization() {
        let data = TestData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let serializer = Serializer::new();
        let serialized = serializer.serialize_binary(&data).unwrap();
        let deserialized: TestData = Serializer::deserialize_binary(&serialized).unwrap();

        assert_eq!(data, deserialized);
    }

    #[test]
    fn test_json_serialization() {
        let data = TestData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let serializer = Serializer::new();
        let serialized = serializer.serialize_json(&data).unwrap();
        let deserialized: TestData = Serializer::deserialize_json(&serialized).unwrap();

        assert_eq!(data, deserialized);
    }

    #[test]
    fn test_compact_serialization() {
        let data = TestData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let serializer = Serializer::new();
        let serialized = serializer.serialize_compact(&data).unwrap();
        let deserialized: TestData = Serializer::deserialize_compact(&serialized).unwrap();

        assert_eq!(data, deserialized);
    }

    #[test]
    fn test_auto_format_detection() {
        let data = TestData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let serializer = Serializer::new();

        // Test binary format
        let binary = serializer.serialize_binary(&data).unwrap();
        let deserialized: TestData = Serializer::deserialize_auto(&binary).unwrap();
        assert_eq!(data, deserialized);

        // Test compact format
        let compact = serializer.serialize_compact(&data).unwrap();
        let deserialized: TestData = Serializer::deserialize_auto(&compact).unwrap();
        assert_eq!(data, deserialized);

        // Test JSON format
        let json = serializer.serialize_json(&data).unwrap();
        let deserialized: TestData = Serializer::deserialize_auto(&json).unwrap();
        assert_eq!(data, deserialized);
    }

    #[test]
    fn test_checksum_serialization() {
        let data = TestData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let serializer = Serializer::new();
        let serialized = serializer.serialize_with_checksum(&data).unwrap();
        let deserialized: TestData = Serializer::deserialize_with_checksum(&serialized).unwrap();

        assert_eq!(data, deserialized);

        // Test checksum validation
        let mut corrupted = serialized.clone();
        corrupted[10] ^= 0xFF; // Corrupt some data
        assert!(Serializer::deserialize_with_checksum::<TestData>(&corrupted).is_err());
    }

    #[test]
    fn test_batch_serialization() {
        let items = vec![
            TestData { id: 1, name: "first".to_string(), values: vec![1, 2] },
            TestData { id: 2, name: "second".to_string(), values: vec![3, 4] },
            TestData { id: 3, name: "third".to_string(), values: vec![5, 6] },
        ];

        let serializer = Serializer::new();
        let serialized = serializer.serialize_batch(&items).unwrap();
        let deserialized: Vec<TestData> = Serializer::deserialize_batch(&serialized).unwrap();

        assert_eq!(items, deserialized);
    }

    #[test]
    fn test_format_info() {
        let data = TestData {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let serializer = Serializer::new();
        let binary = serializer.serialize_binary(&data).unwrap();
        let info = Serializer::get_format_info(&binary).unwrap();
        assert!(info.contains("Binary format"));

        let compact = serializer.serialize_compact(&data).unwrap();
        let info = Serializer::get_format_info(&compact).unwrap();
        assert_eq!(info, "Compact binary format");

        let json = serializer.serialize_json(&data).unwrap();
        let info = Serializer::get_format_info(&json).unwrap();
        assert_eq!(info, "JSON format");
    }
}