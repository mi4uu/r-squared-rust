//! Serializer module for data serialization and deserialization
//!
//! This module provides functionality for serializing and deserializing
//! blockchain data structures and operations for the R-Squared blockchain.
//!
//! ## Features
//!
//! - High-performance binary data parsing
//! - Operation serialization/deserialization
//! - Serialization validation and integrity checks
//! - Type definitions for serialization
//! - Utility functions for serialization operations
//!
//! ## Example
//!
//! ```rust
//! use r_squared_rust::serializer::Serializer;
//! use r_squared_rust::chain::Transaction;
//!
//! // Create a serializer instance
//! let serializer = Serializer::new();
//!
//! // Serialize a transaction
//! let transaction = Transaction::default();
//! let serialized = serializer.serialize(&transaction)?;
//!
//! // Deserialize back
//! let deserialized: Transaction = serializer.deserialize(&serialized)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod fast_parser;
pub mod serializer_operation;
pub mod serializer_validation;
pub mod serializer_types;
pub mod serializer_utils;

// Keep the main serializer in a separate file for backwards compatibility
mod serializer;

// Re-export main types for convenience
pub use serializer::Serializer;
pub use fast_parser::FastParser;
pub use serializer_operation::SerializerOperation;
pub use serializer_validation::SerializerValidation;
pub use serializer_types::SerializerTypes;
pub use serializer_utils::SerializerUtils;

use crate::error::{SerializerError, SerializerResult};

/// Serialization constants
pub mod constants {
    //! Constants used throughout the serializer module
    
    /// Maximum serialized data size (10MB)
    pub const MAX_SERIALIZED_SIZE: usize = 10 * 1024 * 1024;
    
    /// Default buffer size for serialization
    pub const DEFAULT_BUFFER_SIZE: usize = 4096;
    
    /// Maximum operation count in a single serialization
    pub const MAX_OPERATIONS_COUNT: usize = 1000;
    
    /// Serialization format version
    pub const SERIALIZATION_VERSION: u8 = 1;
    
    /// Magic bytes for R-Squared serialization format
    pub const MAGIC_BYTES: &[u8] = b"RSQ\x01";
    
    /// Maximum string length in serialized data
    pub const MAX_STRING_LENGTH: usize = 65535;
    
    /// Maximum array length in serialized data
    pub const MAX_ARRAY_LENGTH: usize = 10000;
}

/// Serialization format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// Binary format using bincode
    Binary,
    /// JSON format for debugging
    Json,
    /// Compact binary format
    Compact,
}

impl Default for SerializationFormat {
    fn default() -> Self {
        Self::Binary
    }
}

/// Serialization configuration
#[derive(Debug, Clone)]
pub struct SerializationConfig {
    /// Format to use for serialization
    pub format: SerializationFormat,
    /// Whether to validate data during serialization
    pub validate: bool,
    /// Whether to compress serialized data
    pub compress: bool,
    /// Maximum allowed size for serialized data
    pub max_size: usize,
}

impl Default for SerializationConfig {
    fn default() -> Self {
        Self {
            format: SerializationFormat::Binary,
            validate: true,
            compress: false,
            max_size: constants::MAX_SERIALIZED_SIZE,
        }
    }
}

/// High-level serialization API
pub struct SerializerApi {
    config: SerializationConfig,
}

impl SerializerApi {
    /// Create a new serializer API with default configuration
    pub fn new() -> Self {
        Self {
            config: SerializationConfig::default(),
        }
    }

    /// Create a new serializer API with custom configuration
    pub fn with_config(config: SerializationConfig) -> Self {
        Self { config }
    }

    /// Serialize any serializable type
    pub fn serialize<T>(&self, data: &T) -> SerializerResult<Vec<u8>>
    where
        T: serde::Serialize + bincode::Encode,
    {
        if self.config.validate {
            SerializerValidation::validate_before_serialization(data)?;
        }

        let serializer = Serializer::new();
        let result = match self.config.format {
            SerializationFormat::Binary => serializer.serialize_binary(data),
            SerializationFormat::Json => serializer.serialize_json(data),
            SerializationFormat::Compact => serializer.serialize_compact(data),
        }?;

        if result.len() > self.config.max_size {
            return Err(SerializerError::BufferError {
                reason: format!("Serialized data size {} exceeds maximum {}", result.len(), self.config.max_size),
            });
        }

        if self.config.compress {
            SerializerUtils::compress(&result)
        } else {
            Ok(result)
        }
    }

    /// Deserialize any deserializable type
    pub fn deserialize<T>(&self, data: &[u8]) -> SerializerResult<T>
    where
        T: serde::de::DeserializeOwned + bincode::Decode<()>,
    {
        let data = if self.config.compress {
            SerializerUtils::decompress(data)?
        } else {
            data.to_vec()
        };

        let result = match self.config.format {
            SerializationFormat::Binary => Serializer::deserialize_binary(&data),
            SerializationFormat::Json => Serializer::deserialize_json(&data),
            SerializationFormat::Compact => Serializer::deserialize_compact(&data),
        }?;

        if self.config.validate {
            SerializerValidation::validate_after_deserialization(&result)?;
        }

        Ok(result)
    }

    /// Get current configuration
    pub fn config(&self) -> &SerializationConfig {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: SerializationConfig) {
        self.config = config;
    }
}

impl Default for SerializerApi {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(constants::MAX_SERIALIZED_SIZE, 10 * 1024 * 1024);
        assert_eq!(constants::DEFAULT_BUFFER_SIZE, 4096);
        assert_eq!(constants::MAGIC_BYTES, b"RSQ\x01");
    }

    #[test]
    fn test_serialization_format() {
        assert_eq!(SerializationFormat::default(), SerializationFormat::Binary);
    }

    #[test]
    fn test_serialization_config() {
        let config = SerializationConfig::default();
        assert_eq!(config.format, SerializationFormat::Binary);
        assert!(config.validate);
        assert!(!config.compress);
        assert_eq!(config.max_size, constants::MAX_SERIALIZED_SIZE);
    }

    #[test]
    fn test_serializer_api_creation() {
        let api = SerializerApi::new();
        assert_eq!(api.config().format, SerializationFormat::Binary);

        let custom_config = SerializationConfig {
            format: SerializationFormat::Json,
            validate: false,
            compress: true,
            max_size: 1024,
        };
        let api_custom = SerializerApi::with_config(custom_config.clone());
        assert_eq!(api_custom.config().format, SerializationFormat::Json);
        assert!(!api_custom.config().validate);
        assert!(api_custom.config().compress);
        assert_eq!(api_custom.config().max_size, 1024);
    }
}