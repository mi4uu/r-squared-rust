//! Serializer module for data serialization and deserialization
//!
//! This module provides functionality for serializing and deserializing
//! blockchain data structures and operations.

pub mod serializer;
pub mod fast_parser;
pub mod types;
pub mod operations;
pub mod template;
pub mod validation;

// Re-export main types for convenience
pub use serializer::Serializer;
pub use fast_parser::FastParser;
pub use types::SerializerTypes;
pub use operations::Operations;
pub use template::Template;
pub use validation::SerializerValidation;

use crate::error::{SerializerError, SerializerResult};

/// Serialization constants
pub mod constants {
    //! Constants used throughout the serializer module
    
    /// Maximum serialized data size
    pub const MAX_SERIALIZED_SIZE: usize = 10 * 1024 * 1024; // 10MB
    
    /// Default buffer size for serialization
    pub const DEFAULT_BUFFER_SIZE: usize = 4096;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(constants::MAX_SERIALIZED_SIZE, 10 * 1024 * 1024);
        assert_eq!(constants::DEFAULT_BUFFER_SIZE, 4096);
    }
}