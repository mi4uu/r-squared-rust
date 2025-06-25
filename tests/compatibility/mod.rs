//! Cross-implementation compatibility tests
//! 
//! This module contains tests that verify the Rust implementation produces
//! identical results to the JavaScript implementation.

pub mod ecc_compatibility;
pub mod chain_compatibility;
pub mod serializer_compatibility;
pub mod test_vectors;

use serde::{Deserialize, Serialize};

/// Test vector structure for cross-implementation verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVector {
    pub name: String,
    pub description: String,
    pub input: TestInput,
    pub expected_output: TestOutput,
}

/// Input data for test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TestInput {
    String(String),
    Bytes(Vec<u8>),
    Object(serde_json::Value),
}

/// Expected output for test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TestOutput {
    String(String),
    Bytes(Vec<u8>),
    Object(serde_json::Value),
    Boolean(bool),
}

/// Load test vectors from JSON files
pub fn load_test_vectors(file_path: &str) -> Result<Vec<TestVector>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file_path)?;
    let vectors: Vec<TestVector> = serde_json::from_str(&content)?;
    Ok(vectors)
}

/// Compare two byte arrays with detailed error reporting
pub fn assert_bytes_equal(actual: &[u8], expected: &[u8], context: &str) {
    if actual != expected {
        panic!(
            "Byte arrays differ in {}\nExpected: {}\nActual:   {}\nExpected (hex): {}\nActual (hex):   {}",
            context,
            expected.len(),
            actual.len(),
            hex::encode(expected),
            hex::encode(actual)
        );
    }
}

/// Compare strings with detailed error reporting
pub fn assert_strings_equal(actual: &str, expected: &str, context: &str) {
    if actual != expected {
        panic!(
            "Strings differ in {}\nExpected: '{}'\nActual:   '{}'",
            context, expected, actual
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_serialization() {
        let vector = TestVector {
            name: "test".to_string(),
            description: "Test vector".to_string(),
            input: TestInput::String("input".to_string()),
            expected_output: TestOutput::String("output".to_string()),
        };

        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: TestVector = serde_json::from_str(&json).unwrap();
        
        assert_eq!(vector.name, deserialized.name);
    }
}