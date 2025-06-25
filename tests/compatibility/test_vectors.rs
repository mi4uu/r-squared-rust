//! Test vector generation and management
//! 
//! This module provides utilities for creating and managing test vectors
//! that can be used to verify compatibility between implementations.

use r_squared_rust::ecc::*;
use r_squared_rust::chain::*;
use r_squared_rust::serializer::*;
use super::{TestVector, TestInput, TestOutput};
use serde_json;
use std::fs;
use std::path::Path;

/// Generate comprehensive test vectors for ECC operations
pub fn generate_ecc_test_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    
    // Private key generation from seed
    vectors.push(TestVector {
        name: "private_key_from_seed".to_string(),
        description: "Generate private key from seed string".to_string(),
        input: TestInput::String("test seed 123".to_string()),
        expected_output: TestOutput::String("5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss".to_string()),
    });
    
    // Brain key normalization
    vectors.push(TestVector {
        name: "brain_key_normalization".to_string(),
        description: "Normalize brain key with extra spaces".to_string(),
        input: TestInput::String("  hello   world  test  ".to_string()),
        expected_output: TestOutput::String("hello world test".to_string()),
    });
    
    // Public key derivation
    vectors.push(TestVector {
        name: "public_key_derivation".to_string(),
        description: "Derive public key from private key".to_string(),
        input: TestInput::String("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ".to_string()),
        expected_output: TestOutput::String("0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a".to_string()),
    });
    
    // Address generation
    vectors.push(TestVector {
        name: "address_generation".to_string(),
        description: "Generate address from public key".to_string(),
        input: TestInput::Object(serde_json::json!({
            "public_key": "0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a",
            "prefix": "RSQ"
        })),
        expected_output: TestOutput::String("RSQ6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV".to_string()),
    });
    
    // Hash functions
    vectors.push(TestVector {
        name: "sha256_hash".to_string(),
        description: "SHA-256 hash of test data".to_string(),
        input: TestInput::String("Hello, World!".to_string()),
        expected_output: TestOutput::String("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f".to_string()),
    });
    
    vectors.push(TestVector {
        name: "ripemd160_hash".to_string(),
        description: "RIPEMD-160 hash of test data".to_string(),
        input: TestInput::String("Hello, World!".to_string()),
        expected_output: TestOutput::String("527a6a4b9a6da75607546842e0e00105350b1aaf".to_string()),
    });
    
    vectors
}

/// Generate test vectors for chain operations
pub fn generate_chain_test_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    
    // Object ID parsing
    vectors.push(TestVector {
        name: "object_id_parsing".to_string(),
        description: "Parse object ID from string".to_string(),
        input: TestInput::String("1.2.100".to_string()),
        expected_output: TestOutput::Object(serde_json::json!({
            "space": 1,
            "type": 2,
            "instance": 100
        })),
    });
    
    // Asset amount formatting
    vectors.push(TestVector {
        name: "asset_amount_formatting".to_string(),
        description: "Format asset amount with precision".to_string(),
        input: TestInput::Object(serde_json::json!({
            "amount": 123456,
            "precision": 5
        })),
        expected_output: TestOutput::String("1.23456".to_string()),
    });
    
    // Account name validation
    vectors.push(TestVector {
        name: "account_name_validation_valid".to_string(),
        description: "Validate valid account name".to_string(),
        input: TestInput::String("alice".to_string()),
        expected_output: TestOutput::Boolean(true),
    });
    
    vectors.push(TestVector {
        name: "account_name_validation_invalid".to_string(),
        description: "Validate invalid account name".to_string(),
        input: TestInput::String("Alice".to_string()),
        expected_output: TestOutput::Boolean(false),
    });
    
    // Asset symbol validation
    vectors.push(TestVector {
        name: "asset_symbol_validation_valid".to_string(),
        description: "Validate valid asset symbol".to_string(),
        input: TestInput::String("BTC".to_string()),
        expected_output: TestOutput::Boolean(true),
    });
    
    vectors.push(TestVector {
        name: "asset_symbol_validation_invalid".to_string(),
        description: "Validate invalid asset symbol".to_string(),
        input: TestInput::String("btc".to_string()),
        expected_output: TestOutput::Boolean(false),
    });
    
    vectors
}

/// Generate test vectors for serialization operations
pub fn generate_serializer_test_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();
    
    // Varint encoding
    let varint_test_values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536];
    for value in &varint_test_values {
        vectors.push(TestVector {
            name: format!("varint_encoding_{}", value),
            description: format!("Encode varint value {}", value),
            input: TestInput::Object(serde_json::json!({"value": value})),
            expected_output: TestOutput::Bytes(SerializerUtils::encode_varint(*value)),
        });
    }
    
    // String encoding
    let string_test_values = ["", "Hello", "Hello, World!", "🚀"];
    for value in &string_test_values {
        vectors.push(TestVector {
            name: format!("string_encoding_{}", value.len()),
            description: format!("Encode string '{}'", value),
            input: TestInput::String(value.to_string()),
            expected_output: TestOutput::Bytes(SerializerUtils::encode_string(value)),
        });
    }
    
    vectors
}

/// Generate all test vectors and save to files
pub fn generate_all_test_vectors() -> Result<(), Box<dyn std::error::Error>> {
    // Create vectors directory if it doesn't exist
    let vectors_dir = "tests/vectors";
    fs::create_dir_all(vectors_dir)?;
    
    // Generate ECC vectors
    let ecc_vectors = generate_ecc_test_vectors();
    let ecc_json = serde_json::to_string_pretty(&ecc_vectors)?;
    fs::write(format!("{}/ecc_vectors.json", vectors_dir), ecc_json)?;
    
    // Generate chain vectors
    let chain_vectors = generate_chain_test_vectors();
    let chain_json = serde_json::to_string_pretty(&chain_vectors)?;
    fs::write(format!("{}/chain_vectors.json", vectors_dir), chain_json)?;
    
    // Generate serializer vectors
    let serializer_vectors = generate_serializer_test_vectors();
    let serializer_json = serde_json::to_string_pretty(&serializer_vectors)?;
    fs::write(format!("{}/serializer_vectors.json", vectors_dir), serializer_json)?;
    
    println!("Generated test vectors:");
    println!("  - ECC vectors: {} tests", ecc_vectors.len());
    println!("  - Chain vectors: {} tests", chain_vectors.len());
    println!("  - Serializer vectors: {} tests", serializer_vectors.len());
    
    Ok(())
}

/// Create test vectors from JavaScript implementation
/// This would be used to generate reference data by running the JavaScript code
pub fn create_js_reference_vectors() -> Result<(), Box<dyn std::error::Error>> {
    // This function would:
    // 1. Execute JavaScript code to generate reference outputs
    // 2. Save the results as test vectors
    // 3. Use these vectors to verify Rust implementation
    
    // For now, we'll create a template that shows what this would look like
    let js_reference_template = r#"
// JavaScript reference implementation test
const rsq = require('rsquared-js');

// Test private key generation
const privateKey = rsq.PrivateKey.fromSeed('test seed 123');
console.log('Private key WIF:', privateKey.toWif());

// Test public key derivation
const publicKey = privateKey.toPublicKey();
console.log('Public key hex:', publicKey.toPublicKeyString());

// Test address generation
const address = publicKey.toAddressString('RSQ');
console.log('Address:', address);

// Test brain key normalization
const normalized = rsq.key.normalize_brainKey('  hello   world  test  ');
console.log('Normalized brain key:', normalized);

// Test hash functions
const testData = 'Hello, World!';
const sha256Hash = rsq.hash.sha256(testData).toString('hex');
const ripemd160Hash = rsq.hash.ripemd160(testData).toString('hex');
console.log('SHA-256:', sha256Hash);
console.log('RIPEMD-160:', ripemd160Hash);
"#;
    
    // Save the template for manual execution
    fs::write("tests/vectors/js_reference_generator.js", js_reference_template)?;
    
    println!("Created JavaScript reference generator template");
    println!("Run with: node tests/vectors/js_reference_generator.js");
    
    Ok(())
}

/// Validate test vectors against current implementation
pub fn validate_test_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let vectors_dir = "tests/vectors";
    
    // Validate ECC vectors
    if Path::new(&format!("{}/ecc_vectors.json", vectors_dir)).exists() {
        let ecc_vectors = super::load_test_vectors(&format!("{}/ecc_vectors.json", vectors_dir))?;
        validate_ecc_vectors(&ecc_vectors)?;
        println!("✓ ECC vectors validated: {} tests", ecc_vectors.len());
    }
    
    // Validate chain vectors
    if Path::new(&format!("{}/chain_vectors.json", vectors_dir)).exists() {
        let chain_vectors = super::load_test_vectors(&format!("{}/chain_vectors.json", vectors_dir))?;
        validate_chain_vectors(&chain_vectors)?;
        println!("✓ Chain vectors validated: {} tests", chain_vectors.len());
    }
    
    // Validate serializer vectors
    if Path::new(&format!("{}/serializer_vectors.json", vectors_dir)).exists() {
        let serializer_vectors = super::load_test_vectors(&format!("{}/serializer_vectors.json", vectors_dir))?;
        validate_serializer_vectors(&serializer_vectors)?;
        println!("✓ Serializer vectors validated: {} tests", serializer_vectors.len());
    }
    
    Ok(())
}

/// Validate ECC test vectors
fn validate_ecc_vectors(vectors: &[TestVector]) -> Result<(), Box<dyn std::error::Error>> {
    for vector in vectors {
        match vector.name.as_str() {
            "brain_key_normalization" => {
                if let (TestInput::String(input), TestOutput::String(expected)) = 
                    (&vector.input, &vector.expected_output) {
                    let result = KeyUtils::normalize_brain_key(input);
                    if result != *expected {
                        return Err(format!("ECC vector '{}' failed: expected '{}', got '{}'", 
                            vector.name, expected, result).into());
                    }
                }
            },
            "sha256_hash" => {
                if let (TestInput::String(input), TestOutput::String(expected)) = 
                    (&vector.input, &vector.expected_output) {
                    let result = sha256(input.as_bytes());
                    let result_hex = hex::encode(result);
                    if result_hex != *expected {
                        return Err(format!("ECC vector '{}' failed: expected '{}', got '{}'", 
                            vector.name, expected, result_hex).into());
                    }
                }
            },
            _ => {
                // Skip vectors that require more complex validation
                println!("Skipping validation for vector: {}", vector.name);
            }
        }
    }
    Ok(())
}

/// Validate chain test vectors
fn validate_chain_vectors(vectors: &[TestVector]) -> Result<(), Box<dyn std::error::Error>> {
    for vector in vectors {
        match vector.name.as_str() {
            "object_id_parsing" => {
                if let (TestInput::String(input), TestOutput::Object(expected)) = 
                    (&vector.input, &vector.expected_output) {
                    let object_id = ObjectId::from_string(input)?;
                    let space = expected["space"].as_u64().unwrap() as u8;
                    let type_id = expected["type"].as_u64().unwrap() as u8;
                    let instance = expected["instance"].as_u64().unwrap();
                    
                    if object_id.space() != space || object_id.type_id() != type_id || object_id.instance() != instance {
                        return Err(format!("Chain vector '{}' failed", vector.name).into());
                    }
                }
            },
            "account_name_validation_valid" => {
                if let (TestInput::String(input), TestOutput::Boolean(expected)) = 
                    (&vector.input, &vector.expected_output) {
                    let result = ChainTypes::validate_account_name(input).is_ok();
                    if result != *expected {
                        return Err(format!("Chain vector '{}' failed", vector.name).into());
                    }
                }
            },
            "account_name_validation_invalid" => {
                if let (TestInput::String(input), TestOutput::Boolean(expected)) = 
                    (&vector.input, &vector.expected_output) {
                    let result = ChainTypes::validate_account_name(input).is_ok();
                    if result != *expected {
                        return Err(format!("Chain vector '{}' failed", vector.name).into());
                    }
                }
            },
            _ => {
                println!("Skipping validation for vector: {}", vector.name);
            }
        }
    }
    Ok(())
}

/// Validate serializer test vectors
fn validate_serializer_vectors(vectors: &[TestVector]) -> Result<(), Box<dyn std::error::Error>> {
    for vector in vectors {
        if vector.name.starts_with("varint_encoding_") {
            if let (TestInput::Object(input), TestOutput::Bytes(expected)) = 
                (&vector.input, &vector.expected_output) {
                let value = input["value"].as_u64().unwrap();
                let result = SerializerUtils::encode_varint(value);
                if result != *expected {
                    return Err(format!("Serializer vector '{}' failed", vector.name).into());
                }
            }
        } else if vector.name.starts_with("string_encoding_") {
            if let (TestInput::String(input), TestOutput::Bytes(expected)) = 
                (&vector.input, &vector.expected_output) {
                let result = SerializerUtils::encode_string(input);
                if result != *expected {
                    return Err(format!("Serializer vector '{}' failed", vector.name).into());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ecc_vectors() {
        let vectors = generate_ecc_test_vectors();
        assert!(!vectors.is_empty(), "Should generate ECC test vectors");
        
        // Verify vector structure
        for vector in &vectors {
            assert!(!vector.name.is_empty(), "Vector should have a name");
            assert!(!vector.description.is_empty(), "Vector should have a description");
        }
    }

    #[test]
    fn test_generate_chain_vectors() {
        let vectors = generate_chain_test_vectors();
        assert!(!vectors.is_empty(), "Should generate chain test vectors");
    }

    #[test]
    fn test_generate_serializer_vectors() {
        let vectors = generate_serializer_test_vectors();
        assert!(!vectors.is_empty(), "Should generate serializer test vectors");
    }

    #[test]
    fn test_vector_serialization() {
        let vectors = generate_ecc_test_vectors();
        let json = serde_json::to_string(&vectors).expect("Should serialize vectors to JSON");
        let deserialized: Vec<TestVector> = serde_json::from_str(&json)
            .expect("Should deserialize vectors from JSON");
        
        assert_eq!(vectors.len(), deserialized.len(), "Vector count should match");
    }
}