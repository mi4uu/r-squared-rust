//! Integration tests for the R-Squared Rust library

use r_squared_rust::prelude::*;
use r_squared_rust::ecc::sha256;
use r_squared_rust::chain::ObjectId;
use r_squared_rust::serializer::Serializer;

mod compatibility;

#[test]
fn test_library_version() {
    assert!(!r_squared_rust::VERSION.is_empty());
    assert_eq!(r_squared_rust::CRATE_NAME, "r-squared-rust");
}

#[test]
fn test_ecc_key_generation() {
    let private_key = PrivateKey::generate().expect("Failed to generate private key");
    let _public_key = private_key.public_key();
    // Basic test to ensure key generation works
}

#[test]
fn test_local_storage() {
    use r_squared_rust::storage::{LocalStorage, LocalConfig, StorageConfig, StorageApiSync};
    use bytes::Bytes;
    use tempfile::TempDir;
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let local_config = LocalConfig {
        base_path: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    let storage_config = StorageConfig::default();
    let storage = LocalStorage::new(local_config, storage_config).expect("Failed to create storage");
    
    let key = "test_key";
    let data = Bytes::from("test_data");
    
    // Test store and retrieve
    storage.put(key, data.clone()).expect("Failed to store data");
    let retrieved = storage.get(key).expect("Failed to retrieve data");
    assert_eq!(retrieved, data);
    
    // Test exists
    assert!(storage.exists(key).expect("Failed to check existence"));
    
    // Test delete
    storage.delete(key).expect("Failed to delete data");
    assert!(!storage.exists(key).expect("Failed to check existence after delete"));
}

#[test]
fn test_transaction_builder() {
    use r_squared_rust::chain::{TransactionBuilder, Operation, ObjectId, AssetAmount};
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let mut builder = TransactionBuilder::new();
    
    // Set chain_id and expiration
    builder.set_chain_id("4018d7844c78f6a6c41c6a552b898022310fc5dec06da467ee7905a8dad512c8".to_string());
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600; // 1 hour from now
    builder.set_expiration(expiration as u32);
    
    // Use a valid Operation enum variant with all required fields
    let operation = Operation::Transfer {
        fee: AssetAmount {
            amount: 1000,
            asset_id: ObjectId::new(1, 2, 0).unwrap(), // Core asset (1.2.0)
        },
        from: ObjectId::new(1, 1, 1).unwrap(), // Account (1.1.1)
        to: ObjectId::new(1, 1, 2).unwrap(),   // Account (1.1.2)
        amount: AssetAmount {
            amount: 10000,
            asset_id: ObjectId::new(1, 2, 0).unwrap(), // Core asset (1.2.0)
        },
        memo: None,
        extensions: vec![],
    };
    
    builder.add_operation(operation).expect("Failed to add operation");
    let _transaction = builder.build().expect("Failed to build transaction");
}

#[test]
fn test_error_types() {
    use r_squared_rust::error::{Error, EccError};
    
    let ecc_error = EccError::InvalidPrivateKey {
        reason: "test error".to_string(),
    };
    let error = Error::Ecc(ecc_error);
    
    assert!(error.to_string().contains("ECC error"));
}

/// Integration test that runs all compatibility tests
#[test]
fn test_javascript_compatibility() {
    println!("Running JavaScript compatibility verification tests...");
    
    // This test ensures that all compatibility tests pass
    // The actual compatibility tests are in the compatibility module
    
    // Test ECC compatibility
    compatibility::ecc_compatibility::test_private_key_to_public_key_compatibility();
    compatibility::ecc_compatibility::test_brain_key_compatibility();
    compatibility::ecc_compatibility::test_address_generation_compatibility();
    compatibility::ecc_compatibility::test_signature_compatibility();
    compatibility::ecc_compatibility::test_memo_encryption_compatibility();
    compatibility::ecc_compatibility::test_hash_function_compatibility();
    
    // Test Chain compatibility
    compatibility::chain_compatibility::test_object_id_compatibility();
    compatibility::chain_compatibility::test_asset_amount_calculations();
    compatibility::chain_compatibility::test_transaction_builder_compatibility();
    compatibility::chain_compatibility::test_account_name_validation_compatibility();
    compatibility::chain_compatibility::test_asset_symbol_validation_compatibility();
    
    // Test Serializer compatibility
    compatibility::serializer_compatibility::test_object_id_serialization_compatibility();
    compatibility::serializer_compatibility::test_asset_amount_serialization_compatibility();
    compatibility::serializer_compatibility::test_varint_encoding_compatibility();
    compatibility::serializer_compatibility::test_string_encoding_compatibility();
    
    println!("✓ All JavaScript compatibility tests passed!");
}

/// Test that generates and validates test vectors
#[test]
fn test_vector_generation_and_validation() {
    use compatibility::test_vectors::*;
    
    // Generate test vectors
    let ecc_vectors = generate_ecc_test_vectors();
    let chain_vectors = generate_chain_test_vectors();
    let serializer_vectors = generate_serializer_test_vectors();
    
    assert!(!ecc_vectors.is_empty(), "Should generate ECC test vectors");
    assert!(!chain_vectors.is_empty(), "Should generate chain test vectors");
    assert!(!serializer_vectors.is_empty(), "Should generate serializer test vectors");
    
    println!("Generated {} ECC test vectors", ecc_vectors.len());
    println!("Generated {} chain test vectors", chain_vectors.len());
    println!("Generated {} serializer test vectors", serializer_vectors.len());
}

/// Performance comparison test
#[test]
fn test_performance_baseline() {
    use std::time::Instant;
    
    println!("Running performance baseline tests...");
    
    // ECC performance baseline
    let start = Instant::now();
    for _ in 0..100 {
        let private_key = PrivateKey::generate().unwrap();
        let _public_key = private_key.public_key().unwrap();
    }
    let ecc_duration = start.elapsed();
    println!("ECC key generation (100 iterations): {:?}", ecc_duration);
    
    // Hash performance baseline
    let test_data = b"Performance test data for hash functions";
    let start = Instant::now();
    for _ in 0..1000 {
        let _hash = sha256(test_data);
    }
    let hash_duration = start.elapsed();
    println!("SHA-256 hashing (1000 iterations): {:?}", hash_duration);
    
    // Serialization performance baseline
    let object_id = ObjectId::new(1, 2, 100).unwrap();
    let serializer = Serializer::new();
    let start = Instant::now();
    for _ in 0..1000 {
        let data = serializer.serialize(&object_id).unwrap();
        let _deserialized: ObjectId = serializer.deserialize(&data).unwrap();
    }
    let serialization_duration = start.elapsed();
    println!("Object ID serialization round-trip (1000 iterations): {:?}", serialization_duration);
    
    // These baselines can be compared with JavaScript implementation
    assert!(ecc_duration.as_millis() < 10000, "ECC operations should be reasonably fast");
    assert!(hash_duration.as_millis() < 1000, "Hash operations should be fast");
    assert!(serialization_duration.as_millis() < 1000, "Serialization should be fast");
}