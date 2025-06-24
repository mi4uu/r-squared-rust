//! Integration tests for the R-Squared Rust library

use r_squared_rust::prelude::*;

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
fn test_memory_storage_adapter() {
    use r_squared_rust::storage::MemoryAdapter;
    use r_squared_rust::storage::adapter::StorageAdapter;
    
    let adapter = MemoryAdapter::new();
    let key = "test_key";
    let data = b"test_data";
    
    // Test store and retrieve
    adapter.store(key, data).expect("Failed to store data");
    let retrieved = adapter.retrieve(key).expect("Failed to retrieve data");
    assert_eq!(retrieved, data);
    
    // Test exists
    assert!(adapter.exists(key).expect("Failed to check existence"));
    
    // Test delete
    adapter.delete(key).expect("Failed to delete data");
    assert!(!adapter.exists(key).expect("Failed to check existence after delete"));
}

#[test]
fn test_transaction_builder() {
    use r_squared_rust::chain::{TransactionBuilder, Operation};
    
    let mut builder = TransactionBuilder::new();
    let operation = Operation {
        op_type: "test".to_string(),
        data: vec![1, 2, 3, 4],
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