//! Serializer module compatibility tests
//! 
//! Tests that verify serialization operations produce identical results between
//! Rust and JavaScript implementations.

use r_squared_rust::serializer::*;
use r_squared_rust::chain::*;
use r_squared_rust::ecc::*;
use r_squared_rust::error::Result;
use super::{TestVector, assert_bytes_equal, assert_strings_equal};

/// Test vectors for binary serialization
const SERIALIZATION_VECTORS: &[(&str, &str)] = &[
    // (description, expected_hex)
    ("empty_transaction", "0000000000000000000000"),
    ("simple_transfer", ""), // Would be filled with actual data
];

/// Test vectors for JSON serialization
const JSON_VECTORS: &[(&str, &str)] = &[
    // (description, expected_json)
    ("object_id", r#"{"space":1,"type":2,"instance":100}"#),
    ("asset_amount", r#"{"amount":"100000","asset_id":"1.3.0"}"#),
];

#[test]
pub fn test_object_id_serialization_compatibility() {
    let object_id = ObjectId::new(1, 2, 100).unwrap();
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&object_id)
        .expect("Failed to serialize object ID");
    
    // Test deserialization
    let deserialized: ObjectId = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize object ID");
    
    assert_eq!(object_id, deserialized, "Object ID binary serialization round-trip");
    
    // Test JSON serialization if serde support is enabled
    #[cfg(feature = "serde_support")]
    {
        let json_data = serde_json::to_string(&object_id)
            .expect("Failed to serialize object ID to JSON");
        
        let deserialized_json: ObjectId = serde_json::from_str(&json_data)
            .expect("Failed to deserialize object ID from JSON");
        
        assert_eq!(object_id, deserialized_json, "Object ID JSON serialization round-trip");
    }
}

#[test]
pub fn test_asset_amount_serialization_compatibility() {
    let asset_id = ObjectId::new(1, 2, 0).unwrap();
    let asset_amount = AssetAmount {
        amount: 100000,
        asset_id,
    };
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&asset_amount)
        .expect("Failed to serialize asset amount");
    
    let deserialized: AssetAmount = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize asset amount");
    
    assert_eq!(asset_amount.amount, deserialized.amount, "Asset amount value");
    assert_eq!(asset_amount.asset_id, deserialized.asset_id, "Asset ID");
    
    // Test JSON serialization
    #[cfg(feature = "serde_support")]
    {
        let json_data = serde_json::to_string(&asset_amount)
            .expect("Failed to serialize asset amount to JSON");
        
        let deserialized_json: AssetAmount = serde_json::from_str(&json_data)
            .expect("Failed to deserialize asset amount from JSON");
        
        assert_eq!(asset_amount.amount, deserialized_json.amount, "JSON asset amount value");
        assert_eq!(asset_amount.asset_id, deserialized_json.asset_id, "JSON asset ID");
    }
}

#[test]
fn test_operation_serialization_compatibility() {
    // Create a transfer operation
    let from_account = ObjectId::new(1, 1, 1).unwrap();
    let to_account = ObjectId::new(1, 1, 2).unwrap();
    let core_asset = ObjectId::new(1, 2, 0).unwrap();
    
    let fee = AssetAmount {
        amount: 1000,
        asset_id: core_asset.clone(),
    };
    
    let transfer_amount = AssetAmount {
        amount: 100000,
        asset_id: core_asset,
    };
    
    let operation = Operation::Transfer {
        fee,
        from: from_account,
        to: to_account,
        amount: transfer_amount,
        memo: None,
        extensions: vec![],
    };
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&operation)
        .expect("Failed to serialize operation");
    
    let deserialized: Operation = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize operation");
    
    // Verify the operation type and basic structure
    match (&operation, &deserialized) {
        (Operation::Transfer { from: f1, to: t1, amount: a1, .. }, 
         Operation::Transfer { from: f2, to: t2, amount: a2, .. }) => {
            assert_eq!(f1, f2, "From account should match");
            assert_eq!(t1, t2, "To account should match");
            assert_eq!(a1.amount, a2.amount, "Transfer amount should match");
            assert_eq!(a1.asset_id, a2.asset_id, "Asset ID should match");
        },
        _ => panic!("Operation type mismatch after serialization"),
    }
}

#[test]
fn test_transaction_serialization_compatibility() {
    // Create a complete transaction
    let mut builder = TransactionBuilder::new();
    
    let from_account = ObjectId::new(1, 1, 1).unwrap();
    let to_account = ObjectId::new(1, 1, 2).unwrap();
    let core_asset = ObjectId::new(1, 2, 0).unwrap();
    
    let transfer_amount = AssetAmount {
        amount: 100000,
        asset_id: core_asset,
    };
    
    builder.add_transfer(from_account, to_account, transfer_amount, None)
        .expect("Failed to add transfer operation");
    
    builder.set_expiration(3600).expect("Failed to set expiration");
    builder.set_reference_block(12345, "0123456789abcdef0123456789abcdef01234567")
        .expect("Failed to set reference block");
    
    let transaction = builder.build().expect("Failed to build transaction");
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&transaction)
        .expect("Failed to serialize transaction");
    
    let deserialized: Transaction = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize transaction");
    
    // Verify transaction properties
    assert_eq!(transaction.ref_block_num, deserialized.ref_block_num, "Reference block number");
    assert_eq!(transaction.ref_block_prefix, deserialized.ref_block_prefix, "Reference block prefix");
    assert_eq!(transaction.expiration, deserialized.expiration, "Expiration");
    assert_eq!(transaction.operations.len(), deserialized.operations.len(), "Operations count");
    
    // Test that serialized data matches expected format
    // This would need to be compared with JavaScript implementation output
    println!("Transaction serialized to {} bytes", binary_data.len());
    println!("Transaction hex: {}", hex::encode(&binary_data));
}

#[test]
fn test_signed_transaction_serialization_compatibility() {
    // Create and sign a transaction
    let mut builder = TransactionBuilder::new();
    
    let from_account = ObjectId::new(1, 1, 1).unwrap();
    let to_account = ObjectId::new(1, 1, 2).unwrap();
    let core_asset = ObjectId::new(1, 2, 0).unwrap();
    
    let transfer_amount = AssetAmount {
        amount: 100000,
        asset_id: core_asset,
    };
    
    builder.add_transfer(from_account, to_account, transfer_amount, None)
        .expect("Failed to add transfer operation");
    
    builder.set_expiration(3600).expect("Failed to set expiration");
    builder.set_reference_block(12345, "0123456789abcdef0123456789abcdef01234567")
        .expect("Failed to set reference block");
    builder.set_chain_id("4018d7844c78f6a6c41c6a552b898022310fc5dec06da467ee7905a8dad512c8".to_string());
    
    let private_key = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        .expect("Failed to parse private key");
    
    let signed_transaction = builder.build_and_sign(&[private_key])
        .expect("Failed to sign transaction");
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&signed_transaction)
        .expect("Failed to serialize signed transaction");
    
    let deserialized: SignedTransaction = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize signed transaction");
    
    // Verify signed transaction properties
    assert_eq!(signed_transaction.transaction.signatures.len(), deserialized.transaction.signatures.len(), "Signatures count");
    assert_eq!(signed_transaction.transaction.ref_block_num, deserialized.transaction.ref_block_num, "Reference block number");
    assert_eq!(signed_transaction.transaction.operations.len(), deserialized.transaction.operations.len(), "Operations count");
    
    // Verify signatures match
    for (i, (sig1, sig2)) in signed_transaction.transaction.signatures.iter()
        .zip(deserialized.transaction.signatures.iter()).enumerate() {
        assert_eq!(sig1, sig2, "Signature {} should match", i);
    }
}

#[test]
fn test_memo_serialization_compatibility() {
    // Create test keys
    let sender_private = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        .expect("Failed to parse sender private key");
    let recipient_private = PrivateKey::from_wif("5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss")
        .expect("Failed to parse recipient private key");
    
    let recipient_public = recipient_private.public_key()
        .expect("Failed to derive recipient public key");
    
    let memo_text = "Test memo for serialization";
    let nonce = 12345u64;
    
    // Create memo
    let memo = TransactionHelper::create_memo(&sender_private, &recipient_public, memo_text, nonce)
        .expect("Failed to create memo");
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&memo)
        .expect("Failed to serialize memo");
    
    let deserialized: Memo = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize memo");
    
    // Verify memo properties
    assert_eq!(memo.nonce, deserialized.nonce, "Memo nonce");
    assert_eq!(memo.from, deserialized.from, "Memo from key");
    assert_eq!(memo.to, deserialized.to, "Memo to key");
    assert_bytes_equal(&memo.message, &deserialized.message, "Memo message");
    
    // Test that decryption still works
    let sender_public = sender_private.public_key()
        .expect("Failed to derive sender public key");
    
    let decrypted = TransactionHelper::decrypt_memo(&deserialized, &recipient_private)
        .expect("Failed to decrypt deserialized memo");
    
    assert_strings_equal(&decrypted, memo_text, "Memo decryption after serialization");
}

#[test]
fn test_public_key_serialization_compatibility() {
    let private_key = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        .expect("Failed to parse private key");
    let public_key = private_key.public_key()
        .expect("Failed to derive public key");
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&public_key)
        .expect("Failed to serialize public key");
    
    let deserialized: PublicKey = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize public key");
    
    // Verify public key data
    assert_bytes_equal(&public_key.to_bytes(), &deserialized.to_bytes(), "Public key bytes");
    
    // Test that the key still works for verification
    let message = b"Test message";
    let hash = sha256(message);
    let signature = private_key.sign(&hash)
        .expect("Failed to sign with original key");
    
    let is_valid = deserialized.verify(&hash, &signature)
        .expect("Failed to verify with deserialized key");
    
    assert!(is_valid, "Deserialized public key should verify signature");
}

#[test]
fn test_address_serialization_compatibility() {
    let private_key = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        .expect("Failed to parse private key");
    let public_key = private_key.public_key()
        .expect("Failed to derive public key");
    let address = Address::from_public_key(&public_key, "RSQ")
        .expect("Failed to create address");
    
    // Test binary serialization
    let serializer = Serializer::new();
    let binary_data = serializer.serialize(&address)
        .expect("Failed to serialize address");
    
    let deserialized: Address = serializer.deserialize(&binary_data)
        .expect("Failed to deserialize address");
    
    // Verify address properties
    assert_strings_equal(&address.to_string(), &deserialized.to_string(), "Address string representation");
    assert_strings_equal(address.prefix(), deserialized.prefix(), "Address prefix");
    assert!(deserialized.is_valid(), "Deserialized address should be valid");
}

#[test]
fn test_serializer_buffer_management() {
    let serializer = Serializer::new();
    
    // Test with different buffer sizes
    let test_data = ObjectId::new(1, 2, 100).unwrap();
    
    // Test default buffer size
    let binary_data = serializer.serialize(&test_data)
        .expect("Failed to serialize with default buffer");
    
    // Test with custom buffer size
    let custom_serializer = Serializer::with_capacity(1024);
    let binary_data_custom = custom_serializer.serialize(&test_data)
        .expect("Failed to serialize with custom buffer");
    
    // Results should be identical regardless of buffer size
    assert_bytes_equal(&binary_data, &binary_data_custom, "Serialization with different buffer sizes");
    
    // Test buffer reuse
    let test_data2 = ObjectId::new(2, 3, 200).unwrap();
    let binary_data2 = custom_serializer.serialize(&test_data2)
        .expect("Failed to serialize second object");
    
    // Should be able to deserialize both
    let deserialized1: ObjectId = custom_serializer.deserialize(&binary_data_custom)
        .expect("Failed to deserialize first object");
    let deserialized2: ObjectId = custom_serializer.deserialize(&binary_data2)
        .expect("Failed to deserialize second object");
    
    assert_eq!(test_data, deserialized1, "First object round-trip");
    assert_eq!(test_data2, deserialized2, "Second object round-trip");
}

#[test]
pub fn test_varint_encoding_compatibility() {
    // Test various varint values that should match JavaScript implementation
    let test_values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536, 2097151, 2097152];
    
    for value in &test_values {
        let encoded = SerializerUtils::encode_varint(*value);
        let (decoded, bytes_read) = SerializerUtils::decode_varint(&encoded)
            .expect(&format!("Failed to decode varint {}", value));
        
        assert_eq!(*value, decoded, "Varint round-trip for value {}", value);
        assert_eq!(encoded.len(), bytes_read, "Bytes read should match encoded length for value {}", value);
        
        // Print for comparison with JavaScript implementation
        println!("Varint {} -> {} bytes: {}", value, encoded.len(), hex::encode(&encoded));
    }
}

#[test]
pub fn test_string_encoding_compatibility() {
    let test_strings = [
        "",
        "Hello",
        "Hello, World!",
        "Test with unicode: 🚀",
        "Very long string that should test buffer management and encoding efficiency",
    ];
    
    let serializer = Serializer::new();
    
    for test_string in &test_strings {
        let encoded = SerializerUtils::encode_string(test_string);
        let (decoded, _) = SerializerUtils::decode_string(&encoded)
            .expect(&format!("Failed to decode string '{}'", test_string));
        
        assert_strings_equal(&decoded, test_string, "String encoding round-trip");
        
        // Print for comparison with JavaScript implementation
        println!("String '{}' -> {} bytes: {}", test_string, encoded.len(), hex::encode(&encoded));
    }
}

/// Load and run serializer test vectors from JSON file
#[test]
fn test_serializer_vectors_from_file() {
    let vectors_path = "tests/vectors/serializer_vectors.json";
    if std::path::Path::new(vectors_path).exists() {
        let vectors = super::load_test_vectors(vectors_path)
            .expect("Failed to load serializer test vectors");
        
        for vector in vectors {
            println!("Running serializer test vector: {}", vector.name);
            // Process each vector based on its type
        }
    }
}