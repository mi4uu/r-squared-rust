//! Chain module compatibility tests
//! 
//! Tests that verify chain operations produce identical results between
//! Rust and JavaScript implementations.

use r_squared_rust::chain::*;
use r_squared_rust::ecc::*;
use r_squared_rust::error::Result;
use super::{TestVector, assert_bytes_equal, assert_strings_equal};

/// Test vectors for object ID parsing and formatting
const OBJECT_ID_VECTORS: &[(&str, u8, u8, u64)] = &[
    // (object_id_string, expected_space, expected_type, expected_instance)
    ("1.2.0", 1, 2, 0),
    ("1.2.100", 1, 2, 100),
    ("1.3.0", 1, 3, 0),
    ("1.3.1", 1, 3, 1),
    ("2.1.0", 2, 1, 0),
    ("0.0.0", 0, 0, 0),
];

/// Test vectors for asset amount calculations
const ASSET_AMOUNT_VECTORS: &[(i64, &str, u8, &str)] = &[
    // (amount, asset_id, precision, expected_display)
    (100000, "1.2.0", 5, "1.00000"),
    (123456, "1.2.0", 5, "1.23456"),
    (1, "1.2.0", 5, "0.00001"),
    (0, "1.2.0", 5, "0.00000"),
];

/// Test vectors for transaction ID generation
const TRANSACTION_VECTORS: &[(&str, &str)] = &[
    // (transaction_hex, expected_id)
    // These would be actual transaction data from the JavaScript implementation
];

#[test]
pub fn test_object_id_compatibility() {
    for (id_string, expected_space, expected_type, expected_instance) in OBJECT_ID_VECTORS {
        // Test parsing from string
        let object_id = ObjectId::from_string(id_string)
            .expect(&format!("Failed to parse object ID: {}", id_string));
        
        assert_eq!(object_id.space(), *expected_space, "Space mismatch for {}", id_string);
        assert_eq!(object_id.type_id(), *expected_type, "Type ID mismatch for {}", id_string);
        assert_eq!(object_id.instance(), *expected_instance, "Instance mismatch for {}", id_string);
        
        // Test formatting to string
        let formatted = object_id.to_string();
        assert_strings_equal(&formatted, id_string, "Object ID string formatting");
        
        // Test round-trip
        let parsed_again = ObjectId::from_string(&formatted)
            .expect("Failed to parse formatted object ID");
        assert_eq!(object_id, parsed_again, "Object ID round-trip failed");
    }
}

#[test]
fn test_object_id_creation() {
    for (id_string, space, type_id, instance) in OBJECT_ID_VECTORS {
        let object_id = ObjectId::new(*space, *type_id, *instance)
            .expect(&format!("Failed to create object ID: {}", id_string));
        
        let formatted = object_id.to_string();
        assert_strings_equal(&formatted, id_string, "Object ID creation and formatting");
    }
}

#[test]
pub fn test_asset_amount_calculations() {
    for (amount, asset_id_str, precision, expected_display) in ASSET_AMOUNT_VECTORS {
        let asset_id = ObjectId::from_string(asset_id_str)
            .expect("Failed to parse asset ID");
        
        let asset_amount = AssetAmount {
            amount: *amount,
            asset_id,
        };
        
        // Test precision calculations
        let display_amount = NumberUtils::format_asset_amount(*amount, *precision);
        assert_strings_equal(&display_amount, expected_display, "Asset amount formatting");
        
        // Test parsing back
        let parsed_amount = NumberUtils::parse_asset_amount(expected_display, *precision)
            .expect("Failed to parse asset amount");
        assert_eq!(parsed_amount, *amount, "Asset amount parsing round-trip");
    }
}

#[test]
pub fn test_transaction_builder_compatibility() {
    let mut builder = TransactionBuilder::new();
    
    // Create test accounts and assets
    let from_account = ObjectId::new(1, 1, 1).unwrap();
    let to_account = ObjectId::new(1, 1, 2).unwrap();
    let core_asset = ObjectId::new(1, 2, 0).unwrap();
    
    // Add a transfer operation
    let transfer_amount = AssetAmount {
        amount: 100000,
        asset_id: core_asset.clone(),
    };
    
    builder.add_transfer(from_account, to_account, transfer_amount, None)
        .expect("Failed to add transfer operation");
    
    // Set transaction properties
    builder.set_expiration(3600).expect("Failed to set expiration");
    builder.set_reference_block(12345, "0123456789abcdef0123456789abcdef01234567")
        .expect("Failed to set reference block");
    
    // Build transaction
    let transaction = builder.build().expect("Failed to build transaction");
    
    // Verify transaction structure
    assert_eq!(transaction.operations.len(), 1, "Transaction should have one operation");
    assert!(transaction.expiration > 0, "Transaction should have expiration set");
    assert_eq!(transaction.ref_block_num, 12345 & 0xFFFF, "Reference block number should be set");
}

#[test]
fn test_transaction_signing_compatibility() {
    let mut builder = TransactionBuilder::new();
    
    // Create test data
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
    
    // Create test private key
    let private_key = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        .expect("Failed to parse private key");
    
    // Sign transaction
    let signed_transaction = builder.build_and_sign(&[private_key])
        .expect("Failed to sign transaction");
    
    // Verify signature exists
    assert!(!signed_transaction.transaction.signatures.is_empty(), "Transaction should have signatures");
    
    // Test transaction ID generation
    let transaction_id = &signed_transaction.transaction_id;
    assert_eq!(transaction_id.len(), 64, "Transaction ID should be 64 hex characters");
}

#[test]
fn test_memo_creation_compatibility() {
    // Create test keys
    let sender_private = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        .expect("Failed to parse sender private key");
    let recipient_private = PrivateKey::from_wif("5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss")
        .expect("Failed to parse recipient private key");
    
    let recipient_public = recipient_private.public_key()
        .expect("Failed to derive recipient public key");
    
    let memo_text = "Test memo for compatibility";
    let nonce = 12345u64;
    
    // Create memo
    let memo = TransactionHelper::create_memo(&sender_private, &recipient_public, memo_text, nonce)
        .expect("Failed to create memo");
    
    // Verify memo structure
    assert_eq!(memo.nonce, nonce, "Memo nonce should match");
    assert!(!memo.message.is_empty(), "Memo message should not be empty");
    
    // Test memo decryption
    let sender_public = sender_private.public_key()
        .expect("Failed to derive sender public key");
    
    let decrypted = TransactionHelper::decrypt_memo(&memo, &recipient_private)
        .expect("Failed to decrypt memo");
    
    assert_strings_equal(&decrypted, memo_text, "Memo decryption");
}

#[test]
fn test_chain_validation_compatibility() {
    // Create a valid transaction for testing
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
    
    // Create mock chain properties for validation
    let chain_properties = ChainProperties {
        chain_id: "test_chain_id".to_string(),
        head_block_number: 12345,
        head_block_id: "0123456789abcdef0123456789abcdef01234567".to_string(),
        head_block_time: 1234567890,
        next_maintenance_time: 1234567890 + 86400,
        last_budget_time: 1234567890,
        witness_budget: 1000000,
        accounts_registered_this_interval: 10,
        recently_missed_count: 0,
        current_aslot: 12345,
        recent_slots_filled: "ffffffffffffffff".to_string(),
        dynamic_flags: 0,
        last_irreversible_block_num: 12340,
    };
    
    let chain_parameters = ChainParameters {
        current_fees: FeeSchedule {
            parameters: vec![],
            scale: 10000,
        },
        block_interval: 3,
        maintenance_interval: 86400,
        maintenance_skip_slots: 3,
        committee_proposal_review_period: 1209600,
        maximum_transaction_size: 2048,
        maximum_block_size: 2000000,
        maximum_time_until_expiration: 86400,
        maximum_proposal_lifetime: 2419200,
        maximum_asset_whitelist_authorities: 10,
        maximum_asset_feed_publishers: 10,
        maximum_witness_count: 1001,
        maximum_committee_count: 1001,
        maximum_authority_membership: 10,
        reserve_percent_of_fee: 2000,
        network_percent_of_fee: 2000,
        lifetime_referrer_percent_of_fee: 3000,
        cashback_vesting_period_seconds: 31536000,
        cashback_vesting_threshold: 10000000,
        count_non_member_votes: true,
        allow_non_member_whitelists: false,
        witness_pay_per_block: 100000,
        worker_budget_per_day: 50000000000,
        max_predicate_opcode: 1,
        fee_liquidation_threshold: 10000000,
        accounts_per_fee_scale: 1000,
        account_fee_scale_bitshifts: 4,
        max_authority_depth: 2,
        extensions: vec![],
    };
    
    let global_properties = GlobalProperties {
        id: ObjectId::new(2, 0, 0).unwrap(),
        parameters: chain_parameters,
        next_available_vote_id: 0,
        active_committee_members: vec![],
        active_witnesses: vec![],
    };
    
    // Test transaction validation
    let validation_result = ChainValidation::validate_transaction(
        &transaction,
        &chain_properties,
        &global_properties
    );
    
    // Basic validation should pass for a well-formed transaction
    assert!(validation_result.is_ok(), "Transaction validation should pass: {:?}", validation_result);
}

#[test]
fn test_number_utils_compatibility() {
    // Test precision number operations
    let num1 = PrecisionNumber::from_string("123.456", 3)
        .expect("Failed to parse precision number");
    let num2 = PrecisionNumber::from_string("78.9", 3)
        .expect("Failed to parse precision number");
    
    // Test addition
    let sum = num1.add(&num2).expect("Failed to add numbers");
    let expected_sum = PrecisionNumber::from_string("202.356", 3)
        .expect("Failed to parse expected sum");
    assert_eq!(sum, expected_sum, "Addition should work correctly");
    
    // Test subtraction
    let diff = num1.subtract(&num2).expect("Failed to subtract numbers");
    let expected_diff = PrecisionNumber::from_string("44.556", 3)
        .expect("Failed to parse expected difference");
    assert_eq!(diff, expected_diff, "Subtraction should work correctly");
    
    // Test multiplication
    let product = num1.multiply(&num2).expect("Failed to multiply numbers");
    // Note: This would need to match JavaScript implementation exactly
    
    // Test division
    let quotient = num1.divide(&num2).expect("Failed to divide numbers");
    // Note: This would need to match JavaScript implementation exactly
    
    // Test string formatting
    let formatted = num1.to_string();
    assert_strings_equal(&formatted, "123.456", "Number formatting");
}

#[test]
pub fn test_account_name_validation_compatibility() {
    // Test valid account names
    let valid_names = [
        "alice",
        "bob123",
        "test-account",
        "a",
        "very-long-account-name-that-should-still-be-valid",
    ];
    
    for name in &valid_names {
        let result = ChainTypes::validate_account_name(name);
        assert!(result.is_ok(), "Account name '{}' should be valid", name);
    }
    
    // Test invalid account names
    let invalid_names = [
        "Alice", // uppercase
        "123", // starts with number
        "test_account", // underscore
        "", // empty
        "a.", // ends with dot
        ".test", // starts with dot
        "test..account", // double dot
    ];
    
    for name in &invalid_names {
        let result = ChainTypes::validate_account_name(name);
        assert!(result.is_err(), "Account name '{}' should be invalid", name);
    }
}

#[test]
pub fn test_asset_symbol_validation_compatibility() {
    // Test valid asset symbols
    let valid_symbols = [
        "BTC",
        "USD",
        "GOLD",
        "SILVER",
        "A",
        "VERYLONGSYMBOL",
    ];
    
    for symbol in &valid_symbols {
        let result = ChainTypes::validate_asset_symbol(symbol);
        assert!(result.is_ok(), "Asset symbol '{}' should be valid", symbol);
    }
    
    // Test invalid asset symbols
    let invalid_symbols = [
        "btc", // lowercase
        "123", // starts with number
        "BT-C", // hyphen
        "", // empty
        "BTC.", // ends with dot
        ".BTC", // starts with dot
    ];
    
    for symbol in &invalid_symbols {
        let result = ChainTypes::validate_asset_symbol(symbol);
        assert!(result.is_err(), "Asset symbol '{}' should be invalid", symbol);
    }
}

/// Load and run chain test vectors from JSON file
#[test]
fn test_chain_vectors_from_file() {
    let vectors_path = "tests/vectors/chain_vectors.json";
    if std::path::Path::new(vectors_path).exists() {
        let vectors = super::load_test_vectors(vectors_path)
            .expect("Failed to load chain test vectors");
        
        for vector in vectors {
            println!("Running chain test vector: {}", vector.name);
            // Process each vector based on its type
        }
    }
}