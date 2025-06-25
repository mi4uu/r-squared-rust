//! Serialization validation and integrity checks
//!
//! This module provides validation functions for ensuring data integrity
//! during serialization and deserialization processes.

use crate::error::{SerializerError, SerializerResult};
use crate::chain::{Transaction, Operation, AssetAmount, ObjectId, Authority, Memo};
use crate::serializer::SerializerTypes;
use std::collections::HashMap;

#[cfg(feature = "serde_support")]
use serde::{Serialize, Deserialize};

/// Serialization validation and integrity checks
pub struct SerializerValidation;

impl SerializerValidation {
    /// Validate data before serialization
    pub fn validate_before_serialization<T>(_data: &T) -> SerializerResult<()>
    where
        T: ?Sized,
    {
        // Generic validation - for now just return Ok
        // In a real implementation, this would perform type-specific validation
        Ok(())
    }

    /// Validate data after deserialization
    pub fn validate_after_deserialization<T>(_data: &T) -> SerializerResult<()>
    where
        T: ?Sized,
    {
        // Generic validation - for now just return Ok
        // In a real implementation, this would perform type-specific validation
        Ok(())
    }

    /// Validate transaction structure and content
    pub fn validate_transaction(transaction: &Transaction) -> SerializerResult<()> {
        // Check basic transaction structure
        if transaction.operations.is_empty() {
            return Err(SerializerError::InvalidFormat {
                expected: "At least one operation".to_string(),
                actual: "Empty operations list".to_string(),
            });
        }

        if transaction.operations.len() > super::constants::MAX_OPERATIONS_COUNT {
            return Err(SerializerError::BufferError {
                reason: format!(
                    "Too many operations: {} > {}",
                    transaction.operations.len(),
                    super::constants::MAX_OPERATIONS_COUNT
                ),
            });
        }

        // Validate expiration
        if transaction.expiration == 0 {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-zero expiration".to_string(),
                actual: "Zero expiration".to_string(),
            });
        }

        // Validate each operation
        for (i, operation) in transaction.operations.iter().enumerate() {
            Self::validate_operation(operation).map_err(|e| {
                SerializerError::InvalidFormat {
                    expected: format!("Valid operation at index {}", i),
                    actual: format!("Invalid operation: {}", e),
                }
            })?;
        }

        // Validate extensions
        for extension in &transaction.extensions {
            Self::validate_extension(&extension.data)?;
        }

        Ok(())
    }

    /// Validate operation structure and content
    pub fn validate_operation(operation: &Operation) -> SerializerResult<()> {
        match operation {
            Operation::Transfer { from, to, amount, fee, memo, extensions } => {
                Self::validate_object_id(from, "account")?;
                Self::validate_object_id(to, "account")?;
                Self::validate_asset_amount(amount)?;
                Self::validate_asset_amount(fee)?;
                
                if let Some(memo) = memo {
                    Self::validate_memo(memo)?;
                }
                
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::LimitOrderCreate { seller, amount_to_sell, min_to_receive, expiration, fill_or_kill, fee, extensions } => {
                Self::validate_object_id(seller, "account")?;
                Self::validate_asset_amount(amount_to_sell)?;
                Self::validate_asset_amount(min_to_receive)?;
                Self::validate_asset_amount(fee)?;
                
                if *expiration == 0 {
                    return Err(SerializerError::InvalidFormat {
                        expected: "Non-zero expiration".to_string(),
                        actual: "Zero expiration".to_string(),
                    });
                }
                
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::LimitOrderCancel { fee_paying_account, order, fee, extensions } => {
                Self::validate_object_id(fee_paying_account, "account")?;
                Self::validate_object_id(order, "limit_order")?;
                Self::validate_asset_amount(fee)?;
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::AccountCreate { registrar, referrer, referrer_percent, name, owner, active, options, fee, extensions } => {
                Self::validate_object_id(registrar, "account")?;
                Self::validate_object_id(referrer, "account")?;
                Self::validate_asset_amount(fee)?;
                
                if *referrer_percent > 10000 {
                    return Err(SerializerError::InvalidFormat {
                        expected: "Referrer percent <= 10000".to_string(),
                        actual: format!("Referrer percent: {}", referrer_percent),
                    });
                }
                
                Self::validate_account_name(name)?;
                Self::validate_authority(owner)?;
                Self::validate_authority(active)?;
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::AccountUpdate { account, owner, active, new_options, fee, extensions } => {
                Self::validate_object_id(account, "account")?;
                Self::validate_asset_amount(fee)?;
                
                if let Some(owner) = owner {
                    Self::validate_authority(owner)?;
                }
                
                if let Some(active) = active {
                    Self::validate_authority(active)?;
                }
                
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::AssetCreate { issuer, symbol, precision, common_options, bitasset_opts, is_prediction_market, fee, extensions } => {
                Self::validate_object_id(issuer, "account")?;
                Self::validate_asset_amount(fee)?;
                Self::validate_asset_symbol(symbol)?;
                
                if *precision > 12 {
                    return Err(SerializerError::InvalidFormat {
                        expected: "Asset precision <= 12".to_string(),
                        actual: format!("Asset precision: {}", precision),
                    });
                }
                
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::AssetUpdate { issuer, asset_to_update, new_options, fee, extensions } => {
                Self::validate_object_id(issuer, "account")?;
                Self::validate_object_id(asset_to_update, "asset")?;
                Self::validate_asset_amount(fee)?;
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::AssetIssue { issuer, asset_to_issue, issue_to_account, fee, extensions } => {
                Self::validate_object_id(issuer, "account")?;
                Self::validate_asset_amount(asset_to_issue)?;
                Self::validate_object_id(issue_to_account, "account")?;
                Self::validate_asset_amount(fee)?;
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
            Operation::Custom { id, payer, required_auths, data, fee, extensions } => {
                Self::validate_object_id(payer, "account")?;
                Self::validate_asset_amount(fee)?;
                
                for auth in required_auths {
                    Self::validate_object_id(auth, "account")?;
                }
                
                if data.len() > 1024 * 1024 {
                    return Err(SerializerError::BufferError {
                        reason: "Custom operation data too large".to_string(),
                    });
                }
                
                Self::validate_extensions(&extensions.iter().map(|e| e.data.clone()).collect::<Vec<_>>())?;
            }
        }
        
        Ok(())
    }

    /// Validate ObjectId
    pub fn validate_object_id(id: &ObjectId, expected_type: &str) -> SerializerResult<()> {
        // Basic validation - check if the ID is valid
        if !id.is_valid() {
            return Err(SerializerError::InvalidFormat {
                expected: format!("Valid {} ObjectId", expected_type),
                actual: format!("Invalid ObjectId: {}", id),
            });
        }

        // Type-specific validation
        match expected_type {
            "account" => {
                if id.space() != 1 || id.type_id() != 2 {
                    return Err(SerializerError::InvalidFormat {
                        expected: "Account ObjectId (1.2.x)".to_string(),
                        actual: format!("ObjectId: {}", id),
                    });
                }
            }
            "asset" => {
                if id.space() != 1 || id.type_id() != 3 {
                    return Err(SerializerError::InvalidFormat {
                        expected: "Asset ObjectId (1.3.x)".to_string(),
                        actual: format!("ObjectId: {}", id),
                    });
                }
            }
            "limit_order" => {
                if id.space() != 1 || id.type_id() != 7 {
                    return Err(SerializerError::InvalidFormat {
                        expected: "Limit Order ObjectId (1.7.x)".to_string(),
                        actual: format!("ObjectId: {}", id),
                    });
                }
            }
            _ => {
                // Generic validation passed
            }
        }

        Ok(())
    }

    /// Validate AssetAmount
    pub fn validate_asset_amount(amount: &AssetAmount) -> SerializerResult<()> {
        // Validate asset ID
        Self::validate_object_id(&amount.asset_id, "asset")?;

        // Check for reasonable amount bounds
        if amount.amount < 0 && amount.amount < -1_000_000_000_000_000 {
            return Err(SerializerError::InvalidFormat {
                expected: "Reasonable negative amount".to_string(),
                actual: format!("Amount too negative: {}", amount.amount),
            });
        }

        if amount.amount > 1_000_000_000_000_000_000 {
            return Err(SerializerError::InvalidFormat {
                expected: "Reasonable positive amount".to_string(),
                actual: format!("Amount too large: {}", amount.amount),
            });
        }

        Ok(())
    }

    /// Validate Authority structure
    pub fn validate_authority(authority: &Authority) -> SerializerResult<()> {
        if authority.weight_threshold == 0 {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-zero weight threshold".to_string(),
                actual: "Zero weight threshold".to_string(),
            });
        }

        // Validate account auths
        for (account_id, weight) in &authority.account_auths {
            Self::validate_object_id(account_id, "account")?;
            if *weight == 0 {
                return Err(SerializerError::InvalidFormat {
                    expected: "Non-zero weight".to_string(),
                    actual: "Zero weight in account auth".to_string(),
                });
            }
        }

        // Validate key auths
        for (public_key, weight) in &authority.key_auths {
            Self::validate_public_key(public_key)?;
            if *weight == 0 {
                return Err(SerializerError::InvalidFormat {
                    expected: "Non-zero weight".to_string(),
                    actual: "Zero weight in key auth".to_string(),
                });
            }
        }

        // Validate address auths
        for (address, weight) in &authority.address_auths {
            Self::validate_address(address)?;
            if *weight == 0 {
                return Err(SerializerError::InvalidFormat {
                    expected: "Non-zero weight".to_string(),
                    actual: "Zero weight in address auth".to_string(),
                });
            }
        }

        // Check that total possible weight can meet threshold
        let total_weight: u32 = authority.account_auths.values().sum::<u16>() as u32
            + authority.key_auths.values().sum::<u16>() as u32
            + authority.address_auths.values().sum::<u16>() as u32;

        if total_weight < authority.weight_threshold {
            return Err(SerializerError::InvalidFormat {
                expected: format!("Total weight >= threshold ({})", authority.weight_threshold),
                actual: format!("Total weight: {}", total_weight),
            });
        }

        Ok(())
    }

    /// Validate Memo structure
    pub fn validate_memo(memo: &Memo) -> SerializerResult<()> {
        // Validate public key formats
        Self::validate_public_key(&memo.from)?;
        Self::validate_public_key(&memo.to)?;

        // Check message size
        if memo.message.len() > super::constants::MAX_STRING_LENGTH {
            return Err(SerializerError::BufferError {
                reason: format!(
                    "Memo message too large: {} > {}",
                    memo.message.len(),
                    super::constants::MAX_STRING_LENGTH
                ),
            });
        }

        Ok(())
    }

    /// Validate account name
    pub fn validate_account_name(name: &str) -> SerializerResult<()> {
        if name.is_empty() {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-empty account name".to_string(),
                actual: "Empty account name".to_string(),
            });
        }

        if name.len() > 63 {
            return Err(SerializerError::InvalidFormat {
                expected: "Account name <= 63 characters".to_string(),
                actual: format!("Account name length: {}", name.len()),
            });
        }

        // Check for valid characters (lowercase letters, numbers, hyphens)
        for ch in name.chars() {
            if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' && ch != '.' {
                return Err(SerializerError::InvalidFormat {
                    expected: "Account name with valid characters (a-z, 0-9, -, .)".to_string(),
                    actual: format!("Invalid character: {}", ch),
                });
            }
        }

        // Cannot start or end with hyphen or dot
        if name.starts_with('-') || name.ends_with('-') || name.starts_with('.') || name.ends_with('.') {
            return Err(SerializerError::InvalidFormat {
                expected: "Account name not starting/ending with - or .".to_string(),
                actual: name.to_string(),
            });
        }

        Ok(())
    }

    /// Validate asset symbol
    pub fn validate_asset_symbol(symbol: &str) -> SerializerResult<()> {
        if symbol.is_empty() {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-empty asset symbol".to_string(),
                actual: "Empty asset symbol".to_string(),
            });
        }

        if symbol.len() > 16 {
            return Err(SerializerError::InvalidFormat {
                expected: "Asset symbol <= 16 characters".to_string(),
                actual: format!("Asset symbol length: {}", symbol.len()),
            });
        }

        // Check for valid characters (uppercase letters, numbers)
        for ch in symbol.chars() {
            if !ch.is_ascii_uppercase() && !ch.is_ascii_digit() && ch != '.' {
                return Err(SerializerError::InvalidFormat {
                    expected: "Asset symbol with valid characters (A-Z, 0-9, .)".to_string(),
                    actual: format!("Invalid character: {}", ch),
                });
            }
        }

        Ok(())
    }

    /// Validate public key format
    pub fn validate_public_key(public_key: &str) -> SerializerResult<()> {
        if public_key.is_empty() {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-empty public key".to_string(),
                actual: "Empty public key".to_string(),
            });
        }

        // Basic length check for hex-encoded public key
        if public_key.len() != 66 && public_key.len() != 130 {
            return Err(SerializerError::InvalidFormat {
                expected: "Public key length 66 (compressed) or 130 (uncompressed)".to_string(),
                actual: format!("Public key length: {}", public_key.len()),
            });
        }

        // Check for valid hex characters
        for ch in public_key.chars() {
            if !ch.is_ascii_hexdigit() {
                return Err(SerializerError::InvalidFormat {
                    expected: "Public key with hex characters".to_string(),
                    actual: format!("Invalid character: {}", ch),
                });
            }
        }

        Ok(())
    }

    /// Validate address format
    pub fn validate_address(address: &str) -> SerializerResult<()> {
        if address.is_empty() {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-empty address".to_string(),
                actual: "Empty address".to_string(),
            });
        }

        // Basic address validation - should be base58 encoded
        if address.len() < 26 || address.len() > 35 {
            return Err(SerializerError::InvalidFormat {
                expected: "Address length between 26 and 35 characters".to_string(),
                actual: format!("Address length: {}", address.len()),
            });
        }

        Ok(())
    }

    /// Validate extensions array
    pub fn validate_extensions(extensions: &[Vec<u8>]) -> SerializerResult<()> {
        for (i, extension) in extensions.iter().enumerate() {
            if extension.len() > 1024 {
                return Err(SerializerError::BufferError {
                    reason: format!("Extension {} too large: {} bytes", i, extension.len()),
                });
            }
        }
        Ok(())
    }

    /// Validate single extension
    pub fn validate_extension(extension: &[u8]) -> SerializerResult<()> {
        if extension.len() > 1024 {
            return Err(SerializerError::BufferError {
                reason: format!("Extension too large: {} bytes", extension.len()),
            });
        }
        Ok(())
    }

    /// Validate serialized data integrity
    pub fn validate_serialized_data(data: &[u8]) -> SerializerResult<()> {
        if data.is_empty() {
            return Err(SerializerError::InvalidFormat {
                expected: "Non-empty serialized data".to_string(),
                actual: "Empty data".to_string(),
            });
        }

        if data.len() > super::constants::MAX_SERIALIZED_SIZE {
            return Err(SerializerError::BufferError {
                reason: format!(
                    "Serialized data too large: {} > {}",
                    data.len(),
                    super::constants::MAX_SERIALIZED_SIZE
                ),
            });
        }

        // Check for magic bytes if present
        if data.len() >= 4 && &data[0..4] == super::constants::MAGIC_BYTES {
            // Validate version
            if data.len() >= 5 {
                let version = data[4];
                if version != super::constants::SERIALIZATION_VERSION {
                    return Err(SerializerError::InvalidFormat {
                        expected: format!("Serialization version {}", super::constants::SERIALIZATION_VERSION),
                        actual: format!("Version: {}", version),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate type consistency
    pub fn validate_type_consistency(expected_type: &str, actual_type_id: u8) -> SerializerResult<()> {
        let expected_id = SerializerTypes::get_type_id(expected_type);
        
        match expected_id {
            Some(id) if id == actual_type_id => Ok(()),
            Some(id) => Err(SerializerError::TypeConversionError {
                from: format!("Type ID {}", actual_type_id),
                to: format!("Expected type {} (ID {})", expected_type, id),
            }),
            None => Err(SerializerError::TypeConversionError {
                from: "Unknown type".to_string(),
                to: expected_type.to_string(),
            }),
        }
    }

    /// Validate buffer bounds
    pub fn validate_buffer_bounds(data: &[u8], offset: usize, required_bytes: usize) -> SerializerResult<()> {
        if offset + required_bytes > data.len() {
            return Err(SerializerError::BufferError {
                reason: format!(
                    "Buffer underflow: need {} bytes at offset {}, but only {} bytes available",
                    required_bytes,
                    offset,
                    data.len() - offset
                ),
            });
        }
        Ok(())
    }

    /// Comprehensive validation for any serializable data
    pub fn comprehensive_validate<T>(data: &T, type_name: &str) -> SerializerResult<()>
    where
        T: ?Sized,
    {
        // This would be implemented with more specific validation logic
        // For now, just validate the type name is known
        if SerializerTypes::get_type_id(type_name).is_none() {
            return Err(SerializerError::TypeConversionError {
                from: "Unknown type".to_string(),
                to: type_name.to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ObjectId, AssetAmount};

    #[test]
    fn test_validate_object_id() {
        let account_id = ObjectId::from_string("1.2.100").unwrap();
        assert!(SerializerValidation::validate_object_id(&account_id, "account").is_ok());

        let asset_id = ObjectId::from_string("1.3.0").unwrap();
        assert!(SerializerValidation::validate_object_id(&asset_id, "asset").is_ok());

        // Wrong type
        assert!(SerializerValidation::validate_object_id(&account_id, "asset").is_err());
    }

    #[test]
    fn test_validate_asset_amount() {
        let asset_id = ObjectId::from_string("1.3.0").unwrap();
        let amount = AssetAmount {
            amount: 1000,
            asset_id,
        };
        assert!(SerializerValidation::validate_asset_amount(&amount).is_ok());

        // Test extreme values
        let large_amount = AssetAmount {
            amount: 2_000_000_000_000_000_000,
            asset_id: ObjectId::from_string("1.3.0").unwrap(),
        };
        assert!(SerializerValidation::validate_asset_amount(&large_amount).is_err());
    }

    #[test]
    fn test_validate_account_name() {
        assert!(SerializerValidation::validate_account_name("alice").is_ok());
        assert!(SerializerValidation::validate_account_name("bob-123").is_ok());
        assert!(SerializerValidation::validate_account_name("test.account").is_ok());

        // Invalid names
        assert!(SerializerValidation::validate_account_name("").is_err());
        assert!(SerializerValidation::validate_account_name("Alice").is_err()); // uppercase
        assert!(SerializerValidation::validate_account_name("-alice").is_err()); // starts with -
        assert!(SerializerValidation::validate_account_name("alice-").is_err()); // ends with -
    }

    #[test]
    fn test_validate_asset_symbol() {
        assert!(SerializerValidation::validate_asset_symbol("BTC").is_ok());
        assert!(SerializerValidation::validate_asset_symbol("USD").is_ok());
        assert!(SerializerValidation::validate_asset_symbol("GOLD.123").is_ok());

        // Invalid symbols
        assert!(SerializerValidation::validate_asset_symbol("").is_err());
        assert!(SerializerValidation::validate_asset_symbol("btc").is_err()); // lowercase
        assert!(SerializerValidation::validate_asset_symbol("VERYLONGSYMBOLNAME").is_err()); // too long
    }

    #[test]
    fn test_validate_public_key() {
        let compressed_key = "02".to_owned() + &"a".repeat(64);
        let uncompressed_key = "04".to_owned() + &"b".repeat(128);

        assert!(SerializerValidation::validate_public_key(&compressed_key).is_ok());
        assert!(SerializerValidation::validate_public_key(&uncompressed_key).is_ok());

        // Invalid keys
        assert!(SerializerValidation::validate_public_key("").is_err());
        assert!(SerializerValidation::validate_public_key("short").is_err());
        assert!(SerializerValidation::validate_public_key(&("02".to_owned() + &"g".repeat(64))).is_err()); // invalid hex
    }

    #[test]
    fn test_validate_serialized_data() {
        let valid_data = vec![1, 2, 3, 4, 5];
        assert!(SerializerValidation::validate_serialized_data(&valid_data).is_ok());

        // Empty data
        assert!(SerializerValidation::validate_serialized_data(&[]).is_err());

        // Data with magic bytes
        let mut magic_data = super::super::constants::MAGIC_BYTES.to_vec();
        magic_data.push(super::super::constants::SERIALIZATION_VERSION);
        magic_data.extend_from_slice(&[1, 2, 3]);
        assert!(SerializerValidation::validate_serialized_data(&magic_data).is_ok());
    }

    #[test]
    fn test_validate_type_consistency() {
        assert!(SerializerValidation::validate_type_consistency("Transaction", 0x01).is_ok());
        assert!(SerializerValidation::validate_type_consistency("Transaction", 0x02).is_err());
        assert!(SerializerValidation::validate_type_consistency("UnknownType", 0x01).is_err());
    }

    #[test]
    fn test_validate_buffer_bounds() {
        let data = vec![1, 2, 3, 4, 5];
        
        assert!(SerializerValidation::validate_buffer_bounds(&data, 0, 3).is_ok());
        assert!(SerializerValidation::validate_buffer_bounds(&data, 2, 3).is_ok());
        assert!(SerializerValidation::validate_buffer_bounds(&data, 3, 3).is_err()); // would exceed bounds
        assert!(SerializerValidation::validate_buffer_bounds(&data, 0, 10).is_err()); // too many bytes
    }
}