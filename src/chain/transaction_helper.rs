//! Transaction helper utilities for R-Squared blockchain
//!
//! This module provides utility functions for transaction serialization,
//! broadcasting, and various transaction-related operations.

use crate::chain::{
    chain_types::*,
    ObjectId,
};
use crate::ecc::{PrivateKey, PublicKey, Signature, hash};
use crate::error::{ChainError, ChainResult, NetworkError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Transaction helper for various transaction operations
pub struct TransactionHelper;

impl TransactionHelper {
    /// Serialize transaction to bytes
    pub fn serialize_transaction(transaction: &Transaction) -> ChainResult<Vec<u8>> {
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        bincode::encode_to_vec(transaction, config).map_err(|e| ChainError::ValidationError {
            field: "serialization".to_string(),
            reason: format!("Failed to serialize transaction: {}", e),
        })
    }

    /// Deserialize transaction from bytes
    pub fn deserialize_transaction(data: &[u8]) -> ChainResult<Transaction> {
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        let (result, _) = bincode::decode_from_slice(data, config).map_err(|e| ChainError::ValidationError {
            field: "deserialization".to_string(),
            reason: format!("Failed to deserialize transaction: {}", e),
        })?;
        Ok(result)
    }

    /// Serialize transaction for signing (without signatures)
    pub fn serialize_for_signing(transaction: &Transaction, chain_id: &str) -> ChainResult<Vec<u8>> {
        let mut signing_data = Vec::new();
        
        // Add chain ID
        let chain_id_bytes = hex::decode(chain_id).map_err(|_| ChainError::ValidationError {
            field: "chain_id".to_string(),
            reason: "Invalid chain ID format".to_string(),
        })?;
        signing_data.extend_from_slice(&chain_id_bytes);
        
        // Create transaction without signatures
        let tx_for_signing = Transaction {
            ref_block_num: transaction.ref_block_num,
            ref_block_prefix: transaction.ref_block_prefix,
            expiration: transaction.expiration,
            operations: transaction.operations.clone(),
            extensions: transaction.extensions.clone(),
            signatures: vec![], // Empty for signing
        };
        
        // Serialize transaction
        let tx_bytes = Self::serialize_transaction(&tx_for_signing)?;
        signing_data.extend_from_slice(&tx_bytes);
        
        Ok(signing_data)
    }

    /// Calculate transaction ID
    pub fn calculate_transaction_id(transaction: &Transaction) -> ChainResult<String> {
        // Create transaction without signatures for ID calculation
        let tx_for_id = Transaction {
            ref_block_num: transaction.ref_block_num,
            ref_block_prefix: transaction.ref_block_prefix,
            expiration: transaction.expiration,
            operations: transaction.operations.clone(),
            extensions: transaction.extensions.clone(),
            signatures: vec![],
        };
        
        let tx_bytes = Self::serialize_transaction(&tx_for_id)?;
        let hash = hash::sha256(&tx_bytes);
        Ok(hex::encode(hash))
    }

    /// Sign transaction with private key
    pub fn sign_transaction(
        transaction: &mut Transaction,
        private_key: &PrivateKey,
        chain_id: &str,
    ) -> ChainResult<()> {
        let signing_data = Self::serialize_for_signing(transaction, chain_id)?;
        let signing_hash = hash::sha256(&signing_data);
        let signature = private_key.sign(&signing_hash)?;
        transaction.signatures.push(signature.to_hex());
        Ok(())
    }

    /// Sign transaction with multiple private keys
    pub fn sign_transaction_with_keys(
        transaction: &mut Transaction,
        private_keys: &[PrivateKey],
        chain_id: &str,
    ) -> ChainResult<()> {
        let signing_data = Self::serialize_for_signing(transaction, chain_id)?;
        let signing_hash = hash::sha256(&signing_data);
        
        for private_key in private_keys {
            let signature = private_key.sign(&signing_hash)?;
            transaction.signatures.push(signature.to_hex());
        }
        
        Ok(())
    }

    /// Verify transaction signatures
    pub fn verify_transaction_signatures(
        transaction: &Transaction,
        public_keys: &[PublicKey],
        chain_id: &str,
    ) -> ChainResult<bool> {
        if transaction.signatures.len() != public_keys.len() {
            return Ok(false);
        }
        
        let signing_data = Self::serialize_for_signing(transaction, chain_id)?;
        
        for (i, signature_hex) in transaction.signatures.iter().enumerate() {
            let signature = Signature::from_hex(signature_hex).map_err(|_| ChainError::ValidationError {
                field: "signature".to_string(),
                reason: "Invalid signature format".to_string(),
            })?;
            
            if !public_keys[i].verify_signature(&signing_data, &signature)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    /// Recover public keys from transaction signatures
    pub fn recover_public_keys(
        transaction: &Transaction,
        chain_id: &str,
    ) -> ChainResult<Vec<PublicKey>> {
        let signing_data = Self::serialize_for_signing(transaction, chain_id)?;
        let mut public_keys = Vec::new();
        
        for signature_hex in &transaction.signatures {
            let signature = Signature::from_hex(signature_hex).map_err(|_| ChainError::ValidationError {
                field: "signature".to_string(),
                reason: "Invalid signature format".to_string(),
            })?;
            
            let public_key = signature.recover_public_key()?;
            public_keys.push(public_key);
        }
        
        Ok(public_keys)
    }

    /// Validate transaction structure
    pub fn validate_transaction(transaction: &Transaction) -> ChainResult<()> {
        // Check if transaction has operations
        if transaction.operations.is_empty() {
            return Err(ChainError::ValidationError {
                field: "operations".to_string(),
                reason: "Transaction must have at least one operation".to_string(),
            });
        }

        // Check operation count limit
        if transaction.operations.len() > crate::chain::constants::MAX_OPERATIONS_PER_TRANSACTION {
            return Err(ChainError::ValidationError {
                field: "operations".to_string(),
                reason: "Too many operations in transaction".to_string(),
            });
        }

        // Check expiration
        if transaction.expiration == 0 {
            return Err(ChainError::ValidationError {
                field: "expiration".to_string(),
                reason: "Transaction expiration must be set".to_string(),
            });
        }

        // Check if transaction has expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs() as u32;

        if transaction.expiration <= now {
            return Err(ChainError::ValidationError {
                field: "expiration".to_string(),
                reason: "Transaction has expired".to_string(),
            });
        }

        // Validate each operation
        for (i, operation) in transaction.operations.iter().enumerate() {
            Self::validate_operation(operation).map_err(|e| ChainError::ValidationError {
                field: format!("operation[{}]", i),
                reason: format!("Operation validation failed: {}", e),
            })?;
        }

        Ok(())
    }

    /// Validate individual operation
    pub fn validate_operation(operation: &Operation) -> ChainResult<()> {
        match operation {
            Operation::Transfer { from, to, amount, .. } => {
                if from == to {
                    return Err(ChainError::ValidationError {
                        field: "transfer".to_string(),
                        reason: "Cannot transfer to self".to_string(),
                    });
                }
                if amount.amount <= 0 {
                    return Err(ChainError::ValidationError {
                        field: "amount".to_string(),
                        reason: "Transfer amount must be positive".to_string(),
                    });
                }
            }
            Operation::LimitOrderCreate { amount_to_sell, min_to_receive, .. } => {
                if amount_to_sell.amount <= 0 {
                    return Err(ChainError::ValidationError {
                        field: "amount_to_sell".to_string(),
                        reason: "Amount to sell must be positive".to_string(),
                    });
                }
                if min_to_receive.amount <= 0 {
                    return Err(ChainError::ValidationError {
                        field: "min_to_receive".to_string(),
                        reason: "Minimum to receive must be positive".to_string(),
                    });
                }
                if amount_to_sell.asset_id == min_to_receive.asset_id {
                    return Err(ChainError::ValidationError {
                        field: "assets".to_string(),
                        reason: "Cannot trade same asset".to_string(),
                    });
                }
            }
            Operation::AccountCreate { name, .. } => {
                crate::chain::ChainTypes::validate_account_name(name)?;
            }
            Operation::AssetCreate { symbol, precision, .. } => {
                crate::chain::ChainTypes::validate_asset_symbol(symbol)?;
                if *precision > 18 {
                    return Err(ChainError::ValidationError {
                        field: "precision".to_string(),
                        reason: "Asset precision cannot exceed 18".to_string(),
                    });
                }
            }
            _ => {} // Other operations pass validation for now
        }
        
        Ok(())
    }

    /// Calculate transaction size in bytes
    pub fn calculate_transaction_size(transaction: &Transaction) -> ChainResult<usize> {
        let serialized = Self::serialize_transaction(transaction)?;
        Ok(serialized.len())
    }

    /// Check if transaction size is within limits
    pub fn is_transaction_size_valid(transaction: &Transaction) -> ChainResult<bool> {
        let size = Self::calculate_transaction_size(transaction)?;
        Ok(size <= crate::chain::constants::MAX_TRANSACTION_SIZE)
    }

    /// Create a memo for encrypted messages
    pub fn create_memo(
        from_private_key: &PrivateKey,
        to_public_key: &PublicKey,
        message: &str,
        nonce: u64,
    ) -> ChainResult<Memo> {
        use crate::ecc::Aes;
        
        let from_public_key = from_private_key.public_key()?;
        
        // Create shared secret using ECDH
        let shared_secret = from_private_key.create_shared_secret(to_public_key)?;
        
        // Encrypt message
        let encrypted_message = Aes::encrypt_with_checksum(&shared_secret, message.as_bytes())?;
        
        Ok(Memo {
            from: from_public_key.to_hex(),
            to: to_public_key.to_hex(),
            nonce,
            message: encrypted_message,
        })
    }

    /// Decrypt a memo
    pub fn decrypt_memo(
        memo: &Memo,
        private_key: &PrivateKey,
    ) -> ChainResult<String> {
        use crate::ecc::Aes;
        
        let my_public_key = private_key.public_key()?;
        let other_public_key = if memo.from == my_public_key.to_hex() {
            PublicKey::from_hex(&memo.to)?
        } else if memo.to == my_public_key.to_hex() {
            PublicKey::from_hex(&memo.from)?
        } else {
            return Err(ChainError::ValidationError {
                field: "memo".to_string(),
                reason: "Memo is not addressed to this key".to_string(),
            });
        };
        
        // Create shared secret
        let shared_secret = private_key.create_shared_secret(&other_public_key)?;
        
        // Decrypt message
        let decrypted_bytes = Aes::decrypt_with_checksum(&shared_secret, &memo.message)?;
        let message = String::from_utf8(decrypted_bytes).map_err(|_| ChainError::ValidationError {
            field: "memo".to_string(),
            reason: "Invalid UTF-8 in decrypted memo".to_string(),
        })?;
        
        Ok(message)
    }

    /// Convert transaction to JSON
    pub fn transaction_to_json(transaction: &Transaction) -> ChainResult<String> {
        serde_json::to_string_pretty(transaction).map_err(|e| ChainError::ValidationError {
            field: "json_serialization".to_string(),
            reason: format!("Failed to serialize to JSON: {}", e),
        })
    }

    /// Parse transaction from JSON
    pub fn transaction_from_json(json: &str) -> ChainResult<Transaction> {
        serde_json::from_str(json).map_err(|e| ChainError::ValidationError {
            field: "json_deserialization".to_string(),
            reason: format!("Failed to deserialize from JSON: {}", e),
        })
    }

    /// Broadcast transaction to network (placeholder)
    pub async fn broadcast_transaction(
        transaction: &SignedTransaction,
        api_url: &str,
    ) -> ChainResult<String> {
        // TODO: Implement actual network broadcasting
        // This would typically use HTTP/WebSocket to send the transaction to a node
        
        // For now, return a mock transaction ID
        Ok(transaction.transaction_id.clone())
    }

    /// Get required signatures for transaction
    pub fn get_required_signatures(transaction: &Transaction) -> ChainResult<Vec<ObjectId>> {
        let mut required_accounts = Vec::new();
        
        for operation in &transaction.operations {
            match operation {
                Operation::Transfer { from, .. } => {
                    if !required_accounts.contains(from) {
                        required_accounts.push(from.clone());
                    }
                }
                Operation::LimitOrderCreate { seller, .. } => {
                    if !required_accounts.contains(seller) {
                        required_accounts.push(seller.clone());
                    }
                }
                Operation::LimitOrderCancel { fee_paying_account, .. } => {
                    if !required_accounts.contains(fee_paying_account) {
                        required_accounts.push(fee_paying_account.clone());
                    }
                }
                Operation::AccountCreate { registrar, .. } => {
                    if !required_accounts.contains(registrar) {
                        required_accounts.push(registrar.clone());
                    }
                }
                Operation::AccountUpdate { account, .. } => {
                    if !required_accounts.contains(account) {
                        required_accounts.push(account.clone());
                    }
                }
                Operation::AssetCreate { issuer, .. } => {
                    if !required_accounts.contains(issuer) {
                        required_accounts.push(issuer.clone());
                    }
                }
                Operation::AssetUpdate { issuer, .. } => {
                    if !required_accounts.contains(issuer) {
                        required_accounts.push(issuer.clone());
                    }
                }
                Operation::AssetIssue { issuer, .. } => {
                    if !required_accounts.contains(issuer) {
                        required_accounts.push(issuer.clone());
                    }
                }
                Operation::Custom { payer, required_auths, .. } => {
                    if !required_accounts.contains(payer) {
                        required_accounts.push(payer.clone());
                    }
                    for auth in required_auths {
                        if !required_accounts.contains(auth) {
                            required_accounts.push(auth.clone());
                        }
                    }
                }
            }
        }
        
        Ok(required_accounts)
    }

    /// Check if transaction has sufficient signatures
    pub fn has_sufficient_signatures(
        transaction: &Transaction,
        authorities: &HashMap<ObjectId, Authority>,
    ) -> ChainResult<bool> {
        let required_accounts = Self::get_required_signatures(transaction)?;
        
        for account_id in required_accounts {
            if let Some(authority) = authorities.get(&account_id) {
                // Simple check: if we have at least one signature and the authority requires one key
                if transaction.signatures.is_empty() {
                    return Ok(false);
                }
                
                // TODO: Implement proper authority checking with weights
                // For now, assume one signature is sufficient if authority exists
            } else {
                return Ok(false); // No authority found for required account
            }
        }
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PrivateKey;

    #[test]
    fn test_serialize_deserialize_transaction() {
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 1234567890,
            operations: vec![],
            extensions: vec![],
            signatures: vec![],
        };
        
        let serialized = TransactionHelper::serialize_transaction(&transaction).unwrap();
        let deserialized = TransactionHelper::deserialize_transaction(&serialized).unwrap();
        
        assert_eq!(transaction.ref_block_num, deserialized.ref_block_num);
        assert_eq!(transaction.ref_block_prefix, deserialized.ref_block_prefix);
        assert_eq!(transaction.expiration, deserialized.expiration);
    }

    #[test]
    fn test_calculate_transaction_id() {
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 1234567890,
            operations: vec![],
            extensions: vec![],
            signatures: vec!["dummy_signature".to_string()],
        };
        
        let tx_id = TransactionHelper::calculate_transaction_id(&transaction).unwrap();
        assert!(!tx_id.is_empty());
        assert_eq!(tx_id.len(), 64); // SHA-256 hash as hex string
    }

    #[test]
    fn test_validate_transaction_empty_operations() {
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 1234567890,
            operations: vec![],
            extensions: vec![],
            signatures: vec![],
        };
        
        assert!(TransactionHelper::validate_transaction(&transaction).is_err());
    }

    #[test]
    fn test_validate_transaction_expired() {
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 1000000000, // Past timestamp
            operations: vec![Operation::Transfer {
                fee: AssetAmount {
                    amount: 1000,
                    asset_id: ObjectId::new(1, 3, 0).unwrap(),
                },
                from: ObjectId::new(1, 2, 1).unwrap(),
                to: ObjectId::new(1, 2, 2).unwrap(),
                amount: AssetAmount {
                    amount: 10000,
                    asset_id: ObjectId::new(1, 3, 0).unwrap(),
                },
                memo: None,
                extensions: vec![],
            }],
            extensions: vec![],
            signatures: vec![],
        };
        
        assert!(TransactionHelper::validate_transaction(&transaction).is_err());
    }

    #[test]
    fn test_transaction_size_calculation() {
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 9999999999, // Future timestamp
            operations: vec![Operation::Transfer {
                fee: AssetAmount {
                    amount: 1000,
                    asset_id: ObjectId::new(1, 3, 0).unwrap(),
                },
                from: ObjectId::new(1, 2, 1).unwrap(),
                to: ObjectId::new(1, 2, 2).unwrap(),
                amount: AssetAmount {
                    amount: 10000,
                    asset_id: ObjectId::new(1, 3, 0).unwrap(),
                },
                memo: None,
                extensions: vec![],
            }],
            extensions: vec![],
            signatures: vec![],
        };
        
        let size = TransactionHelper::calculate_transaction_size(&transaction).unwrap();
        assert!(size > 0);
        
        let is_valid_size = TransactionHelper::is_transaction_size_valid(&transaction).unwrap();
        assert!(is_valid_size);
    }

    #[test]
    fn test_json_serialization() {
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 9999999999,
            operations: vec![],
            extensions: vec![],
            signatures: vec![],
        };
        
        let json = TransactionHelper::transaction_to_json(&transaction).unwrap();
        assert!(json.contains("ref_block_num"));
        
        let parsed = TransactionHelper::transaction_from_json(&json).unwrap();
        assert_eq!(transaction.ref_block_num, parsed.ref_block_num);
    }

    #[test]
    fn test_get_required_signatures() {
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 9999999999,
            operations: vec![
                Operation::Transfer {
                    fee: AssetAmount {
                        amount: 1000,
                        asset_id: ObjectId::new(1, 3, 0).unwrap(),
                    },
                    from: ObjectId::new(1, 2, 1).unwrap(),
                    to: ObjectId::new(1, 2, 2).unwrap(),
                    amount: AssetAmount {
                        amount: 10000,
                        asset_id: ObjectId::new(1, 3, 0).unwrap(),
                    },
                    memo: None,
                    extensions: vec![],
                }
            ],
            extensions: vec![],
            signatures: vec![],
        };
        
        let required = TransactionHelper::get_required_signatures(&transaction).unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], ObjectId::new(1, 2, 1).unwrap());
    }
}