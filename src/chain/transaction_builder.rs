//! Transaction builder implementation for R-Squared blockchain
//!
//! This module provides functionality for building, validating, and managing
//! blockchain transactions with proper fee calculation and operation handling.

use crate::chain::{
    chain_types::*,
    number_utils::PrecisionNumber,
    ObjectId,
};
use crate::ecc::{PrivateKey, PublicKey, Signature};
use crate::error::{ChainError, ChainResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Transaction builder for creating blockchain transactions
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    /// Reference block number
    ref_block_num: u16,
    /// Reference block prefix
    ref_block_prefix: u32,
    /// Expiration time (seconds since epoch)
    expiration: u32,
    /// Operations to include in the transaction
    operations: Vec<Operation>,
    /// Extensions
    extensions: Vec<Extension>,
    /// Fee schedule for calculating fees
    fee_schedule: Option<FeeSchedule>,
    /// Chain ID for signing
    chain_id: Option<String>,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            ref_block_num: 0,
            ref_block_prefix: 0,
            expiration: 0,
            operations: Vec::new(),
            extensions: Vec::new(),
            fee_schedule: None,
            chain_id: None,
        }
    }

    /// Set reference block information
    pub fn set_reference_block(&mut self, block_num: u32, block_id: &str) -> ChainResult<()> {
        self.ref_block_num = (block_num & 0xFFFF) as u16;
        
        // Extract prefix from block ID (first 4 bytes after reversing)
        if block_id.len() < 8 {
            return Err(ChainError::ValidationError {
                field: "block_id".to_string(),
                reason: "Block ID too short".to_string(),
            });
        }
        
        let prefix_hex = &block_id[8..16];
        self.ref_block_prefix = u32::from_str_radix(prefix_hex, 16)
            .map_err(|_| ChainError::ValidationError {
                field: "block_id".to_string(),
                reason: "Invalid block ID format".to_string(),
            })?;
        
        Ok(())
    }

    /// Set expiration time (seconds from now)
    pub fn set_expiration(&mut self, seconds_from_now: u32) -> ChainResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs() as u32;
        
        self.expiration = now + seconds_from_now;
        Ok(())
    }

    /// Set absolute expiration time
    pub fn set_absolute_expiration(&mut self, expiration: u32) {
        self.expiration = expiration;
    }

    /// Set fee schedule for fee calculations
    pub fn set_fee_schedule(&mut self, fee_schedule: FeeSchedule) {
        self.fee_schedule = Some(fee_schedule);
    }

    /// Set chain ID for signing
    pub fn set_chain_id(&mut self, chain_id: String) {
        self.chain_id = Some(chain_id);
    }

    /// Add a transfer operation
    pub fn add_transfer(
        &mut self,
        from: ObjectId,
        to: ObjectId,
        amount: AssetAmount,
        memo: Option<Memo>,
    ) -> ChainResult<()> {
        let fee = self.calculate_fee_for_operation_type(0)?;
        
        let operation = Operation::Transfer {
            fee,
            from,
            to,
            amount,
            memo,
            extensions: vec![],
        };
        
        self.operations.push(operation);
        Ok(())
    }

    /// Add a limit order create operation
    pub fn add_limit_order_create(
        &mut self,
        seller: ObjectId,
        amount_to_sell: AssetAmount,
        min_to_receive: AssetAmount,
        expiration: u32,
        fill_or_kill: bool,
    ) -> ChainResult<()> {
        let fee = self.calculate_fee_for_operation_type(1)?;
        
        let operation = Operation::LimitOrderCreate {
            fee,
            seller,
            amount_to_sell,
            min_to_receive,
            expiration,
            fill_or_kill,
            extensions: vec![],
        };
        
        self.operations.push(operation);
        Ok(())
    }

    /// Add a limit order cancel operation
    pub fn add_limit_order_cancel(
        &mut self,
        fee_paying_account: ObjectId,
        order: ObjectId,
    ) -> ChainResult<()> {
        let fee = self.calculate_fee_for_operation_type(2)?;
        
        let operation = Operation::LimitOrderCancel {
            fee,
            fee_paying_account,
            order,
            extensions: vec![],
        };
        
        self.operations.push(operation);
        Ok(())
    }

    /// Add an account create operation
    pub fn add_account_create(
        &mut self,
        registrar: ObjectId,
        referrer: ObjectId,
        referrer_percent: u16,
        name: String,
        owner: Authority,
        active: Authority,
        options: AccountOptions,
    ) -> ChainResult<()> {
        // Validate account name
        ChainTypes::validate_account_name(&name)?;
        
        let fee = self.calculate_fee_for_operation_type(5)?;
        
        let operation = Operation::AccountCreate {
            fee,
            registrar,
            referrer,
            referrer_percent,
            name,
            owner,
            active,
            options,
            extensions: vec![],
        };
        
        self.operations.push(operation);
        Ok(())
    }

    /// Add an account update operation
    pub fn add_account_update(
        &mut self,
        account: ObjectId,
        owner: Option<Authority>,
        active: Option<Authority>,
        new_options: Option<AccountOptions>,
    ) -> ChainResult<()> {
        let fee = self.calculate_fee_for_operation_type(6)?;
        
        let operation = Operation::AccountUpdate {
            fee,
            account,
            owner,
            active,
            new_options,
            extensions: vec![],
        };
        
        self.operations.push(operation);
        Ok(())
    }

    /// Add an asset create operation
    pub fn add_asset_create(
        &mut self,
        issuer: ObjectId,
        symbol: String,
        precision: u8,
        common_options: AssetOptions,
        bitasset_opts: Option<BitassetOptions>,
        is_prediction_market: bool,
    ) -> ChainResult<()> {
        // Validate asset symbol
        ChainTypes::validate_asset_symbol(&symbol)?;
        
        let fee = self.calculate_fee_for_operation_type(10)?;
        
        let operation = Operation::AssetCreate {
            fee,
            issuer,
            symbol,
            precision,
            common_options,
            bitasset_opts,
            is_prediction_market,
            extensions: vec![],
        };
        
        self.operations.push(operation);
        Ok(())
    }

    /// Add a custom operation
    pub fn add_operation(&mut self, operation: Operation) -> ChainResult<()> {
        if self.operations.len() >= crate::chain::constants::MAX_OPERATIONS_PER_TRANSACTION {
            return Err(ChainError::ValidationError {
                field: "operations".to_string(),
                reason: "Too many operations in transaction".to_string(),
            });
        }
        
        self.operations.push(operation);
        Ok(())
    }

    /// Calculate fee for operation type
    fn calculate_fee_for_operation_type(&self, operation_type: u8) -> ChainResult<AssetAmount> {
        if let Some(ref fee_schedule) = self.fee_schedule {
            for param in &fee_schedule.parameters {
                if param.operation_type == operation_type {
                    let base_fee = param.fee.fee;
                    let scaled_fee = (base_fee as u64 * fee_schedule.scale as u64) / 10000;
                    
                    return Ok(AssetAmount {
                        amount: scaled_fee as i64,
                        asset_id: ObjectId::new(1, 3, 0)?, // Core asset
                    });
                }
            }
        }
        
        // Default fee if no fee schedule is set
        Ok(AssetAmount {
            amount: 1000, // Default 0.001 core asset (assuming 5 decimal precision)
            asset_id: ObjectId::new(1, 3, 0)?,
        })
    }

    /// Calculate total fees for all operations
    pub fn calculate_total_fees(&self) -> ChainResult<AssetAmount> {
        let mut total_fee = 0i64;
        let core_asset = ObjectId::new(1, 3, 0)?;
        
        for operation in &self.operations {
            let fee = match operation {
                Operation::Transfer { fee, .. } => fee,
                Operation::LimitOrderCreate { fee, .. } => fee,
                Operation::LimitOrderCancel { fee, .. } => fee,
                Operation::AccountCreate { fee, .. } => fee,
                Operation::AccountUpdate { fee, .. } => fee,
                Operation::AssetCreate { fee, .. } => fee,
                Operation::AssetUpdate { fee, .. } => fee,
                Operation::AssetIssue { fee, .. } => fee,
                Operation::Custom { fee, .. } => fee,
            };
            
            if fee.asset_id != core_asset {
                return Err(ChainError::ValidationError {
                    field: "fee".to_string(),
                    reason: "All fees must be paid in core asset".to_string(),
                });
            }
            
            total_fee = total_fee.checked_add(fee.amount).ok_or_else(|| ChainError::ValidationError {
                field: "fee".to_string(),
                reason: "Fee overflow".to_string(),
            })?;
        }
        
        Ok(AssetAmount {
            amount: total_fee,
            asset_id: core_asset,
        })
    }

    /// Validate the transaction
    pub fn validate(&self) -> ChainResult<()> {
        if self.operations.is_empty() {
            return Err(ChainError::ValidationError {
                field: "operations".to_string(),
                reason: "Transaction must have at least one operation".to_string(),
            });
        }
        
        if self.operations.len() > crate::chain::constants::MAX_OPERATIONS_PER_TRANSACTION {
            return Err(ChainError::ValidationError {
                field: "operations".to_string(),
                reason: "Too many operations in transaction".to_string(),
            });
        }
        
        if self.expiration == 0 {
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
        
        if self.expiration <= now {
            return Err(ChainError::ValidationError {
                field: "expiration".to_string(),
                reason: "Transaction has expired".to_string(),
            });
        }
        
        Ok(())
    }

    /// Build the unsigned transaction
    pub fn build(&self) -> ChainResult<Transaction> {
        self.validate()?;
        
        Ok(Transaction {
            ref_block_num: self.ref_block_num,
            ref_block_prefix: self.ref_block_prefix,
            expiration: self.expiration,
            operations: self.operations.clone(),
            extensions: self.extensions.clone(),
            signatures: vec![],
        })
    }

    /// Build and sign the transaction
    pub fn build_and_sign(&self, private_keys: &[PrivateKey]) -> ChainResult<SignedTransaction> {
        let mut transaction = self.build()?;
        
        let chain_id = self.chain_id.as_ref().ok_or_else(|| ChainError::ValidationError {
            field: "chain_id".to_string(),
            reason: "Chain ID must be set for signing".to_string(),
        })?;
        
        // Serialize transaction for signing
        let tx_data = self.serialize_for_signing(&transaction, chain_id)?;
        
        // Sign with each private key
        let mut signatures = Vec::new();
        for private_key in private_keys {
            let signature = private_key.sign_message(&tx_data)?;
            signatures.push(signature.to_hex());
        }
        
        transaction.signatures = signatures;
        
        // Calculate transaction ID
        let tx_id = self.calculate_transaction_id(&transaction)?;
        
        Ok(SignedTransaction {
            transaction,
            transaction_id: tx_id,
        })
    }

    /// Serialize transaction for signing
    fn serialize_for_signing(&self, transaction: &Transaction, chain_id: &str) -> ChainResult<Vec<u8>> {
        use bincode;
        
        // Create signing data: chain_id + transaction (without signatures)
        let mut signing_data = Vec::new();
        
        // Add chain ID
        let chain_id_bytes = hex::decode(chain_id).map_err(|_| ChainError::ValidationError {
            field: "chain_id".to_string(),
            reason: "Invalid chain ID format".to_string(),
        })?;
        signing_data.extend_from_slice(&chain_id_bytes);
        
        // Add transaction data
        let tx_without_sigs = Transaction {
            ref_block_num: transaction.ref_block_num,
            ref_block_prefix: transaction.ref_block_prefix,
            expiration: transaction.expiration,
            operations: transaction.operations.clone(),
            extensions: transaction.extensions.clone(),
            signatures: vec![], // Empty signatures for signing
        };
        
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        let tx_bytes = bincode::encode_to_vec(&tx_without_sigs, config).map_err(|e| ChainError::ValidationError {
            field: "serialization".to_string(),
            reason: format!("Failed to serialize transaction: {}", e),
        })?;
        
        signing_data.extend_from_slice(&tx_bytes);
        
        Ok(signing_data)
    }

    /// Calculate transaction ID
    fn calculate_transaction_id(&self, transaction: &Transaction) -> ChainResult<String> {
        use crate::ecc::hash;
        
        // Serialize transaction without signatures
        let tx_without_sigs = Transaction {
            ref_block_num: transaction.ref_block_num,
            ref_block_prefix: transaction.ref_block_prefix,
            expiration: transaction.expiration,
            operations: transaction.operations.clone(),
            extensions: transaction.extensions.clone(),
            signatures: vec![],
        };
        
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        let tx_bytes = bincode::encode_to_vec(&tx_without_sigs, config).map_err(|e| ChainError::ValidationError {
            field: "serialization".to_string(),
            reason: format!("Failed to serialize transaction: {}", e),
        })?;
        
        let hash = hash::sha256(&tx_bytes);
        Ok(hex::encode(hash))
    }

    /// Get current operations count
    pub fn operations_count(&self) -> usize {
        self.operations.len()
    }

    /// Get operations
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    /// Clear all operations
    pub fn clear_operations(&mut self) {
        self.operations.clear();
    }

    /// Get expiration time
    pub fn expiration(&self) -> u32 {
        self.expiration
    }

    /// Check if transaction will expire soon (within 30 seconds)
    pub fn expires_soon(&self) -> ChainResult<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs() as u32;
        
        Ok(self.expiration <= now + 30)
    }

    /// Estimate transaction size in bytes
    pub fn estimate_size(&self) -> ChainResult<usize> {
        let transaction = self.build()?;
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        let serialized = bincode::encode_to_vec(&transaction, config).map_err(|e| ChainError::ValidationError {
            field: "serialization".to_string(),
            reason: format!("Failed to serialize transaction: {}", e),
        })?;
        
        Ok(serialized.len())
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PrivateKey;

    #[test]
    fn test_transaction_builder_creation() {
        let builder = TransactionBuilder::new();
        assert_eq!(builder.operations_count(), 0);
        assert_eq!(builder.expiration(), 0);
    }

    #[test]
    fn test_set_reference_block() {
        let mut builder = TransactionBuilder::new();
        let result = builder.set_reference_block(12345, "0123456789abcdef0123456789abcdef");
        assert!(result.is_ok());
        assert_eq!(builder.ref_block_num, 12345 & 0xFFFF);
    }

    #[test]
    fn test_set_expiration() {
        let mut builder = TransactionBuilder::new();
        let result = builder.set_expiration(3600); // 1 hour from now
        assert!(result.is_ok());
        assert!(builder.expiration() > 0);
    }

    #[test]
    fn test_add_transfer() {
        let mut builder = TransactionBuilder::new();
        let from = ObjectId::new(1, 2, 1).unwrap();
        let to = ObjectId::new(1, 2, 2).unwrap();
        let amount = AssetAmount {
            amount: 10000,
            asset_id: ObjectId::new(1, 3, 0).unwrap(),
        };
        
        let result = builder.add_transfer(from, to, amount, None);
        assert!(result.is_ok());
        assert_eq!(builder.operations_count(), 1);
    }

    #[test]
    fn test_calculate_total_fees() {
        let mut builder = TransactionBuilder::new();
        let from = ObjectId::new(1, 2, 1).unwrap();
        let to = ObjectId::new(1, 2, 2).unwrap();
        let amount = AssetAmount {
            amount: 10000,
            asset_id: ObjectId::new(1, 3, 0).unwrap(),
        };
        
        builder.add_transfer(from, to, amount, None).unwrap();
        
        let total_fees = builder.calculate_total_fees().unwrap();
        assert!(total_fees.amount > 0);
        assert_eq!(total_fees.asset_id, ObjectId::new(1, 3, 0).unwrap());
    }

    #[test]
    fn test_validation_empty_operations() {
        let builder = TransactionBuilder::new();
        assert!(builder.validate().is_err());
    }

    #[test]
    fn test_validation_no_expiration() {
        let mut builder = TransactionBuilder::new();
        let from = ObjectId::new(1, 2, 1).unwrap();
        let to = ObjectId::new(1, 2, 2).unwrap();
        let amount = AssetAmount {
            amount: 10000,
            asset_id: ObjectId::new(1, 3, 0).unwrap(),
        };
        
        builder.add_transfer(from, to, amount, None).unwrap();
        assert!(builder.validate().is_err());
    }

    #[test]
    fn test_build_transaction() {
        let mut builder = TransactionBuilder::new();
        builder.set_expiration(3600).unwrap();
        builder.set_reference_block(12345, "0123456789abcdef0123456789abcdef").unwrap();
        
        let from = ObjectId::new(1, 2, 1).unwrap();
        let to = ObjectId::new(1, 2, 2).unwrap();
        let amount = AssetAmount {
            amount: 10000,
            asset_id: ObjectId::new(1, 3, 0).unwrap(),
        };
        
        builder.add_transfer(from, to, amount, None).unwrap();
        
        let transaction = builder.build();
        assert!(transaction.is_ok());
        
        let tx = transaction.unwrap();
        assert_eq!(tx.operations.len(), 1);
        assert!(tx.expiration > 0);
    }

    #[test]
    fn test_estimate_size() {
        let mut builder = TransactionBuilder::new();
        builder.set_expiration(3600).unwrap();
        
        let from = ObjectId::new(1, 2, 1).unwrap();
        let to = ObjectId::new(1, 2, 2).unwrap();
        let amount = AssetAmount {
            amount: 10000,
            asset_id: ObjectId::new(1, 3, 0).unwrap(),
        };
        
        builder.add_transfer(from, to, amount, None).unwrap();
        
        let size = builder.estimate_size();
        assert!(size.is_ok());
        assert!(size.unwrap() > 0);
    }
}