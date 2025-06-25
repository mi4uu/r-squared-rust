//! Chain validation utilities for R-Squared blockchain
//!
//! This module provides comprehensive validation logic for transactions,
//! operations, and blockchain state consistency.

use crate::chain::{
    chain_types::*,
    ObjectId,
};
use crate::error::{ChainError, ChainResult};
use std::time::{SystemTime, UNIX_EPOCH};

/// Chain validation utility struct
pub struct ChainValidation;

impl ChainValidation {
    /// Validate a complete transaction
    pub fn validate_transaction(
        transaction: &Transaction,
        chain_properties: &ChainProperties,
        global_properties: &GlobalProperties,
    ) -> ChainResult<()> {
        // Basic structure validation
        Self::validate_transaction_structure(transaction)?;
        
        // Time-based validation
        Self::validate_transaction_timing(transaction, chain_properties)?;
        
        // Size validation
        Self::validate_transaction_size(transaction, &global_properties.parameters)?;
        
        // Operation validation
        Self::validate_transaction_operations(transaction, &global_properties.parameters)?;
        
        // Fee validation
        Self::validate_transaction_fees(transaction)?;
        
        Ok(())
    }

    /// Validate transaction structure
    pub fn validate_transaction_structure(transaction: &Transaction) -> ChainResult<()> {
        // Must have at least one operation
        if transaction.operations.is_empty() {
            return Err(ChainError::ValidationError {
                field: "operations".to_string(),
                reason: "Transaction must contain at least one operation".to_string(),
            });
        }

        // Check operation count limit
        if transaction.operations.len() > crate::chain::constants::MAX_OPERATIONS_PER_TRANSACTION {
            return Err(ChainError::ValidationError {
                field: "operations".to_string(),
                reason: format!(
                    "Transaction contains {} operations, maximum allowed is {}",
                    transaction.operations.len(),
                    crate::chain::constants::MAX_OPERATIONS_PER_TRANSACTION
                ),
            });
        }

        // Validate expiration is set
        if transaction.expiration == 0 {
            return Err(ChainError::ValidationError {
                field: "expiration".to_string(),
                reason: "Transaction expiration must be set".to_string(),
            });
        }

        // Validate reference block
        if transaction.ref_block_num == 0 {
            return Err(ChainError::ValidationError {
                field: "ref_block_num".to_string(),
                reason: "Reference block number must be set".to_string(),
            });
        }

        Ok(())
    }

    /// Validate transaction timing
    pub fn validate_transaction_timing(
        transaction: &Transaction,
        chain_properties: &ChainProperties,
    ) -> ChainResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs() as u32;

        // Check if transaction has expired
        if transaction.expiration <= now {
            return Err(ChainError::ValidationError {
                field: "expiration".to_string(),
                reason: format!(
                    "Transaction expired at {}, current time is {}",
                    transaction.expiration, now
                ),
            });
        }

        // Check if expiration is too far in the future
        // Note: We need to get this from global properties parameters, not chain properties
        // For now, use a reasonable default of 24 hours (86400 seconds)
        let max_expiration = now + 86400; // 24 hours default
        if transaction.expiration > max_expiration {
            return Err(ChainError::ValidationError {
                field: "expiration".to_string(),
                reason: format!(
                    "Transaction expiration {} is too far in the future, maximum allowed is {}",
                    transaction.expiration, max_expiration
                ),
            });
        }

        Ok(())
    }

    /// Validate transaction size
    pub fn validate_transaction_size(
        transaction: &Transaction,
        parameters: &ChainParameters,
    ) -> ChainResult<()> {
        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        let serialized = bincode::encode_to_vec(transaction, config).map_err(|e| ChainError::ValidationError {
            field: "serialization".to_string(),
            reason: format!("Failed to serialize transaction: {}", e),
        })?;

        let size = serialized.len() as u32;
        if size > parameters.maximum_transaction_size {
            return Err(ChainError::ValidationError {
                field: "size".to_string(),
                reason: format!(
                    "Transaction size {} exceeds maximum allowed size {}",
                    size, parameters.maximum_transaction_size
                ),
            });
        }

        Ok(())
    }

    /// Validate all operations in a transaction
    pub fn validate_transaction_operations(
        transaction: &Transaction,
        parameters: &ChainParameters,
    ) -> ChainResult<()> {
        for (i, operation) in transaction.operations.iter().enumerate() {
            Self::validate_operation(operation, parameters).map_err(|e| ChainError::ValidationError {
                field: format!("operation[{}]", i),
                reason: format!("Operation validation failed: {}", e),
            })?;
        }
        Ok(())
    }

    /// Validate transaction fees
    pub fn validate_transaction_fees(transaction: &Transaction) -> ChainResult<()> {
        let core_asset = ObjectId::new(1, 2, 0)?;
        
        for (i, operation) in transaction.operations.iter().enumerate() {
            let fee = Self::get_operation_fee(operation);
            
            // Fee must be positive
            if fee.amount <= 0 {
                return Err(ChainError::ValidationError {
                    field: format!("operation[{}].fee", i),
                    reason: "Operation fee must be positive".to_string(),
                });
            }
            
            // Fee must be paid in core asset
            if fee.asset_id != core_asset {
                return Err(ChainError::ValidationError {
                    field: format!("operation[{}].fee", i),
                    reason: "Operation fee must be paid in core asset".to_string(),
                });
            }
        }
        
        Ok(())
    }

    /// Validate individual operation
    pub fn validate_operation(
        operation: &Operation,
        parameters: &ChainParameters,
    ) -> ChainResult<()> {
        match operation {
            Operation::Transfer { from, to, amount, memo, .. } => {
                Self::validate_transfer_operation(from, to, amount, memo.as_ref())?;
            }
            Operation::LimitOrderCreate {
                seller,
                amount_to_sell,
                min_to_receive,
                expiration,
                ..
            } => {
                Self::validate_limit_order_create_operation(
                    seller,
                    amount_to_sell,
                    min_to_receive,
                    *expiration
                )?;
            }
            Operation::LimitOrderCancel { order, .. } => {
                Self::validate_limit_order_cancel_operation(order)?;
            }
            Operation::AccountCreate {
                name,
                owner,
                active,
                options,
                ..
            } => {
                Self::validate_account_create_operation(name, owner, active, options, parameters)?;
            }
            Operation::AccountUpdate {
                account,
                owner,
                active,
                new_options,
                ..
            } => {
                Self::validate_account_update_operation(account, owner.as_ref(), active.as_ref(), new_options.as_ref())?;
            }
            Operation::AssetCreate {
                symbol,
                precision,
                common_options,
                ..
            } => {
                Self::validate_asset_create_operation(symbol, *precision, common_options)?;
            }
            Operation::AssetUpdate {
                asset_to_update,
                new_options,
                ..
            } => {
                // Validate asset ID
                if !asset_to_update.is_asset() {
                    return Err(ChainError::ValidationError {
                        field: "asset_to_update".to_string(),
                        reason: "Invalid asset ID".to_string(),
                    });
                }
                // Validate new options if provided
                if let Some(options) = new_options {
                    Self::validate_asset_options(options)?;
                }
            }
            Operation::AssetIssue {
                asset_to_issue,
                issue_to_account,
                ..
            } => {
                // Validate asset amount
                if asset_to_issue.amount <= 0 {
                    return Err(ChainError::ValidationError {
                        field: "asset_to_issue".to_string(),
                        reason: "Issue amount must be positive".to_string(),
                    });
                }
                // Validate asset ID
                if !asset_to_issue.asset_id.is_asset() {
                    return Err(ChainError::ValidationError {
                        field: "asset_to_issue".to_string(),
                        reason: "Invalid asset ID".to_string(),
                    });
                }
                // Validate recipient account
                if !issue_to_account.is_account() {
                    return Err(ChainError::ValidationError {
                        field: "issue_to_account".to_string(),
                        reason: "Invalid account ID".to_string(),
                    });
                }
            }
            Operation::Custom {
                required_auths,
                data,
                ..
            } => {
                // Validate required authorities
                for auth in required_auths {
                    if !auth.is_account() {
                        return Err(ChainError::ValidationError {
                            field: "required_auths".to_string(),
                            reason: "Invalid account ID in required authorities".to_string(),
                        });
                    }
                }
                // Validate data size (e.g., max 1KB)
                if data.len() > 1024 {
                    return Err(ChainError::ValidationError {
                        field: "data".to_string(),
                        reason: "Custom operation data too large".to_string(),
                    });
                }
            }
        }
        
        Ok(())
    }

    /// Validate transfer operation
    fn validate_transfer_operation(
        from: &ObjectId,
        to: &ObjectId,
        amount: &AssetAmount,
        memo: Option<&Memo>,
    ) -> ChainResult<()> {
        // Cannot transfer to self
        if from == to {
            return Err(ChainError::ValidationError {
                field: "transfer".to_string(),
                reason: "Cannot transfer to self".to_string(),
            });
        }

        // Amount must be positive
        if amount.amount <= 0 {
            return Err(ChainError::ValidationError {
                field: "amount".to_string(),
                reason: "Transfer amount must be positive".to_string(),
            });
        }

        // Validate account IDs
        if !from.is_account() {
            return Err(ChainError::ValidationError {
                field: "from".to_string(),
                reason: "From field must be an account ID".to_string(),
            });
        }

        if !to.is_account() {
            return Err(ChainError::ValidationError {
                field: "to".to_string(),
                reason: "To field must be an account ID".to_string(),
            });
        }

        // Validate asset ID
        if !amount.asset_id.is_asset() {
            return Err(ChainError::ValidationError {
                field: "asset_id".to_string(),
                reason: "Invalid asset ID".to_string(),
            });
        }

        // Validate memo if present
        if let Some(memo) = memo {
            Self::validate_memo(memo)?;
        }

        Ok(())
    }

    /// Validate limit order create operation
    fn validate_limit_order_create_operation(
        seller: &ObjectId,
        amount_to_sell: &AssetAmount,
        min_to_receive: &AssetAmount,
        expiration: u32,
    ) -> ChainResult<()> {
        // Seller must be an account
        if !seller.is_account() {
            return Err(ChainError::ValidationError {
                field: "seller".to_string(),
                reason: "Seller must be an account ID".to_string(),
            });
        }

        // Amount to sell must be positive
        if amount_to_sell.amount <= 0 {
            return Err(ChainError::ValidationError {
                field: "amount_to_sell".to_string(),
                reason: "Amount to sell must be positive".to_string(),
            });
        }

        // Minimum to receive must be positive
        if min_to_receive.amount <= 0 {
            return Err(ChainError::ValidationError {
                field: "min_to_receive".to_string(),
                reason: "Minimum to receive must be positive".to_string(),
            });
        }

        // Cannot trade same asset
        if amount_to_sell.asset_id == min_to_receive.asset_id {
            return Err(ChainError::ValidationError {
                field: "assets".to_string(),
                reason: "Cannot trade the same asset".to_string(),
            });
        }

        // Validate asset IDs
        if !amount_to_sell.asset_id.is_asset() || !min_to_receive.asset_id.is_asset() {
            return Err(ChainError::ValidationError {
                field: "asset_ids".to_string(),
                reason: "Invalid asset IDs".to_string(),
            });
        }

        // Validate expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChainError::ValidationError {
                field: "time".to_string(),
                reason: "System time error".to_string(),
            })?
            .as_secs() as u32;

        if expiration <= now {
            return Err(ChainError::ValidationError {
                field: "expiration".to_string(),
                reason: "Order expiration must be in the future".to_string(),
            });
        }

        Ok(())
    }

    /// Validate limit order cancel operation
    fn validate_limit_order_cancel_operation(order: &ObjectId) -> ChainResult<()> {
        if !order.is_limit_order() {
            return Err(ChainError::ValidationError {
                field: "order".to_string(),
                reason: "Order ID must be a limit order".to_string(),
            });
        }
        Ok(())
    }

    /// Validate account create operation
    fn validate_account_create_operation(
        name: &str,
        owner: &Authority,
        active: &Authority,
        options: &AccountOptions,
        parameters: &ChainParameters,
    ) -> ChainResult<()> {
        // Validate account name
        crate::chain::ChainTypes::validate_account_name(name)?;

        // Validate authorities
        Self::validate_authority(owner, parameters)?;
        Self::validate_authority(active, parameters)?;

        // Owner authority must be stronger than or equal to active
        if owner.weight_threshold < active.weight_threshold {
            return Err(ChainError::ValidationError {
                field: "authorities".to_string(),
                reason: "Owner authority threshold must be >= active authority threshold".to_string(),
            });
        }

        // Validate account options
        Self::validate_account_options(options)?;

        Ok(())
    }

    /// Validate account update operation
    fn validate_account_update_operation(
        account: &ObjectId,
        owner: Option<&Authority>,
        active: Option<&Authority>,
        new_options: Option<&AccountOptions>,
    ) -> ChainResult<()> {
        // Account must be an account ID
        if !account.is_account() {
            return Err(ChainError::ValidationError {
                field: "account".to_string(),
                reason: "Account must be an account ID".to_string(),
            });
        }

        // At least one field must be updated
        if owner.is_none() && active.is_none() && new_options.is_none() {
            return Err(ChainError::ValidationError {
                field: "update".to_string(),
                reason: "At least one field must be updated".to_string(),
            });
        }

        // Validate authorities if provided
        if let Some(owner_auth) = owner {
            Self::validate_authority(owner_auth, &ChainParameters::default())?;
        }

        if let Some(active_auth) = active {
            Self::validate_authority(active_auth, &ChainParameters::default())?;
        }

        // Validate options if provided
        if let Some(options) = new_options {
            Self::validate_account_options(options)?;
        }

        Ok(())
    }

    /// Validate asset create operation
    fn validate_asset_create_operation(
        symbol: &str,
        precision: u8,
        common_options: &AssetOptions,
    ) -> ChainResult<()> {
        // Validate asset symbol
        crate::chain::ChainTypes::validate_asset_symbol(symbol)?;

        // Validate precision
        if precision > 18 {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: "Asset precision cannot exceed 18 decimal places".to_string(),
            });
        }

        // Validate asset options
        Self::validate_asset_options(common_options)?;

        Ok(())
    }

    /// Validate authority structure
    fn validate_authority(authority: &Authority, parameters: &ChainParameters) -> ChainResult<()> {
        // Weight threshold must be positive
        if authority.weight_threshold == 0 {
            return Err(ChainError::ValidationError {
                field: "weight_threshold".to_string(),
                reason: "Authority weight threshold must be positive".to_string(),
            });
        }

        // Check total number of authorities
        let total_auths = authority.account_auths.len() + 
                         authority.key_auths.len() + 
                         authority.address_auths.len();

        if total_auths == 0 {
            return Err(ChainError::ValidationError {
                field: "authorities".to_string(),
                reason: "Authority must have at least one key, account, or address".to_string(),
            });
        }

        if total_auths > parameters.maximum_authority_membership as usize {
            return Err(ChainError::ValidationError {
                field: "authorities".to_string(),
                reason: format!(
                    "Authority has {} members, maximum allowed is {}",
                    total_auths, parameters.maximum_authority_membership
                ),
            });
        }

        // Validate account authorities
        for (account_id, weight) in &authority.account_auths {
            if !account_id.is_account() {
                return Err(ChainError::ValidationError {
                    field: "account_auths".to_string(),
                    reason: "Invalid account ID in authority".to_string(),
                });
            }
            if *weight == 0 {
                return Err(ChainError::ValidationError {
                    field: "account_auths".to_string(),
                    reason: "Authority weight must be positive".to_string(),
                });
            }
        }

        // Validate key authorities
        for (key, weight) in &authority.key_auths {
            if key.is_empty() {
                return Err(ChainError::ValidationError {
                    field: "key_auths".to_string(),
                    reason: "Public key cannot be empty".to_string(),
                });
            }
            if *weight == 0 {
                return Err(ChainError::ValidationError {
                    field: "key_auths".to_string(),
                    reason: "Authority weight must be positive".to_string(),
                });
            }
        }

        // Validate address authorities
        for (address, weight) in &authority.address_auths {
            if address.is_empty() {
                return Err(ChainError::ValidationError {
                    field: "address_auths".to_string(),
                    reason: "Address cannot be empty".to_string(),
                });
            }
            if *weight == 0 {
                return Err(ChainError::ValidationError {
                    field: "address_auths".to_string(),
                    reason: "Authority weight must be positive".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate account options
    fn validate_account_options(options: &AccountOptions) -> ChainResult<()> {
        // Validate memo key
        if options.memo_key.is_empty() {
            return Err(ChainError::ValidationError {
                field: "memo_key".to_string(),
                reason: "Memo key cannot be empty".to_string(),
            });
        }

        // Validate voting account
        if !options.voting_account.is_account() {
            return Err(ChainError::ValidationError {
                field: "voting_account".to_string(),
                reason: "Voting account must be a valid account ID".to_string(),
            });
        }

        // Validate vote counts
        if options.votes.len() != (options.num_witness + options.num_committee) as usize {
            return Err(ChainError::ValidationError {
                field: "votes".to_string(),
                reason: "Vote count mismatch".to_string(),
            });
        }

        Ok(())
    }

    /// Validate asset options
    fn validate_asset_options(options: &AssetOptions) -> ChainResult<()> {
        // Max supply must be positive
        if options.max_supply <= 0 {
            return Err(ChainError::ValidationError {
                field: "max_supply".to_string(),
                reason: "Maximum supply must be positive".to_string(),
            });
        }

        // Market fee percent must be reasonable
        if options.market_fee_percent > 10000 {
            return Err(ChainError::ValidationError {
                field: "market_fee_percent".to_string(),
                reason: "Market fee percent cannot exceed 100%".to_string(),
            });
        }

        // Max market fee must be non-negative
        if options.max_market_fee < 0 {
            return Err(ChainError::ValidationError {
                field: "max_market_fee".to_string(),
                reason: "Maximum market fee cannot be negative".to_string(),
            });
        }

        // Validate core exchange rate
        Self::validate_price(&options.core_exchange_rate)?;

        Ok(())
    }

    /// Validate price structure
    fn validate_price(price: &Price) -> ChainResult<()> {
        if price.base.amount <= 0 {
            return Err(ChainError::ValidationError {
                field: "price.base".to_string(),
                reason: "Price base amount must be positive".to_string(),
            });
        }

        if price.quote.amount <= 0 {
            return Err(ChainError::ValidationError {
                field: "price.quote".to_string(),
                reason: "Price quote amount must be positive".to_string(),
            });
        }

        if !price.base.asset_id.is_asset() || !price.quote.asset_id.is_asset() {
            return Err(ChainError::ValidationError {
                field: "price.assets".to_string(),
                reason: "Invalid asset IDs in price".to_string(),
            });
        }

        Ok(())
    }

    /// Validate memo structure
    fn validate_memo(memo: &Memo) -> ChainResult<()> {
        if memo.from.is_empty() {
            return Err(ChainError::ValidationError {
                field: "memo.from".to_string(),
                reason: "Memo from key cannot be empty".to_string(),
            });
        }

        if memo.to.is_empty() {
            return Err(ChainError::ValidationError {
                field: "memo.to".to_string(),
                reason: "Memo to key cannot be empty".to_string(),
            });
        }

        if memo.message.is_empty() {
            return Err(ChainError::ValidationError {
                field: "memo.message".to_string(),
                reason: "Memo message cannot be empty".to_string(),
            });
        }

        // Check message size limit (e.g., 2KB)
        if memo.message.len() > 2048 {
            return Err(ChainError::ValidationError {
                field: "memo.message".to_string(),
                reason: "Memo message too large".to_string(),
            });
        }

        Ok(())
    }

    /// Get operation fee
    fn get_operation_fee(operation: &Operation) -> &AssetAmount {
        match operation {
            Operation::Transfer { fee, .. } => fee,
            Operation::LimitOrderCreate { fee, .. } => fee,
            Operation::LimitOrderCancel { fee, .. } => fee,
            Operation::AccountCreate { fee, .. } => fee,
            Operation::AccountUpdate { fee, .. } => fee,
            Operation::AssetCreate { fee, .. } => fee,
            Operation::AssetUpdate { fee, .. } => fee,
            Operation::AssetIssue { fee, .. } => fee,
            Operation::Custom { fee, .. } => fee,
        }
    }

    /// Validate block structure
    pub fn validate_block(block: &Block, previous_block: Option<&Block>) -> ChainResult<()> {
        // Validate block header
        Self::validate_block_header(&block.header, previous_block)?;

        // Validate transactions
        for (i, transaction) in block.transactions.iter().enumerate() {
            Self::validate_signed_transaction(transaction).map_err(|e| ChainError::ValidationError {
                field: format!("transaction[{}]", i),
                reason: format!("Transaction validation failed: {}", e),
            })?;
        }

        // Validate witness signature
        if block.witness_signature.is_empty() {
            return Err(ChainError::ValidationError {
                field: "witness_signature".to_string(),
                reason: "Block must have witness signature".to_string(),
            });
        }

        Ok(())
    }

    /// Validate block header
    fn validate_block_header(header: &BlockHeader, previous_block: Option<&Block>) -> ChainResult<()> {
        // Validate witness
        if !header.witness.is_witness() {
            return Err(ChainError::ValidationError {
                field: "witness".to_string(),
                reason: "Block witness must be a witness account".to_string(),
            });
        }

        // Validate timestamp
        if header.timestamp == 0 {
            return Err(ChainError::ValidationError {
                field: "timestamp".to_string(),
                reason: "Block timestamp must be set".to_string(),
            });
        }

        // Validate previous block reference
        if let Some(prev_block) = previous_block {
            let config = bincode::config::standard()
                .with_little_endian()
                .with_fixed_int_encoding();
            let serialized_header = bincode::encode_to_vec(&prev_block.header, config).unwrap();
            let expected_previous = crate::ecc::hash::sha256(&serialized_header);
            let expected_previous_hex = hex::encode(expected_previous);
            
            if header.previous != expected_previous_hex {
                return Err(ChainError::ValidationError {
                    field: "previous".to_string(),
                    reason: "Invalid previous block reference".to_string(),
                });
            }

            // Timestamp must be after previous block
            if header.timestamp <= prev_block.header.timestamp {
                return Err(ChainError::ValidationError {
                    field: "timestamp".to_string(),
                    reason: "Block timestamp must be after previous block".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate signed transaction
    fn validate_signed_transaction(transaction: &SignedTransaction) -> ChainResult<()> {
        // Validate transaction ID
        let calculated_id = crate::chain::TransactionHelper::calculate_transaction_id(&transaction.transaction)?;
        if transaction.transaction_id != calculated_id {
            return Err(ChainError::ValidationError {
                field: "transaction_id".to_string(),
                reason: "Transaction ID mismatch".to_string(),
            });
        }

        // Validate signatures exist
        if transaction.transaction.signatures.is_empty() {
            return Err(ChainError::ValidationError {
                field: "signatures".to_string(),
                reason: "Transaction must have at least one signature".to_string(),
            });
        }

        Ok(())
    }
}

/// Default implementation for ChainParameters (for testing)
impl Default for ChainParameters {
    fn default() -> Self {
        Self {
            current_fees: FeeSchedule {
                parameters: vec![],
                scale: 10000,
            },
            block_interval: 3,
            maintenance_interval: 86400,
            maintenance_skip_slots: 3,
            committee_proposal_review_period: 1209600,
            maximum_transaction_size: 1024 * 1024,
            maximum_block_size: 2 * 1024 * 1024,
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
            cashback_vesting_threshold: 100000,
            count_non_member_votes: true,
            allow_non_member_whitelists: false,
            witness_pay_per_block: 1000,
            worker_budget_per_day: 50000000,
            max_predicate_opcode: 1,
            fee_liquidation_threshold: 100000,
            accounts_per_fee_scale: 1000,
            account_fee_scale_bitshifts: 4,
            max_authority_depth: 2,
            extensions: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_transaction_structure() {
        // Empty operations should fail
        let transaction = Transaction {
            ref_block_num: 12345,
            ref_block_prefix: 0x12345678,
            expiration: 4294967295,
            operations: vec![],
            extensions: vec![],
            signatures: vec![],
        };
        
        assert!(ChainValidation::validate_transaction_structure(&transaction).is_err());
    }

    #[test]
    fn test_validate_transfer_operation() {
        let from = ObjectId::new(1, 1, 1).unwrap();
        let to = ObjectId::new(1, 1, 2).unwrap();
        let amount = AssetAmount {
            amount: 10000,
            asset_id: ObjectId::new(1, 2, 0).unwrap(),
        };
        
        // Valid transfer
        assert!(ChainValidation::validate_transfer_operation(&from, &to, &amount, None).is_ok());
        
        // Transfer to self should fail
        assert!(ChainValidation::validate_transfer_operation(&from, &from, &amount, None).is_err());
        
        // Zero amount should fail
        let zero_amount = AssetAmount {
            amount: 0,
            asset_id: ObjectId::new(1, 2, 0).unwrap(),
        };
        assert!(ChainValidation::validate_transfer_operation(&from, &to, &zero_amount, None).is_err());
    }

    #[test]
    fn test_validate_authority() {
        let mut authority = Authority {
            weight_threshold: 1,
            account_auths: HashMap::new(),
            key_auths: HashMap::new(),
            address_auths: HashMap::new(),
        };
        
        // Empty authority should fail
        assert!(ChainValidation::validate_authority(&authority, &ChainParameters::default()).is_err());
        
        // Add a key authority
        authority.key_auths.insert("RSQ6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV".to_string(), 1);
        assert!(ChainValidation::validate_authority(&authority, &ChainParameters::default()).is_ok());
        
        // Zero weight threshold should fail
        authority.weight_threshold = 0;
        assert!(ChainValidation::validate_authority(&authority, &ChainParameters::default()).is_err());
    }

    #[test]
    fn test_validate_account_name() {
        assert!(crate::chain::ChainTypes::validate_account_name("alice").is_ok());
        assert!(crate::chain::ChainTypes::validate_account_name("bob-123").is_ok());
        assert!(crate::chain::ChainTypes::validate_account_name("").is_err());
        assert!(crate::chain::ChainTypes::validate_account_name("Alice").is_err());
    }

    #[test]
    fn test_validate_asset_symbol() {
        assert!(crate::chain::ChainTypes::validate_asset_symbol("BTC").is_ok());
        assert!(crate::chain::ChainTypes::validate_asset_symbol("USD.COIN").is_ok());
        assert!(crate::chain::ChainTypes::validate_asset_symbol("").is_err());
        assert!(crate::chain::ChainTypes::validate_asset_symbol("btc").is_err());
    }

    #[test]
    fn test_validate_price() {
        let price = Price {
            base: AssetAmount {
                amount: 100,
                asset_id: ObjectId::new(1, 2, 0).unwrap(),
            },
            quote: AssetAmount {
                amount: 200,
                asset_id: ObjectId::new(1, 2, 1).unwrap(),
            },
        };
        
        assert!(ChainValidation::validate_price(&price).is_ok());
        
        // Zero base amount should fail
        let invalid_price = Price {
            base: AssetAmount {
                amount: 0,
                asset_id: ObjectId::new(1, 2, 0).unwrap(),
            },
            quote: AssetAmount {
                amount: 200,
                asset_id: ObjectId::new(1, 2, 1).unwrap(),
            },
        };
        
        assert!(ChainValidation::validate_price(&invalid_price).is_err());
    }
}