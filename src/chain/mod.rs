//! Chain module for blockchain operations
//!
//! This module provides functionality for blockchain operations including
//! transaction building, chain state management, and blockchain validation.

pub mod transaction_builder;
pub mod chain_store;
pub mod chain_types;
pub mod object_id;
pub mod number_utils;
pub mod transaction_helper;
pub mod chain_validation;
pub mod account_login;

// Re-export main types for convenience
pub use transaction_builder::TransactionBuilder;
pub use chain_store::{ChainStore, ChainStoreConfig};
pub use chain_types::*;
pub use object_id::{ObjectId, constants as object_constants};
pub use number_utils::{NumberUtils, PrecisionNumber};
pub use transaction_helper::TransactionHelper;
pub use chain_validation::ChainValidation;
pub use account_login::{AccountLogin, LoginSession, LoginCredentials, LoginChallenge, LoginResponse};

use crate::error::{ChainError, ChainResult};

/// Common blockchain constants
pub mod constants {
    //! Constants used throughout the chain module
    
    /// Maximum transaction size in bytes
    pub const MAX_TRANSACTION_SIZE: usize = 1024 * 1024; // 1MB
    
    /// Maximum number of operations per transaction
    pub const MAX_OPERATIONS_PER_TRANSACTION: usize = 100;
    
    /// Block time in seconds
    pub const BLOCK_TIME_SECONDS: u64 = 3;
    
    /// Maximum memo size in bytes
    pub const MAX_MEMO_SIZE: usize = 2048;
    
    /// Default session timeout in seconds
    pub const DEFAULT_SESSION_TIMEOUT: u64 = 3600; // 1 hour
    
    /// Default challenge timeout in seconds
    pub const DEFAULT_CHALLENGE_TIMEOUT: u64 = 300; // 5 minutes
}

/// High-level Chain API for common operations
#[derive(Debug)]
pub struct Chain {
    /// Transaction builder
    pub transaction_builder: TransactionBuilder,
    /// Chain store for state management
    pub chain_store: ChainStore,
    /// Account login manager
    pub account_login: AccountLogin,
}

impl Chain {
    /// Create a new Chain instance
    pub fn new() -> Self {
        Self {
            transaction_builder: TransactionBuilder::new(),
            chain_store: ChainStore::new(),
            account_login: AccountLogin::new(),
        }
    }

    /// Create a new Chain instance with custom configuration
    pub fn with_config(store_config: ChainStoreConfig) -> Self {
        Self {
            transaction_builder: TransactionBuilder::new(),
            chain_store: ChainStore::with_config(store_config),
            account_login: AccountLogin::new(),
        }
    }

    /// Get account by ID
    pub async fn get_account(&self, account_id: &ObjectId) -> ChainResult<Account> {
        self.chain_store.get_account(account_id).await
    }

    /// Get account by name
    pub async fn get_account_by_name(&self, name: &str) -> ChainResult<Account> {
        self.chain_store.get_account_by_name(name).await
    }

    /// Get asset by ID
    pub async fn get_asset(&self, asset_id: &ObjectId) -> ChainResult<Asset> {
        self.chain_store.get_asset(asset_id).await
    }

    /// Get asset by symbol
    pub async fn get_asset_by_symbol(&self, symbol: &str) -> ChainResult<Asset> {
        self.chain_store.get_asset_by_symbol(symbol).await
    }

    /// Create a transfer transaction
    pub fn create_transfer(
        &mut self,
        from: ObjectId,
        to: ObjectId,
        amount: AssetAmount,
        memo: Option<Memo>,
    ) -> ChainResult<()> {
        self.transaction_builder.add_transfer(from, to, amount, memo)
    }

    /// Create a limit order
    pub fn create_limit_order(
        &mut self,
        seller: ObjectId,
        amount_to_sell: AssetAmount,
        min_to_receive: AssetAmount,
        expiration: u32,
        fill_or_kill: bool,
    ) -> ChainResult<()> {
        self.transaction_builder.add_limit_order_create(
            seller,
            amount_to_sell,
            min_to_receive,
            expiration,
            fill_or_kill,
        )
    }

    /// Build and sign transaction
    pub fn build_and_sign_transaction(
        &self,
        private_keys: &[crate::ecc::PrivateKey],
    ) -> ChainResult<SignedTransaction> {
        self.transaction_builder.build_and_sign(private_keys)
    }

    /// Validate transaction
    pub async fn validate_transaction(&self, transaction: &Transaction) -> ChainResult<()> {
        let chain_properties = self.chain_store.get_chain_properties().await?;
        let global_properties = self.chain_store.get_global_properties().await?;
        
        ChainValidation::validate_transaction(transaction, &chain_properties, &global_properties)
    }

    /// Broadcast transaction
    pub async fn broadcast_transaction(
        &self,
        transaction: &SignedTransaction,
    ) -> ChainResult<String> {
        // Get API URL from chain store config
        let api_url = &self.chain_store.config.api_url;
        TransactionHelper::broadcast_transaction(transaction, api_url).await
    }

    /// Login with credentials
    pub fn login(&mut self, credentials: &LoginCredentials) -> ChainResult<LoginChallenge> {
        // For now, create a challenge without specific account requirement
        self.account_login.create_challenge(None)
    }

    /// Complete login process
    pub async fn complete_login(
        &mut self,
        response: &LoginResponse,
    ) -> ChainResult<LoginSession> {
        let account = self.get_account(&response.account_id).await?;
        self.account_login.verify_and_create_session(response, &account)
    }

    /// Validate session
    pub fn validate_session(&self, session_token: &str) -> ChainResult<&LoginSession> {
        self.account_login.validate_session(session_token)
    }

    /// Logout session
    pub fn logout(&mut self, session_token: &str) -> ChainResult<()> {
        self.account_login.logout(session_token)
    }

    /// Clear transaction builder
    pub fn clear_transaction(&mut self) {
        self.transaction_builder.clear_operations();
    }

    /// Set transaction expiration
    pub fn set_transaction_expiration(&mut self, seconds_from_now: u32) -> ChainResult<()> {
        self.transaction_builder.set_expiration(seconds_from_now)
    }

    /// Set reference block for transaction
    pub fn set_reference_block(&mut self, block_num: u32, block_id: &str) -> ChainResult<()> {
        self.transaction_builder.set_reference_block(block_num, block_id)
    }

    /// Get transaction operations count
    pub fn transaction_operations_count(&self) -> usize {
        self.transaction_builder.operations_count()
    }

    /// Calculate transaction fees
    pub fn calculate_transaction_fees(&self) -> ChainResult<AssetAmount> {
        self.transaction_builder.calculate_total_fees()
    }

    /// Estimate transaction size
    pub fn estimate_transaction_size(&self) -> ChainResult<usize> {
        self.transaction_builder.estimate_size()
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for common chain operations
pub mod utils {
    use super::*;

    /// Create a simple transfer transaction
    pub fn create_simple_transfer(
        from: ObjectId,
        to: ObjectId,
        amount: i64,
        asset_id: ObjectId,
        memo_text: Option<&str>,
        from_private_key: &crate::ecc::PrivateKey,
        to_public_key: Option<&crate::ecc::PublicKey>,
    ) -> ChainResult<TransactionBuilder> {
        let mut builder = TransactionBuilder::new();
        
        let asset_amount = AssetAmount { amount, asset_id };
        
        let memo = if let (Some(text), Some(to_key)) = (memo_text, to_public_key) {
            Some(TransactionHelper::create_memo(
                from_private_key,
                to_key,
                text,
                0, // nonce
            )?)
        } else {
            None
        };
        
        builder.add_transfer(from, to, asset_amount, memo)?;
        
        Ok(builder)
    }

    /// Create account creation transaction
    pub fn create_account_creation(
        registrar: ObjectId,
        name: &str,
        owner_key: &str,
        active_key: &str,
        memo_key: &str,
    ) -> ChainResult<TransactionBuilder> {
        let mut builder = TransactionBuilder::new();
        
        let owner_authority = ChainTypes::create_default_authority(owner_key, 1);
        let active_authority = ChainTypes::create_default_authority(active_key, 1);
        
        let options = AccountOptions {
            memo_key: memo_key.to_string(),
            voting_account: object_constants::PROXY_TO_SELF_ACCOUNT,
            num_witness: 0,
            num_committee: 0,
            votes: vec![],
            extensions: vec![],
        };
        
        builder.add_account_create(
            registrar,
            object_constants::PROXY_TO_SELF_ACCOUNT, // referrer
            0, // referrer_percent
            name.to_string(),
            owner_authority,
            active_authority,
            options,
        )?;
        
        Ok(builder)
    }

    /// Create asset creation transaction
    pub fn create_asset_creation(
        issuer: ObjectId,
        symbol: &str,
        precision: u8,
        max_supply: i64,
    ) -> ChainResult<TransactionBuilder> {
        let mut builder = TransactionBuilder::new();
        
        let core_exchange_rate = Price {
            base: AssetAmount {
                amount: 1,
                asset_id: object_constants::CORE_ASSET,
            },
            quote: AssetAmount {
                amount: 1,
                asset_id: object_constants::CORE_ASSET,
            },
        };
        
        let options = AssetOptions {
            max_supply,
            market_fee_percent: 0,
            max_market_fee: 0,
            issuer_permissions: 0,
            flags: 0,
            core_exchange_rate,
            whitelist_authorities: vec![],
            blacklist_authorities: vec![],
            whitelist_markets: vec![],
            blacklist_markets: vec![],
            description: String::new(),
            extensions: vec![],
        };
        
        builder.add_asset_create(
            issuer,
            symbol.to_string(),
            precision,
            options,
            None, // bitasset_opts
            false, // is_prediction_market
        )?;
        
        Ok(builder)
    }

    /// Parse object ID from string
    pub fn parse_object_id(id_str: &str) -> ChainResult<ObjectId> {
        ObjectId::from_string(id_str)
    }

    /// Create asset amount
    pub fn create_asset_amount(amount: i64, asset_id: ObjectId) -> AssetAmount {
        ChainTypes::create_asset_amount(amount, asset_id)
    }

    /// Validate account name
    pub fn validate_account_name(name: &str) -> ChainResult<()> {
        ChainTypes::validate_account_name(name)
    }

    /// Validate asset symbol
    pub fn validate_asset_symbol(symbol: &str) -> ChainResult<()> {
        ChainTypes::validate_asset_symbol(symbol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_creation() {
        let chain = Chain::new();
        assert_eq!(chain.transaction_operations_count(), 0);
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::MAX_TRANSACTION_SIZE, 1024 * 1024);
        assert_eq!(constants::BLOCK_TIME_SECONDS, 3);
        assert_eq!(constants::MAX_OPERATIONS_PER_TRANSACTION, 100);
    }

    #[test]
    fn test_utils_parse_object_id() {
        let obj_id = utils::parse_object_id("1.2.100").unwrap();
        assert_eq!(obj_id.space(), 1);
        assert_eq!(obj_id.type_id(), 2);
        assert_eq!(obj_id.instance(), 100);
    }

    #[test]
    fn test_utils_create_asset_amount() {
        let asset_id = ObjectId::new(1, 3, 0).unwrap();
        let amount = utils::create_asset_amount(10000, asset_id.clone());
        assert_eq!(amount.amount, 10000);
        assert_eq!(amount.asset_id, asset_id);
    }

    #[test]
    fn test_utils_validate_names() {
        assert!(utils::validate_account_name("alice").is_ok());
        assert!(utils::validate_account_name("Alice").is_err());
        
        assert!(utils::validate_asset_symbol("BTC").is_ok());
        assert!(utils::validate_asset_symbol("btc").is_err());
    }

    #[test]
    fn test_chain_transaction_operations() {
        let mut chain = Chain::new();
        
