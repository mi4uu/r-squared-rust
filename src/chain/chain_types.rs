//! Chain types and constants for R-Squared blockchain
//!
//! This module defines the core data structures and types used in the
//! R-Squared blockchain, including accounts, assets, operations, and transactions.

use crate::chain::ObjectId;
use crate::error::{ChainError, ChainResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Account object representing a blockchain account
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Account ID (1.2.x)
    pub id: ObjectId,
    /// Account name
    pub name: String,
    /// Owner authority
    pub owner: Authority,
    /// Active authority
    pub active: Authority,
    /// Options for the account
    pub options: AccountOptions,
    /// Statistics object ID
    pub statistics: ObjectId,
    /// Whitelisting accounts
    pub whitelisting_accounts: Vec<ObjectId>,
    /// Blacklisting accounts
    pub blacklisting_accounts: Vec<ObjectId>,
    /// Whitelisted assets
    pub whitelisted_assets: Vec<ObjectId>,
    /// Blacklisted assets
    pub blacklisted_assets: Vec<ObjectId>,
    /// Owner special authority
    pub owner_special_authority: Option<SpecialAuthority>,
    /// Active special authority
    pub active_special_authority: Option<SpecialAuthority>,
    /// Top N control flags
    pub top_n_control_flags: u8,
}

/// Asset object representing a blockchain asset
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// Asset ID (1.3.x)
    pub id: ObjectId,
    /// Asset symbol
    pub symbol: String,
    /// Precision (number of decimal places)
    pub precision: u8,
    /// Issuer account ID
    pub issuer: ObjectId,
    /// Asset options
    pub options: AssetOptions,
    /// Dynamic asset data ID
    pub dynamic_asset_data_id: ObjectId,
    /// Bitasset data ID (if applicable)
    pub bitasset_data_id: Option<ObjectId>,
}

/// Authority structure for account permissions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Authority {
    /// Weight threshold required
    pub weight_threshold: u32,
    /// Account authorities with weights
    pub account_auths: HashMap<ObjectId, u16>,
    /// Key authorities with weights
    pub key_auths: HashMap<String, u16>,
    /// Address authorities with weights
    pub address_auths: HashMap<String, u16>,
}

/// Account options
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountOptions {
    /// Memo key
    pub memo_key: String,
    /// Voting account
    pub voting_account: ObjectId,
    /// Number of witness votes
    pub num_witness: u16,
    /// Number of committee votes
    pub num_committee: u16,
    /// Witness votes
    pub votes: Vec<ObjectId>,
    /// Extensions
    pub extensions: Vec<Extension>,
}

impl Default for AccountOptions {
    fn default() -> Self {
        Self {
            memo_key: String::new(),
            voting_account: ObjectId::new(1, 2, 0).unwrap_or_default(),
            num_witness: 0,
            num_committee: 0,
            votes: Vec::new(),
            extensions: Vec::new(),
        }
    }
}

/// Asset options
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AssetOptions {
    /// Maximum supply
    pub max_supply: i64,
    /// Market fee percent
    pub market_fee_percent: u16,
    /// Maximum market fee
    pub max_market_fee: i64,
    /// Issuer permissions
    pub issuer_permissions: u16,
    /// Flags
    pub flags: u16,
    /// Core exchange rate
    pub core_exchange_rate: Price,
    /// Whitelist authorities
    pub whitelist_authorities: Vec<ObjectId>,
    /// Blacklist authorities
    pub blacklist_authorities: Vec<ObjectId>,
    /// Whitelist markets
    pub whitelist_markets: Vec<ObjectId>,
    /// Blacklist markets
    pub blacklist_markets: Vec<ObjectId>,
    /// Description
    pub description: String,
    /// Extensions
    pub extensions: Vec<Extension>,
}

impl Default for AssetOptions {
    fn default() -> Self {
        Self {
            max_supply: 1000000000000000i64, // 1 quadrillion
            market_fee_percent: 0,
            max_market_fee: 1000000000000000i64,
            issuer_permissions: 0,
            flags: 0,
            core_exchange_rate: Price {
                base: AssetAmount {
                    amount: 1,
                    asset_id: ObjectId::new(1, 3, 0).unwrap_or_default(),
                },
                quote: AssetAmount {
                    amount: 1,
                    asset_id: ObjectId::new(1, 3, 0).unwrap_or_default(),
                },
            },
            whitelist_authorities: Vec::new(),
            blacklist_authorities: Vec::new(),
            whitelist_markets: Vec::new(),
            blacklist_markets: Vec::new(),
            description: String::new(),
            extensions: Vec::new(),
        }
    }
}

/// Price structure for asset exchange rates
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Price {
    /// Base asset amount
    pub base: AssetAmount,
    /// Quote asset amount
    pub quote: AssetAmount,
}

/// Asset amount structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AssetAmount {
    /// Amount value
    pub amount: i64,
    /// Asset ID
    pub asset_id: ObjectId,
}

/// Special authority types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecialAuthority {
    /// No special authority
    NoSpecialAuthority,
    /// Top holders authority
    TopHolders {
        /// Number of top holders
        num_top_holders: u8,
        /// Asset ID
        asset: ObjectId,
    },
}

/// Extension type for future compatibility
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Extension {
    /// Extension type ID
    pub type_id: u8,
    /// Extension data
    pub data: Vec<u8>,
}

/// Transaction structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode, Default)]
pub struct Transaction {
    /// Reference block number
    pub ref_block_num: u16,
    /// Reference block prefix
    pub ref_block_prefix: u32,
    /// Expiration time
    pub expiration: u32,
    /// Operations in the transaction
    pub operations: Vec<Operation>,
    /// Extensions
    pub extensions: Vec<Extension>,
    /// Signatures
    pub signatures: Vec<String>,
}

/// Signed transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SignedTransaction {
    /// Base transaction
    pub transaction: Transaction,
    /// Transaction ID
    pub transaction_id: String,
}

/// Operation types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum Operation {
    /// Transfer operation
    Transfer {
        /// Fee
        fee: AssetAmount,
        /// From account
        from: ObjectId,
        /// To account
        to: ObjectId,
        /// Amount to transfer
        amount: AssetAmount,
        /// Memo
        memo: Option<Memo>,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Limit order create operation
    LimitOrderCreate {
        /// Fee
        fee: AssetAmount,
        /// Seller account
        seller: ObjectId,
        /// Amount to sell
        amount_to_sell: AssetAmount,
        /// Minimum to receive
        min_to_receive: AssetAmount,
        /// Expiration time
        expiration: u32,
        /// Fill or kill flag
        fill_or_kill: bool,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Limit order cancel operation
    LimitOrderCancel {
        /// Fee
        fee: AssetAmount,
        /// Fee paying account
        fee_paying_account: ObjectId,
        /// Order to cancel
        order: ObjectId,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Account create operation
    AccountCreate {
        /// Fee
        fee: AssetAmount,
        /// Registrar account
        registrar: ObjectId,
        /// Referrer account
        referrer: ObjectId,
        /// Referrer percent
        referrer_percent: u16,
        /// Account name
        name: String,
        /// Owner authority
        owner: Authority,
        /// Active authority
        active: Authority,
        /// Account options
        options: AccountOptions,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Account update operation
    AccountUpdate {
        /// Fee
        fee: AssetAmount,
        /// Account to update
        account: ObjectId,
        /// New owner authority
        owner: Option<Authority>,
        /// New active authority
        active: Option<Authority>,
        /// New account options
        new_options: Option<AccountOptions>,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Asset create operation
    AssetCreate {
        /// Fee
        fee: AssetAmount,
        /// Issuer account
        issuer: ObjectId,
        /// Asset symbol
        symbol: String,
        /// Asset precision
        precision: u8,
        /// Common options
        common_options: AssetOptions,
        /// Bitasset options
        bitasset_opts: Option<BitassetOptions>,
        /// Is prediction market
        is_prediction_market: bool,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Asset update operation
    AssetUpdate {
        /// Fee
        fee: AssetAmount,
        /// Issuer account
        issuer: ObjectId,
        /// Asset to update
        asset_to_update: ObjectId,
        /// New options
        new_options: Option<AssetOptions>,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Asset issue operation
    AssetIssue {
        /// Fee
        fee: AssetAmount,
        /// Issuer account
        issuer: ObjectId,
        /// Asset to issue
        asset_to_issue: AssetAmount,
        /// Issue to account
        issue_to_account: ObjectId,
        /// Extensions
        extensions: Vec<Extension>,
    },
    /// Custom operation
    Custom {
        /// Operation ID
        id: u16,
        /// Payer account
        payer: ObjectId,
        /// Required authorities
        required_auths: Vec<ObjectId>,
        /// Custom data
        data: Vec<u8>,
        /// Fee
        fee: AssetAmount,
        /// Extensions
        extensions: Vec<Extension>,
    },
}

/// Memo structure for encrypted messages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Memo {
    /// From public key
    pub from: String,
    /// To public key
    pub to: String,
    /// Nonce
    pub nonce: u64,
    /// Encrypted message
    pub message: Vec<u8>,
}

/// Bitasset options for market-pegged assets
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BitassetOptions {
    /// Feed lifetime in seconds
    pub feed_lifetime_sec: u32,
    /// Minimum number of feeds
    pub minimum_feeds: u8,
    /// Force settlement delay in seconds
    pub force_settlement_delay_sec: u32,
    /// Force settlement offset percent
    pub force_settlement_offset_percent: u16,
    /// Maximum force settlement volume percent
    pub maximum_force_settlement_volume: u16,
    /// Short backing asset
    pub short_backing_asset: ObjectId,
    /// Extensions
    pub extensions: Vec<Extension>,
}

impl Default for BitassetOptions {
    fn default() -> Self {
        Self {
            feed_lifetime_sec: 86400, // 24 hours
            minimum_feeds: 1,
            force_settlement_delay_sec: 86400, // 24 hours
            force_settlement_offset_percent: 0,
            maximum_force_settlement_volume: 2000, // 20%
            short_backing_asset: ObjectId::new(1, 3, 0).unwrap_or_default(),
            extensions: Vec::new(),
        }
    }
}

/// Block header structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockHeader {
    /// Previous block ID
    pub previous: String,
    /// Block timestamp
    pub timestamp: u32,
    /// Witness account ID
    pub witness: ObjectId,
    /// Transaction merkle root
    pub transaction_merkle_root: String,
    /// Extensions
    pub extensions: Vec<Extension>,
}

/// Full block structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Transactions in the block
    pub transactions: Vec<SignedTransaction>,
    /// Witness signature
    pub witness_signature: String,
}

/// Chain properties
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainProperties {
    /// Chain ID
    pub chain_id: String,
    /// Head block number
    pub head_block_number: u32,
    /// Head block ID
    pub head_block_id: String,
    /// Head block time
    pub head_block_time: u32,
    /// Next maintenance time
    pub next_maintenance_time: u32,
    /// Last budget time
    pub last_budget_time: u32,
    /// Witness budget
    pub witness_budget: i64,
    /// Accounts registered this interval
    pub accounts_registered_this_interval: u32,
    /// Recently missed count
    pub recently_missed_count: u32,
    /// Current aslot
    pub current_aslot: u64,
    /// Recent slots filled
    pub recent_slots_filled: String,
    /// Dynamic flags
    pub dynamic_flags: u32,
    /// Last irreversible block number
    pub last_irreversible_block_num: u32,
}

/// Global properties
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalProperties {
    /// ID
    pub id: ObjectId,
    /// Parameters
    pub parameters: ChainParameters,
    /// Next available vote ID
    pub next_available_vote_id: u32,
    /// Active committee members
    pub active_committee_members: Vec<ObjectId>,
    /// Active witnesses
    pub active_witnesses: Vec<ObjectId>,
}

/// Chain parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainParameters {
    /// Current fees
    pub current_fees: FeeSchedule,
    /// Block interval in seconds
    pub block_interval: u8,
    /// Maintenance interval in seconds
    pub maintenance_interval: u32,
    /// Maintenance skip slots
    pub maintenance_skip_slots: u8,
    /// Committee proposal review period
    pub committee_proposal_review_period: u32,
    /// Maximum transaction size
    pub maximum_transaction_size: u32,
    /// Maximum block size
    pub maximum_block_size: u32,
    /// Maximum time until expiration
    pub maximum_time_until_expiration: u32,
    /// Maximum proposal lifetime
    pub maximum_proposal_lifetime: u32,
    /// Maximum asset whitelist authorities
    pub maximum_asset_whitelist_authorities: u8,
    /// Maximum asset feed publishers
    pub maximum_asset_feed_publishers: u8,
    /// Maximum witness count
    pub maximum_witness_count: u16,
    /// Maximum committee count
    pub maximum_committee_count: u16,
    /// Maximum authority membership
    pub maximum_authority_membership: u16,
    /// Reserve percent of fee
    pub reserve_percent_of_fee: u16,
    /// Network percent of fee
    pub network_percent_of_fee: u16,
    /// Lifetime referrer percent of fee
    pub lifetime_referrer_percent_of_fee: u16,
    /// Cashback vesting period in seconds
    pub cashback_vesting_period_seconds: u32,
    /// Cashback vesting threshold
    pub cashback_vesting_threshold: i64,
    /// Count non-member votes
    pub count_non_member_votes: bool,
    /// Allow non-member whitelists
    pub allow_non_member_whitelists: bool,
    /// Witness pay per block
    pub witness_pay_per_block: i64,
    /// Worker budget per day
    pub worker_budget_per_day: i64,
    /// Maximum predicate opcode
    pub max_predicate_opcode: u16,
    /// Fee liquidation threshold
    pub fee_liquidation_threshold: i64,
    /// Accounts per fee scale
    pub accounts_per_fee_scale: u16,
    /// Account fee scale bitshifts
    pub account_fee_scale_bitshifts: u8,
    /// Maximum authority depth
    pub max_authority_depth: u8,
    /// Extensions
    pub extensions: Vec<Extension>,
}

/// Fee schedule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Parameters for different operation types
    pub parameters: Vec<FeeParameters>,
    /// Scale factor
    pub scale: u32,
}

/// Fee parameters for operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeParameters {
    /// Operation type
    pub operation_type: u8,
    /// Fee structure
    pub fee: Fee,
}

/// Fee structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fee {
    /// Basic fee
    pub fee: u64,
    /// Price per kilobyte
    pub price_per_kbyte: u32,
}

/// Chain types utility struct
pub struct ChainTypes;

impl ChainTypes {
    /// Get operation type ID
    pub fn get_operation_type_id(operation: &Operation) -> u8 {
        match operation {
            Operation::Transfer { .. } => 0,
            Operation::LimitOrderCreate { .. } => 1,
            Operation::LimitOrderCancel { .. } => 2,
            Operation::AccountCreate { .. } => 5,
            Operation::AccountUpdate { .. } => 6,
            Operation::AssetCreate { .. } => 10,
            Operation::AssetUpdate { .. } => 11,
            Operation::AssetIssue { .. } => 12,
            Operation::Custom { .. } => 35,
        }
    }

    /// Create default authority
    pub fn create_default_authority(key: &str, weight: u16) -> Authority {
        let mut key_auths = HashMap::new();
        key_auths.insert(key.to_string(), weight);

        Authority {
            weight_threshold: weight as u32,
            account_auths: HashMap::new(),
            key_auths,
            address_auths: HashMap::new(),
        }
    }

    /// Create asset amount
    pub fn create_asset_amount(amount: i64, asset_id: ObjectId) -> AssetAmount {
        AssetAmount { amount, asset_id }
    }

    /// Create price from amounts
    pub fn create_price(base: AssetAmount, quote: AssetAmount) -> Price {
        Price { base, quote }
    }

    /// Validate account name
    pub fn validate_account_name(name: &str) -> ChainResult<()> {
        if name.is_empty() {
            return Err(ChainError::ValidationError {
                field: "name".to_string(),
                reason: "Account name cannot be empty".to_string(),
            });
        }

        if name.len() > 63 {
            return Err(ChainError::ValidationError {
                field: "name".to_string(),
                reason: "Account name too long".to_string(),
            });
        }

        // Check for valid characters (lowercase letters, numbers, hyphens)
        for c in name.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                return Err(ChainError::ValidationError {
                    field: "name".to_string(),
                    reason: "Invalid character in account name".to_string(),
                });
            }
        }

        // Cannot start or end with hyphen
        if name.starts_with('-') || name.ends_with('-') {
            return Err(ChainError::ValidationError {
                field: "name".to_string(),
                reason: "Account name cannot start or end with hyphen".to_string(),
            });
        }

        // Cannot be purely numeric
        if name.chars().all(|c| c.is_ascii_digit()) {
            return Err(ChainError::ValidationError {
                field: "name".to_string(),
                reason: "Account name cannot be purely numeric".to_string(),
            });
        }

        Ok(())
    }

    /// Validate asset symbol
    pub fn validate_asset_symbol(symbol: &str) -> ChainResult<()> {
        if symbol.is_empty() {
            return Err(ChainError::ValidationError {
                field: "symbol".to_string(),
                reason: "Asset symbol cannot be empty".to_string(),
            });
        }

        if symbol.len() > 16 {
            return Err(ChainError::ValidationError {
                field: "symbol".to_string(),
                reason: "Asset symbol too long".to_string(),
            });
        }

        // Check for valid characters (uppercase letters, numbers, dots)
        for c in symbol.chars() {
            if !c.is_ascii_uppercase() && !c.is_ascii_digit() && c != '.' {
                return Err(ChainError::ValidationError {
                    field: "symbol".to_string(),
                    reason: "Invalid character in asset symbol".to_string(),
                });
            }
        }

        // Cannot be purely numeric
        if symbol.chars().all(|c| c.is_ascii_digit()) {
            return Err(ChainError::ValidationError {
                field: "symbol".to_string(),
                reason: "Asset symbol cannot be purely numeric".to_string(),
            });
        }

        // Cannot start or end with dot
        if symbol.starts_with('.') || symbol.ends_with('.') {
            return Err(ChainError::ValidationError {
                field: "symbol".to_string(),
                reason: "Asset symbol cannot start or end with dot".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_type_id() {
        let transfer_op = Operation::Transfer {
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
        };

        assert_eq!(ChainTypes::get_operation_type_id(&transfer_op), 0);
    }

    #[test]
    fn test_create_default_authority() {
        let auth = ChainTypes::create_default_authority("RSQ6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV", 1);
        assert_eq!(auth.weight_threshold, 1);
        assert_eq!(auth.key_auths.len(), 1);
    }

    #[test]
    fn test_validate_account_name() {
        assert!(ChainTypes::validate_account_name("alice").is_ok());
        assert!(ChainTypes::validate_account_name("bob-123").is_ok());
        assert!(ChainTypes::validate_account_name("").is_err());
        assert!(ChainTypes::validate_account_name("Alice").is_err());
        assert!(ChainTypes::validate_account_name("-alice").is_err());
        assert!(ChainTypes::validate_account_name("alice-").is_err());
    }

    #[test]
    fn test_validate_asset_symbol() {
        assert!(ChainTypes::validate_asset_symbol("BTC").is_ok());
        assert!(ChainTypes::validate_asset_symbol("USD.COIN").is_ok());
        assert!(ChainTypes::validate_asset_symbol("").is_err());
        assert!(ChainTypes::validate_asset_symbol("btc").is_err());
        assert!(ChainTypes::validate_asset_symbol("BTC-USD").is_err());
    }

    #[test]
    fn test_asset_amount_creation() {
        let asset_id = ObjectId::new(1, 3, 0).unwrap();
        let amount = ChainTypes::create_asset_amount(10000, asset_id.clone());
        assert_eq!(amount.amount, 10000);
        assert_eq!(amount.asset_id, asset_id);
    }

    #[test]
    fn test_price_creation() {
        let base_asset = ObjectId::new(1, 3, 0).unwrap();
        let quote_asset = ObjectId::new(1, 3, 1).unwrap();
        
        let base = ChainTypes::create_asset_amount(100, base_asset);
        let quote = ChainTypes::create_asset_amount(200, quote_asset);
        
        let price = ChainTypes::create_price(base.clone(), quote.clone());
        assert_eq!(price.base, base);
        assert_eq!(price.quote, quote);
    }
}