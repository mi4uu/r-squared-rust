//! Chain store implementation for blockchain state management
//!
//! This module provides functionality for managing blockchain state,
//! caching objects, and integrating with blockchain APIs.

use crate::chain::{
    chain_types::*,
    ObjectId,
};
use crate::error::{ChainError, ChainResult};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::fmt;

/// Cache entry with expiration time
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    data: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(data: T, ttl: Duration) -> Self {
        Self {
            data,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Chain store configuration
#[derive(Debug, Clone)]
pub struct ChainStoreConfig {
    /// API endpoint URL
    pub api_url: String,
    /// Cache TTL for objects
    pub cache_ttl: Duration,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Request timeout
    pub request_timeout: Duration,
    /// Auto-subscribe to updates
    pub auto_subscribe: bool,
}

impl Default for ChainStoreConfig {
    fn default() -> Self {
        Self {
            api_url: "wss://api.r-squared.network".to_string(),
            cache_ttl: Duration::from_secs(300), // 5 minutes
            max_cache_size: 10000,
            request_timeout: Duration::from_secs(30),
            auto_subscribe: true,
        }
    }
}

/// Chain store for managing blockchain state
pub struct ChainStore {
    /// Configuration
    pub config: ChainStoreConfig,
    /// Account cache
    accounts: Arc<RwLock<HashMap<ObjectId, CacheEntry<Account>>>>,
    /// Asset cache
    assets: Arc<RwLock<HashMap<ObjectId, CacheEntry<Asset>>>>,
    /// Object cache (generic)
    objects: Arc<RwLock<HashMap<ObjectId, CacheEntry<serde_json::Value>>>>,
    /// Global properties cache
    global_properties: Arc<RwLock<Option<CacheEntry<GlobalProperties>>>>,
    /// Chain properties cache
    chain_properties: Arc<RwLock<Option<CacheEntry<ChainProperties>>>>,
    /// Fee schedule cache
    fee_schedule: Arc<RwLock<Option<CacheEntry<FeeSchedule>>>>,
    /// Block cache
    blocks: Arc<RwLock<HashMap<u32, CacheEntry<Block>>>>,
    /// Transaction cache
    transactions: Arc<RwLock<HashMap<String, CacheEntry<SignedTransaction>>>>,
    /// Subscription callbacks
    subscriptions: Arc<RwLock<HashMap<String, Box<dyn Fn(serde_json::Value) + Send + Sync>>>>,
}

impl ChainStore {
    /// Create a new chain store with default configuration
    pub fn new() -> Self {
        Self::with_config(ChainStoreConfig::default())
    }

    /// Create a new chain store with custom configuration
    pub fn with_config(config: ChainStoreConfig) -> Self {
        Self {
            config,
            accounts: Arc::new(RwLock::new(HashMap::new())),
            assets: Arc::new(RwLock::new(HashMap::new())),
            objects: Arc::new(RwLock::new(HashMap::new())),
            global_properties: Arc::new(RwLock::new(None)),
            chain_properties: Arc::new(RwLock::new(None)),
            fee_schedule: Arc::new(RwLock::new(None)),
            blocks: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get account by ID
    pub async fn get_account(&self, account_id: &ObjectId) -> ChainResult<Account> {
        // Check cache first
        if let Some(account) = self.get_cached_account(account_id) {
            return Ok(account);
        }

        // Fetch from API
        let account = self.fetch_account_from_api(account_id).await?;
        
        // Cache the result
        self.cache_account(account_id.clone(), account.clone());
        
        Ok(account)
    }

    /// Get account by name
    pub async fn get_account_by_name(&self, name: &str) -> ChainResult<Account> {
        // First try to find in cache
        let accounts = self.accounts.read().unwrap();
        for (_, entry) in accounts.iter() {
            if !entry.is_expired() && entry.data.name == name {
                return Ok(entry.data.clone());
            }
        }
        drop(accounts);

        // Fetch from API
        let account = self.fetch_account_by_name_from_api(name).await?;
        
        // Cache the result
        self.cache_account(account.id.clone(), account.clone());
        
        Ok(account)
    }

    /// Get asset by ID
    pub async fn get_asset(&self, asset_id: &ObjectId) -> ChainResult<Asset> {
        // Check cache first
        if let Some(asset) = self.get_cached_asset(asset_id) {
            return Ok(asset);
        }

        // Fetch from API
        let asset = self.fetch_asset_from_api(asset_id).await?;
        
        // Cache the result
        self.cache_asset(asset_id.clone(), asset.clone());
        
        Ok(asset)
    }

    /// Get asset by symbol
    pub async fn get_asset_by_symbol(&self, symbol: &str) -> ChainResult<Asset> {
        // First try to find in cache
        let assets = self.assets.read().unwrap();
        for (_, entry) in assets.iter() {
            if !entry.is_expired() && entry.data.symbol == symbol {
                return Ok(entry.data.clone());
            }
        }
        drop(assets);

        // Fetch from API
        let asset = self.fetch_asset_by_symbol_from_api(symbol).await?;
        
        // Cache the result
        self.cache_asset(asset.id.clone(), asset.clone());
        
        Ok(asset)
    }

    /// Get multiple objects by IDs
    pub async fn get_objects(&self, object_ids: &[ObjectId]) -> ChainResult<Vec<serde_json::Value>> {
        let mut results = Vec::new();
        let mut missing_ids = Vec::new();

        // Check cache for each object
        for object_id in object_ids {
            if let Some(object) = self.get_cached_object(object_id) {
                results.push(object);
            } else {
                missing_ids.push(object_id.clone());
            }
        }

        // Fetch missing objects from API
        if !missing_ids.is_empty() {
            let fetched_objects = self.fetch_objects_from_api(&missing_ids).await?;
            
            // Cache and add to results
            for (i, object) in fetched_objects.into_iter().enumerate() {
                self.cache_object(missing_ids[i].clone(), object.clone());
                results.push(object);
            }
        }

        Ok(results)
    }

    /// Get global properties
    pub async fn get_global_properties(&self) -> ChainResult<GlobalProperties> {
        // Check cache first
        if let Some(props) = self.get_cached_global_properties() {
            return Ok(props);
        }

        // Fetch from API
        let props = self.fetch_global_properties_from_api().await?;
        
        // Cache the result
        self.cache_global_properties(props.clone());
        
        Ok(props)
    }

    /// Get chain properties
    pub async fn get_chain_properties(&self) -> ChainResult<ChainProperties> {
        // Check cache first
        if let Some(props) = self.get_cached_chain_properties() {
            return Ok(props);
        }

        // Fetch from API
        let props = self.fetch_chain_properties_from_api().await?;
        
        // Cache the result
        self.cache_chain_properties(props.clone());
        
        Ok(props)
    }

    /// Get fee schedule
    pub async fn get_fee_schedule(&self) -> ChainResult<FeeSchedule> {
        // Check cache first
        if let Some(schedule) = self.get_cached_fee_schedule() {
            return Ok(schedule);
        }

        // Fetch from API
        let schedule = self.fetch_fee_schedule_from_api().await?;
        
        // Cache the result
        self.cache_fee_schedule(schedule.clone());
        
        Ok(schedule)
    }

    /// Get block by number
    pub async fn get_block(&self, block_num: u32) -> ChainResult<Block> {
        // Check cache first
        if let Some(block) = self.get_cached_block(block_num) {
            return Ok(block);
        }

        // Fetch from API
        let block = self.fetch_block_from_api(block_num).await?;
        
        // Cache the result
        self.cache_block(block_num, block.clone());
        
        Ok(block)
    }

    /// Get transaction by ID
    pub async fn get_transaction(&self, tx_id: &str) -> ChainResult<SignedTransaction> {
        // Check cache first
        if let Some(tx) = self.get_cached_transaction(tx_id) {
            return Ok(tx);
        }

        // Fetch from API
        let tx = self.fetch_transaction_from_api(tx_id).await?;
        
        // Cache the result
        self.cache_transaction(tx_id.to_string(), tx.clone());
        
        Ok(tx)
    }

    /// Subscribe to object updates
    pub fn subscribe_to_object<F>(&self, object_id: ObjectId, callback: F) -> ChainResult<String>
    where
        F: Fn(serde_json::Value) + Send + Sync + 'static,
    {
        let subscription_id = format!("object_{}", object_id);
        
        let mut subscriptions = self.subscriptions.write().unwrap();
        subscriptions.insert(subscription_id.clone(), Box::new(callback));
        
        // TODO: Implement actual WebSocket subscription to API
        
        Ok(subscription_id)
    }

    /// Unsubscribe from updates
    pub fn unsubscribe(&self, subscription_id: &str) -> ChainResult<()> {
        let mut subscriptions = self.subscriptions.write().unwrap();
        subscriptions.remove(subscription_id);
        
        // TODO: Implement actual WebSocket unsubscription
        
        Ok(())
    }

    /// Clear all caches
    pub fn clear_cache(&self) {
        self.accounts.write().unwrap().clear();
        self.assets.write().unwrap().clear();
        self.objects.write().unwrap().clear();
        *self.global_properties.write().unwrap() = None;
        *self.chain_properties.write().unwrap() = None;
        *self.fee_schedule.write().unwrap() = None;
        self.blocks.write().unwrap().clear();
        self.transactions.write().unwrap().clear();
    }

    /// Clear expired cache entries
    pub fn clear_expired_cache(&self) {
        // Clear expired accounts
        let mut accounts = self.accounts.write().unwrap();
        accounts.retain(|_, entry| !entry.is_expired());
        
        // Clear expired assets
        let mut assets = self.assets.write().unwrap();
        assets.retain(|_, entry| !entry.is_expired());
        
        // Clear expired objects
        let mut objects = self.objects.write().unwrap();
        objects.retain(|_, entry| !entry.is_expired());
        
        // Clear expired blocks
        let mut blocks = self.blocks.write().unwrap();
        blocks.retain(|_, entry| !entry.is_expired());
        
        // Clear expired transactions
        let mut transactions = self.transactions.write().unwrap();
        transactions.retain(|_, entry| !entry.is_expired());
        
        // Check global properties
        if let Some(ref entry) = *self.global_properties.read().unwrap() {
            if entry.is_expired() {
                *self.global_properties.write().unwrap() = None;
            }
        }
        
        // Check chain properties
        if let Some(ref entry) = *self.chain_properties.read().unwrap() {
            if entry.is_expired() {
                *self.chain_properties.write().unwrap() = None;
            }
        }
        
        // Check fee schedule
        if let Some(ref entry) = *self.fee_schedule.read().unwrap() {
            if entry.is_expired() {
                *self.fee_schedule.write().unwrap() = None;
            }
        }
    }

    // Cache helper methods
    fn get_cached_account(&self, account_id: &ObjectId) -> Option<Account> {
        let accounts = self.accounts.read().unwrap();
        accounts.get(account_id)
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_account(&self, account_id: ObjectId, account: Account) {
        let mut accounts = self.accounts.write().unwrap();
        accounts.insert(account_id, CacheEntry::new(account, self.config.cache_ttl));
        
        // Enforce cache size limit
        if accounts.len() > self.config.max_cache_size {
            // Remove oldest entries (simple LRU approximation)
            let keys_to_remove: Vec<_> = accounts.keys().take(accounts.len() - self.config.max_cache_size).cloned().collect();
            for key in keys_to_remove {
                accounts.remove(&key);
            }
        }
    }

    fn get_cached_asset(&self, asset_id: &ObjectId) -> Option<Asset> {
        let assets = self.assets.read().unwrap();
        assets.get(asset_id)
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_asset(&self, asset_id: ObjectId, asset: Asset) {
        let mut assets = self.assets.write().unwrap();
        assets.insert(asset_id, CacheEntry::new(asset, self.config.cache_ttl));
        
        // Enforce cache size limit
        if assets.len() > self.config.max_cache_size {
            let keys_to_remove: Vec<_> = assets.keys().take(assets.len() - self.config.max_cache_size).cloned().collect();
            for key in keys_to_remove {
                assets.remove(&key);
            }
        }
    }

    fn get_cached_object(&self, object_id: &ObjectId) -> Option<serde_json::Value> {
        let objects = self.objects.read().unwrap();
        objects.get(object_id)
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_object(&self, object_id: ObjectId, object: serde_json::Value) {
        let mut objects = self.objects.write().unwrap();
        objects.insert(object_id, CacheEntry::new(object, self.config.cache_ttl));
        
        // Enforce cache size limit
        if objects.len() > self.config.max_cache_size {
            let keys_to_remove: Vec<_> = objects.keys().take(objects.len() - self.config.max_cache_size).cloned().collect();
            for key in keys_to_remove {
                objects.remove(&key);
            }
        }
    }

    fn get_cached_global_properties(&self) -> Option<GlobalProperties> {
        self.global_properties.read().unwrap()
            .as_ref()
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_global_properties(&self, props: GlobalProperties) {
        *self.global_properties.write().unwrap() = Some(CacheEntry::new(props, self.config.cache_ttl));
    }

    fn get_cached_chain_properties(&self) -> Option<ChainProperties> {
        self.chain_properties.read().unwrap()
            .as_ref()
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_chain_properties(&self, props: ChainProperties) {
        *self.chain_properties.write().unwrap() = Some(CacheEntry::new(props, self.config.cache_ttl));
    }

    fn get_cached_fee_schedule(&self) -> Option<FeeSchedule> {
        self.fee_schedule.read().unwrap()
            .as_ref()
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_fee_schedule(&self, schedule: FeeSchedule) {
        *self.fee_schedule.write().unwrap() = Some(CacheEntry::new(schedule, self.config.cache_ttl));
    }

    fn get_cached_block(&self, block_num: u32) -> Option<Block> {
        let blocks = self.blocks.read().unwrap();
        blocks.get(&block_num)
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_block(&self, block_num: u32, block: Block) {
        let mut blocks = self.blocks.write().unwrap();
        blocks.insert(block_num, CacheEntry::new(block, self.config.cache_ttl));
        
        // Enforce cache size limit
        if blocks.len() > self.config.max_cache_size {
            let keys_to_remove: Vec<_> = blocks.keys().take(blocks.len() - self.config.max_cache_size).cloned().collect();
            for key in keys_to_remove {
                blocks.remove(&key);
            }
        }
    }

    fn get_cached_transaction(&self, tx_id: &str) -> Option<SignedTransaction> {
        let transactions = self.transactions.read().unwrap();
        transactions.get(tx_id)
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.data.clone())
    }

    fn cache_transaction(&self, tx_id: String, tx: SignedTransaction) {
        let mut transactions = self.transactions.write().unwrap();
        transactions.insert(tx_id, CacheEntry::new(tx, self.config.cache_ttl));
        
        // Enforce cache size limit
        if transactions.len() > self.config.max_cache_size {
            let keys_to_remove: Vec<_> = transactions.keys().take(transactions.len() - self.config.max_cache_size).cloned().collect();
            for key in keys_to_remove {
                transactions.remove(&key);
            }
        }
    }

    // API fetch methods (placeholder implementations)
    async fn fetch_account_from_api(&self, _account_id: &ObjectId) -> ChainResult<Account> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_account_by_name_from_api(&self, _name: &str) -> ChainResult<Account> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_asset_from_api(&self, _asset_id: &ObjectId) -> ChainResult<Asset> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_asset_by_symbol_from_api(&self, _symbol: &str) -> ChainResult<Asset> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_objects_from_api(&self, _object_ids: &[ObjectId]) -> ChainResult<Vec<serde_json::Value>> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_global_properties_from_api(&self) -> ChainResult<GlobalProperties> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_chain_properties_from_api(&self) -> ChainResult<ChainProperties> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_fee_schedule_from_api(&self) -> ChainResult<FeeSchedule> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_block_from_api(&self, _block_num: u32) -> ChainResult<Block> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }

    async fn fetch_transaction_from_api(&self, _tx_id: &str) -> ChainResult<SignedTransaction> {
        // TODO: Implement actual API call
        Err(ChainError::ChainStateError {
            reason: "API not implemented".to_string(),
        })
    }
}

impl Default for ChainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ChainStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainStore")
            .field("config", &self.config)
            .field("accounts_count", &self.accounts.read().unwrap().len())
            .field("assets_count", &self.assets.read().unwrap().len())
            .field("objects_count", &self.objects.read().unwrap().len())
            .field("blocks_count", &self.blocks.read().unwrap().len())
            .field("transactions_count", &self.transactions.read().unwrap().len())
            .field("subscriptions_count", &self.subscriptions.read().unwrap().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_chain_store_creation() {
        let store = ChainStore::new();
        // Basic creation test - store should be created successfully
        assert_eq!(store.config.api_url, "wss://api.r-squared.network");
    }

    #[test]
    fn test_chain_store_with_config() {
        let config = ChainStoreConfig {
            api_url: "wss://custom.api.url".to_string(),
            cache_ttl: Duration::from_secs(600),
            max_cache_size: 5000,
            request_timeout: Duration::from_secs(60),
            auto_subscribe: false,
        };
        
        let store = ChainStore::with_config(config.clone());
        assert_eq!(store.config.api_url, config.api_url);
        assert_eq!(store.config.cache_ttl, config.cache_ttl);
        assert_eq!(store.config.max_cache_size, config.max_cache_size);
    }

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry::new("test_data".to_string(), Duration::from_millis(1));
        assert!(!entry.is_expired());
        
        std::thread::sleep(Duration::from_millis(2));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_clear_cache() {
        let store = ChainStore::new();
        
        // Add some test data to cache
        let account_id = ObjectId::new(1, 2, 1).unwrap();
        let test_account = Account {
            id: account_id.clone(),
            name: "test".to_string(),
            owner: Authority {
                weight_threshold: 1,
                account_auths: HashMap::new(),
                key_auths: HashMap::new(),
                address_auths: HashMap::new(),
            },
            active: Authority {
                weight_threshold: 1,
                account_auths: HashMap::new(),
                key_auths: HashMap::new(),
                address_auths: HashMap::new(),
            },
            options: AccountOptions {
                memo_key: "test_key".to_string(),
                voting_account: ObjectId::new(1, 2, 0).unwrap(),
                num_witness: 0,
                num_committee: 0,
                votes: vec![],
                extensions: vec![],
            },
            statistics: ObjectId::new(2, 6, 1).unwrap(),
            whitelisting_accounts: vec![],
            blacklisting_accounts: vec![],
            whitelisted_assets: vec![],
            blacklisted_assets: vec![],
            owner_special_authority: None,
            active_special_authority: None,
            top_n_control_flags: 0,
        };
        
        store.cache_account(account_id.clone(), test_account);
        
        // Verify cache has data
        assert!(store.get_cached_account(&account_id).is_some());
        
        // Clear cache
        store.clear_cache();
        
        // Verify cache is empty
        assert!(store.get_cached_account(&account_id).is_none());
    }

    #[test]
    fn test_subscription_management() {
        let store = ChainStore::new();
        let object_id = ObjectId::new(1, 2, 1).unwrap();
        
        let subscription_id = store.subscribe_to_object(object_id, |_| {
            // Test callback
        }).unwrap();
        
        assert!(subscription_id.starts_with("object_"));
        
        // Test unsubscribe
        assert!(store.unsubscribe(&subscription_id).is_ok());
    }
}