//! Storage module for data persistence
//!
//! This module provides a unified storage interface with multiple backend implementations:
//! - **Local filesystem storage** - For local file operations
//! - **AWS S3 storage** - For cloud object storage (optional, requires `s3` feature)
//! - **IPFS storage** - For distributed content-addressed storage (optional, requires `ipfs` feature)
//!
//! The storage module follows a trait-based design allowing for pluggable backends
//! and consistent API across different storage types.
//!
//! # Features
//!
//! - Unified storage API with both sync and async support
//! - Multiple storage backends with feature-gated compilation
//! - Batch operations for efficiency
//! - Metadata support and content type detection
//! - Atomic operations and retry logic
//! - Comprehensive error handling
//!
//! # Examples
//!
//! ## Local Storage
//!
//! ```rust
//! use r_squared_rust::storage::{LocalStorage, LocalConfig, StorageConfig, StorageApiSync};
//! use bytes::Bytes;
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let local_config = LocalConfig {
//!     base_path: PathBuf::from("./my_storage"),
//!     ..Default::default()
//! };
//! let storage_config = StorageConfig::default();
//! let storage = LocalStorage::new(local_config, storage_config)?;
//!
//! // Store data
//! storage.put("my_file.txt", Bytes::from("Hello, World!"))?;
//!
//! // Retrieve data
//! let data = storage.get("my_file.txt")?;
//! assert_eq!(data, Bytes::from("Hello, World!"));
//!
//! // Check existence
//! assert!(storage.exists("my_file.txt")?);
//!
//! // Delete data
//! storage.delete("my_file.txt")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## S3 Storage (requires `s3` feature)
//!
//! ```rust,ignore
//! use r_squared_rust::storage::{S3Storage, S3Config, StorageConfig, StorageApi};
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let s3_config = S3Config {
//!         bucket: "my-bucket".to_string(),
//!         region: "us-east-1".to_string(),
//!         ..Default::default()
//!     };
//!     let storage_config = StorageConfig::default();
//!     let storage = S3Storage::new(s3_config, storage_config).await?;
//!
//!     // Store data
//!     storage.put("my_file.txt", Bytes::from("Hello, S3!")).await?;
//!
//!     // Retrieve data
//!     let data = storage.get("my_file.txt").await?;
//!     assert_eq!(data, Bytes::from("Hello, S3!"));
//!
//!     Ok(())
//! }
//! ```

// Core storage API and types
pub mod storage_api;

// Storage backend implementations
pub mod storage_local;

#[cfg(feature = "s3")]
pub mod storage_s3;

#[cfg(feature = "ipfs")]
pub mod storage_ipfs;

// Re-export main types for convenience
pub use storage_api::{
    StorageApi, StorageApiSync, StorageConfig, StorageMetadata, StorageBackend,
    StorageManager, BatchOperation, BatchResult, BatchOperationType,
};

pub use storage_local::{LocalStorage, LocalConfig};

#[cfg(feature = "s3")]
pub use storage_s3::{S3Storage, S3Config, PresignedUrlMethod, S3ListResult};

#[cfg(feature = "ipfs")]
pub use storage_ipfs::{IpfsStorage, IpfsConfig, IpfsContent, PinStatus};

use crate::error::{StorageError, StorageResult};

/// Storage constants
pub mod constants {
    //! Constants used throughout the storage module
    
    /// Maximum storage key length
    pub const MAX_KEY_LENGTH: usize = 1024;
    
    /// Maximum storage value size (1GB)
    pub const MAX_VALUE_SIZE: usize = 1024 * 1024 * 1024;
    
    /// Default timeout for storage operations in seconds
    pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
    
    /// Default retry attempts
    pub const DEFAULT_MAX_RETRIES: u32 = 3;
    
    /// Default buffer size for streaming operations
    pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024; // 64KB
}

/// Storage factory for creating storage instances
pub struct StorageFactory;

impl StorageFactory {
    /// Create a local storage instance
    pub fn create_local(
        local_config: LocalConfig,
        storage_config: StorageConfig,
    ) -> StorageResult<LocalStorage> {
        LocalStorage::new(local_config, storage_config)
    }
    
    /// Create an S3 storage instance (requires `s3` feature)
    #[cfg(feature = "s3")]
    pub async fn create_s3(
        s3_config: S3Config,
        storage_config: StorageConfig,
    ) -> StorageResult<S3Storage> {
        S3Storage::new(s3_config, storage_config).await
    }
    
    /// Create an IPFS storage instance (requires `ipfs` feature)
    #[cfg(feature = "ipfs")]
    pub async fn create_ipfs(
        ipfs_config: IpfsConfig,
        storage_config: StorageConfig,
    ) -> StorageResult<IpfsStorage> {
        IpfsStorage::new(ipfs_config, storage_config).await
    }
    
    /// Create storage from URL (convenience method)
    pub async fn from_url(url: &str) -> StorageResult<Box<dyn StorageApiSync + Send + Sync>> {
        let storage_config = StorageConfig::default();
        
        if url.starts_with("file://") || url.starts_with("./") || url.starts_with("/") {
            // Local filesystem
            let path = if url.starts_with("file://") {
                url.strip_prefix("file://").unwrap()
            } else {
                url
            };
            
            let local_config = LocalConfig {
                base_path: std::path::PathBuf::from(path),
                ..Default::default()
            };
            
            let storage = LocalStorage::new(local_config, storage_config)?;
            Ok(Box::new(storage))
        } else if url.starts_with("s3://") {
            #[cfg(feature = "s3")]
            {
                // Parse S3 URL: s3://bucket/path
                let url_parts: Vec<&str> = url.strip_prefix("s3://").unwrap().split('/').collect();
                if url_parts.is_empty() {
                    return Err(StorageError::OperationFailed {
                        operation: "parse_s3_url".to_string(),
                        reason: "Invalid S3 URL format".to_string(),
                    });
                }
                
                let s3_config = S3Config {
                    bucket: url_parts[0].to_string(),
                    ..Default::default()
                };
                
                let storage = S3Storage::new(s3_config, storage_config).await?;
                Ok(Box::new(storage) as Box<dyn StorageApiSync + Send + Sync>)
            }
            #[cfg(not(feature = "s3"))]
            {
                Err(StorageError::BackendNotAvailable {
                    backend: "S3".to_string(),
                })
            }
        } else if url.starts_with("ipfs://") {
            #[cfg(feature = "ipfs")]
            {
                let ipfs_config = IpfsConfig::default();
                let storage = IpfsStorage::new(ipfs_config, storage_config).await?;
                Ok(Box::new(storage) as Box<dyn StorageApiSync + Send + Sync>)
            }
            #[cfg(not(feature = "ipfs"))]
            {
                Err(StorageError::BackendNotAvailable {
                    backend: "IPFS".to_string(),
                })
            }
        } else {
            Err(StorageError::OperationFailed {
                operation: "parse_storage_url".to_string(),
                reason: format!("Unsupported storage URL: {}", url),
            })
        }
    }
}

/// High-level storage utilities
pub mod utils {
    use super::*;
    use bytes::Bytes;
    
    /// Copy data between different storage backends
    pub async fn copy_between_storages<S1, S2>(
        source: &S1,
        source_key: &str,
        destination: &S2,
        dest_key: &str,
    ) -> StorageResult<()>
    where
        S1: StorageApiSync,
        S2: StorageApiSync,
    {
        let data = source.get(source_key)?;
        destination.put(dest_key, data)?;
        Ok(())
    }
    
    /// Sync data from one storage to another (one-way sync)
    pub async fn sync_storage<S1, S2>(
        source: &S1,
        destination: &S2,
        prefix: &str,
    ) -> StorageResult<Vec<String>>
    where
        S1: StorageApiSync,
        S2: StorageApiSync,
    {
        let mut synced_keys = Vec::new();
        let keys = source.list(prefix)?;
        
        for key in keys {
            if let Ok(data) = source.get(&key) {
                destination.put(&key, data)?;
                synced_keys.push(key);
            }
        }
        
        Ok(synced_keys)
    }
    
    /// Calculate storage usage for a prefix
    pub fn calculate_storage_usage<S>(
        storage: &S,
        prefix: &str,
    ) -> StorageResult<u64>
    where
        S: StorageApiSync,
    {
        let keys = storage.list(prefix)?;
        let mut total_size = 0;
        
        for key in keys {
            if let Ok(metadata) = storage.head(&key) {
                total_size += metadata.content_length;
            }
        }
        
        Ok(total_size)
    }
    
    /// Validate storage key format
    pub fn validate_storage_key(key: &str) -> StorageResult<()> {
        storage_api::utils::validate_key(key)
    }
    
    /// Generate a unique storage key with timestamp
    pub fn generate_unique_key(prefix: &str, extension: Option<&str>) -> String {
        storage_api::utils::generate_key(prefix, extension)
    }
    
    /// Compress data before storage (simple implementation)
    pub fn compress_data(data: &[u8]) -> StorageResult<Bytes> {
        // Simple run-length encoding for demonstration
        // In practice, you'd use a proper compression library like flate2
        let mut compressed = Vec::new();
        let mut current_byte = data[0];
        let mut count = 1u8;
        
        for &byte in &data[1..] {
            if byte == current_byte && count < 255 {
                count += 1;
            } else {
                compressed.push(count);
                compressed.push(current_byte);
                current_byte = byte;
                count = 1;
            }
        }
        
        // Add the last run
        compressed.push(count);
        compressed.push(current_byte);
        
        Ok(Bytes::from(compressed))
    }
    
    /// Decompress data after retrieval
    pub fn decompress_data(compressed: &[u8]) -> StorageResult<Bytes> {
        let mut decompressed = Vec::new();
        
        for chunk in compressed.chunks(2) {
            if chunk.len() == 2 {
                let count = chunk[0];
                let byte = chunk[1];
                for _ in 0..count {
                    decompressed.push(byte);
                }
            }
        }
        
        Ok(Bytes::from(decompressed))
    }
}

/// Storage middleware for adding functionality like caching, compression, etc.
pub mod middleware {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use bytes::Bytes;
    
    /// Caching middleware for storage operations
    pub struct CachingStorage<S> {
        inner: S,
        cache: Arc<RwLock<HashMap<String, Bytes>>>,
        max_cache_size: usize,
    }
    
    impl<S> CachingStorage<S> {
        pub fn new(inner: S, max_cache_size: usize) -> Self {
            Self {
                inner,
                cache: Arc::new(RwLock::new(HashMap::new())),
                max_cache_size,
            }
        }
        
        fn get_from_cache(&self, key: &str) -> Option<Bytes> {
            self.cache.read().unwrap().get(key).cloned()
        }
        
        fn put_to_cache(&self, key: String, data: Bytes) {
            let mut cache = self.cache.write().unwrap();
            
            // Simple cache eviction: remove oldest entries if cache is full
            if cache.len() >= self.max_cache_size {
                if let Some(first_key) = cache.keys().next().cloned() {
                    cache.remove(&first_key);
                }
            }
            
            cache.insert(key, data);
        }
        
        fn remove_from_cache(&self, key: &str) {
            self.cache.write().unwrap().remove(key);
        }
    }
    
    impl<S: StorageApiSync> StorageApiSync for CachingStorage<S> {
        fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
            let result = self.inner.put(key, data.clone());
            if result.is_ok() {
                self.put_to_cache(key.to_string(), data);
            }
            result
        }
        
        fn put_with_metadata(&self, key: &str, data: Bytes, metadata: StorageMetadata) -> StorageResult<()> {
            let result = self.inner.put_with_metadata(key, data.clone(), metadata);
            if result.is_ok() {
                self.put_to_cache(key.to_string(), data);
            }
            result
        }
        
        fn get(&self, key: &str) -> StorageResult<Bytes> {
            if let Some(cached_data) = self.get_from_cache(key) {
                return Ok(cached_data);
            }
            
            let data = self.inner.get(key)?;
            self.put_to_cache(key.to_string(), data.clone());
            Ok(data)
        }
        
        fn get_with_metadata(&self, key: &str) -> StorageResult<(Bytes, StorageMetadata)> {
            // For simplicity, we don't cache metadata
            self.inner.get_with_metadata(key)
        }
        
        fn delete(&self, key: &str) -> StorageResult<()> {
            let result = self.inner.delete(key);
            if result.is_ok() {
                self.remove_from_cache(key);
            }
            result
        }
        
        fn exists(&self, key: &str) -> StorageResult<bool> {
            if self.get_from_cache(key).is_some() {
                return Ok(true);
            }
            self.inner.exists(key)
        }
        
        fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
            self.inner.list(prefix)
        }
        
        fn head(&self, key: &str) -> StorageResult<StorageMetadata> {
            self.inner.head(key)
        }
        
        fn copy(&self, source: &str, destination: &str) -> StorageResult<()> {
            let result = self.inner.copy(source, destination);
            if result.is_ok() {
                // Copy cache entry if it exists
                if let Some(data) = self.get_from_cache(source) {
                    self.put_to_cache(destination.to_string(), data);
                }
            }
            result
        }
        
        fn batch(&self, operations: Vec<BatchOperation>) -> StorageResult<Vec<BatchResult>> {
            self.inner.batch(operations)
        }
        
        fn backend_type(&self) -> StorageBackend {
            self.inner.backend_type()
        }
        
        fn config(&self) -> &StorageConfig {
            self.inner.config()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_storage_factory_local() {
        let temp_dir = TempDir::new().unwrap();
        let local_config = LocalConfig {
            base_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let storage_config = StorageConfig::default();
        
        let storage = StorageFactory::create_local(local_config, storage_config);
        assert!(storage.is_ok());
    }
    
    #[test]
    fn test_constants() {
        assert_eq!(constants::MAX_KEY_LENGTH, 1024);
        assert_eq!(constants::MAX_VALUE_SIZE, 1024 * 1024 * 1024);
        assert_eq!(constants::DEFAULT_TIMEOUT_SECONDS, 30);
        assert_eq!(constants::DEFAULT_MAX_RETRIES, 3);
    }
    
    #[test]
    fn test_utils_validate_key() {
        assert!(utils::validate_storage_key("valid/key").is_ok());
        assert!(utils::validate_storage_key("").is_err());
    }
    
    #[test]
    fn test_utils_generate_key() {
        let key = utils::generate_unique_key("prefix", Some("txt"));
        assert!(key.starts_with("prefix/"));
        assert!(key.ends_with(".txt"));
    }
    
    #[test]
    fn test_utils_compress_decompress() {
        let data = b"aaabbbccc";
        let compressed = utils::compress_data(data).unwrap();
        let decompressed = utils::decompress_data(&compressed).unwrap();
        assert_eq!(data.to_vec(), decompressed.to_vec());
    }
    
    #[test]
    fn test_caching_middleware() {
        let temp_dir = TempDir::new().unwrap();
        let local_config = LocalConfig {
            base_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let storage_config = StorageConfig::default();
        let storage = LocalStorage::new(local_config, storage_config).unwrap();
        
        let cached_storage = middleware::CachingStorage::new(storage, 10);
        
        let key = "test.txt";
        let data = Bytes::from("Hello, World!");
        
        cached_storage.put(key, data.clone()).unwrap();
        let retrieved = cached_storage.get(key).unwrap();
        assert_eq!(data, retrieved);
    }
    
    #[tokio::test]
    async fn test_factory_from_url_local() {
        let temp_dir = TempDir::new().unwrap();
        let url = format!("file://{}", temp_dir.path().display());
        
        let storage = StorageFactory::from_url(&url).await;
        assert!(storage.is_ok());
    }
}