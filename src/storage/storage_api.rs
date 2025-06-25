//! High-level storage API with async operations
//!
//! This module provides a unified, high-level interface for all storage operations
//! across different backends (S3, IPFS, Local filesystem).

use crate::error::{StorageError, StorageResult};
use std::collections::HashMap;
use std::time::Duration;
use bytes::Bytes;

#[cfg(feature = "async")]
use tokio::time::timeout;

/// Storage configuration for different backends
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Default timeout for operations
    pub timeout: Duration,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Compression enabled
    pub compression: bool,
    /// Encryption enabled
    pub encryption: bool,
    /// Backend-specific configuration
    pub backend_config: HashMap<String, String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_retries: 3,
            compression: false,
            encryption: false,
            backend_config: HashMap::new(),
        }
    }
}

/// Storage metadata for objects
#[derive(Debug, Clone)]
pub struct StorageMetadata {
    /// Content type
    pub content_type: Option<String>,
    /// Content length
    pub content_length: u64,
    /// Last modified timestamp
    pub last_modified: Option<chrono::DateTime<chrono::Utc>>,
    /// ETag or hash
    pub etag: Option<String>,
    /// Custom metadata
    pub custom: HashMap<String, String>,
}

/// Storage backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageBackend {
    /// Local filesystem storage
    Local,
    /// AWS S3 storage
    S3,
    /// IPFS storage
    Ipfs,
}

/// Batch operation for multiple storage operations
#[derive(Debug, Clone)]
pub struct BatchOperation {
    /// Operation type
    pub operation: BatchOperationType,
    /// Object key
    pub key: String,
    /// Data (for put operations)
    pub data: Option<Bytes>,
}

/// Types of batch operations
#[derive(Debug, Clone)]
pub enum BatchOperationType {
    /// Put object
    Put,
    /// Get object
    Get,
    /// Delete object
    Delete,
    /// Check if object exists
    Exists,
}

/// Result of a batch operation
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Operation key
    pub key: String,
    /// Operation result
    pub result: StorageResult<Option<Bytes>>,
}

/// High-level storage API trait
#[cfg(feature = "async")]
pub trait StorageApi: Send + Sync {
    /// Put an object into storage
     fn put(&self, key: &str, data: Bytes) -> impl std::future::Future<Output = StorageResult<()>> + Send;    
    /// Put an object with metadata
     fn put_with_metadata(&self, key: &str, data: Bytes, metadata: StorageMetadata) -> impl std::future::Future<Output = StorageResult<()>> + Send;    
    /// Get an object from storage
     fn get(&self, key: &str) -> impl std::future::Future<Output = StorageResult<Bytes>> + Send;    
    /// Get an object with metadata
     fn get_with_metadata(&self, key: &str) -> impl std::future::Future<Output = StorageResult<(Bytes, StorageMetadata)>> + Send;    
    /// Delete an object from storage
fn delete(&self, key: &str) -> impl std::future::Future<Output = StorageResult<()>> + Send;    
    /// Check if an object exists
 fn exists(&self, key: &str) -> impl std::future::Future<Output = StorageResult<bool>> + Send;    
    /// List objects with a prefix
fn list(&self, prefix: &str) -> impl std::future::Future<Output = StorageResult<Vec<String>>> + Send;    
    /// Get object metadata only
  fn head(&self, key: &str) -> impl std::future::Future<Output = StorageResult<StorageMetadata>> + Send;    
    /// Copy an object within the same backend
   fn copy(&self, source: &str, destination: &str) -> impl std::future::Future<Output = StorageResult<()>> + Send;    
    /// Execute batch operations
fn batch(&self, operations: Vec<BatchOperation>) -> impl std::future::Future<Output = StorageResult<Vec<BatchResult>>> + Send;    
    /// Get storage backend type
    fn backend_type(&self) -> StorageBackend;
    
    /// Get storage configuration
    fn config(&self) -> &StorageConfig;
}

/// Synchronous storage API trait for non-async environments
pub trait StorageApiSync: Send + Sync {
    /// Put an object into storage
    fn put(&self, key: &str, data: Bytes) -> StorageResult<()>;
    
    /// Put an object with metadata
    fn put_with_metadata(&self, key: &str, data: Bytes, metadata: StorageMetadata) -> StorageResult<()>;
    
    /// Get an object from storage
    fn get(&self, key: &str) -> StorageResult<Bytes>;
    
    /// Get an object with metadata
    fn get_with_metadata(&self, key: &str) -> StorageResult<(Bytes, StorageMetadata)>;
    
    /// Delete an object from storage
    fn delete(&self, key: &str) -> StorageResult<()>;
    
    /// Check if an object exists
    fn exists(&self, key: &str) -> StorageResult<bool>;
    
    /// List objects with a prefix
    fn list(&self, prefix: &str) -> StorageResult<Vec<String>>;
    
    /// Get object metadata only
    fn head(&self, key: &str) -> StorageResult<StorageMetadata>;
    
    /// Copy an object within the same backend
    fn copy(&self, source: &str, destination: &str) -> StorageResult<()>;
    
    /// Execute batch operations
    fn batch(&self, operations: Vec<BatchOperation>) -> StorageResult<Vec<BatchResult>>;
    
    /// Get storage backend type
    fn backend_type(&self) -> StorageBackend;
    
    /// Get storage configuration
    fn config(&self) -> &StorageConfig;
}

/// Storage manager for handling multiple backends
pub struct StorageManager {
    /// Default backend
    default_backend: StorageBackend,
    /// Storage configurations
    configs: HashMap<StorageBackend, StorageConfig>,
}

impl StorageManager {
    /// Create a new storage manager
    pub fn new(default_backend: StorageBackend) -> Self {
        Self {
            default_backend,
            configs: HashMap::new(),
        }
    }
    
    /// Set configuration for a backend
    pub fn set_config(&mut self, backend: StorageBackend, config: StorageConfig) {
        self.configs.insert(backend, config);
    }
    
    /// Get configuration for a backend
    pub fn get_config(&self, backend: StorageBackend) -> Option<&StorageConfig> {
        self.configs.get(&backend)
    }
    
    /// Get default backend
    pub fn default_backend(&self) -> StorageBackend {
        self.default_backend
    }
    
    /// Set default backend
    pub fn set_default_backend(&mut self, backend: StorageBackend) {
        self.default_backend = backend;
    }
}

/// Utility functions for storage operations
pub mod utils {
    use super::*;
    use crate::error::StorageError;
    
    /// Validate storage key
    pub fn validate_key(key: &str) -> StorageResult<()> {
        if key.is_empty() {
            return Err(StorageError::OperationFailed {
                operation: "validate_key".to_string(),
                reason: "Key cannot be empty".to_string(),
            });
        }
        
        if key.len() > 1024 {
            return Err(StorageError::OperationFailed {
                operation: "validate_key".to_string(),
                reason: "Key too long (max 1024 characters)".to_string(),
            });
        }
        
        // Check for invalid characters
        if key.contains('\0') || key.contains('\n') || key.contains('\r') {
            return Err(StorageError::OperationFailed {
                operation: "validate_key".to_string(),
                reason: "Key contains invalid characters".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Generate a unique key with prefix
    pub fn generate_key(prefix: &str, suffix: Option<&str>) -> String {
        let timestamp = chrono::Utc::now().timestamp_millis();
        let uuid = uuid::Uuid::new_v4();
        
        match suffix {
            Some(s) => format!("{}/{}-{}.{}", prefix, timestamp, uuid, s),
            None => format!("{}/{}-{}", prefix, timestamp, uuid),
        }
    }
    
    /// Extract prefix from key
    pub fn extract_prefix(key: &str) -> Option<&str> {
        key.rfind('/').map(|pos| &key[..pos])
    }
    
    /// Extract filename from key
    pub fn extract_filename(key: &str) -> &str {
        key.rfind('/').map(|pos| &key[pos + 1..]).unwrap_or(key)
    }
    
    /// Normalize key path
    pub fn normalize_key(key: &str) -> String {
        key.trim_start_matches('/').replace("//", "/")
    }
}

#[cfg(feature = "async")]
/// Retry wrapper for async operations
pub async fn with_retry<F, Fut, T>(
    operation: F,
    max_retries: u32,
    timeout_duration: Duration,
) -> StorageResult<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = StorageResult<T>>,
{
    let mut last_error = None;
    
    for attempt in 0..=max_retries {
        match timeout(timeout_duration, operation()).await {
            Ok(Ok(result)) => return Ok(result),
            Ok(Err(e)) => {
                last_error = Some(e);
                if attempt < max_retries {
                    let delay = Duration::from_millis(100 * (1 << attempt)); // Exponential backoff
                    tokio::time::sleep(delay).await;
                }
            }
            Err(_) => {
                last_error = Some(StorageError::OperationFailed {
                    operation: "retry_operation".to_string(),
                    reason: "Operation timed out".to_string(),
                });
                if attempt < max_retries {
                    let delay = Duration::from_millis(100 * (1 << attempt));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    
    Err(last_error.unwrap_or_else(|| StorageError::OperationFailed {
        operation: "retry_operation".to_string(),
        reason: "All retry attempts failed".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert!(!config.compression);
        assert!(!config.encryption);
    }
    
    #[test]
    fn test_validate_key() {
        assert!(utils::validate_key("valid/key").is_ok());
        assert!(utils::validate_key("").is_err());
        assert!(utils::validate_key("key\0with\0nulls").is_err());
        assert!(utils::validate_key("key\nwith\nnewlines").is_err());
    }
    
    #[test]
    fn test_generate_key() {
        let key = utils::generate_key("prefix", Some("txt"));
        assert!(key.starts_with("prefix/"));
        assert!(key.ends_with(".txt"));
    }
    
    #[test]
    fn test_extract_prefix() {
        assert_eq!(utils::extract_prefix("prefix/file.txt"), Some("prefix"));
        assert_eq!(utils::extract_prefix("file.txt"), None);
    }
    
    #[test]
    fn test_extract_filename() {
        assert_eq!(utils::extract_filename("prefix/file.txt"), "file.txt");
        assert_eq!(utils::extract_filename("file.txt"), "file.txt");
    }
    
    #[test]
    fn test_normalize_key() {
        assert_eq!(utils::normalize_key("/prefix//file.txt"), "prefix/file.txt");
        assert_eq!(utils::normalize_key("prefix/file.txt"), "prefix/file.txt");
    }
    
    #[test]
    fn test_storage_manager() {
        let mut manager = StorageManager::new(StorageBackend::Local);
        assert_eq!(manager.default_backend(), StorageBackend::Local);
        
        let config = StorageConfig::default();
        manager.set_config(StorageBackend::S3, config.clone());
        assert!(manager.get_config(StorageBackend::S3).is_some());
    }
}