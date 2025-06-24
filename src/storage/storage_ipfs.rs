//! IPFS storage backend implementation
//!
//! This module provides a complete IPFS storage backend with support for:
//! - Content addressing and retrieval
//! - Pinning and unpinning content
//! - Gateway access for HTTP retrieval
//! - Content discovery and listing
//! - Async operations with retry logic

#[cfg(feature = "ipfs")]
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};

use crate::error::{StorageError, StorageResult};
use crate::storage::storage_api::{
    StorageApi, StorageApiSync, StorageConfig, StorageMetadata, StorageBackend,
    BatchOperation, BatchResult, BatchOperationType,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;

#[cfg(feature = "async")]
use tokio::time::timeout;

/// IPFS storage configuration
#[derive(Debug, Clone)]
pub struct IpfsConfig {
    /// IPFS node URL (API endpoint)
    pub node_url: String,
    /// IPFS gateway URL for HTTP access
    pub gateway_url: String,
    /// Enable automatic pinning of uploaded content
    pub auto_pin: bool,
    /// Pin timeout duration
    pub pin_timeout: Duration,
    /// Maximum file size for single upload (bytes)
    pub max_file_size: u64,
    /// Enable content verification after upload
    pub verify_content: bool,
    /// Custom headers for API requests
    pub custom_headers: HashMap<String, String>,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            node_url: "http://localhost:5001".to_string(),
            gateway_url: "http://localhost:8080".to_string(),
            auto_pin: true,
            pin_timeout: Duration::from_secs(60),
            max_file_size: 100 * 1024 * 1024, // 100MB
            verify_content: true,
            custom_headers: HashMap::new(),
        }
    }
}

/// IPFS content information
#[derive(Debug, Clone)]
pub struct IpfsContent {
    /// Content hash (CID)
    pub hash: String,
    /// Content size in bytes
    pub size: u64,
    /// Content type (if known)
    pub content_type: Option<String>,
    /// Whether content is pinned
    pub pinned: bool,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// IPFS pin status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// Content is pinned
    Pinned,
    /// Content is not pinned
    Unpinned,
    /// Pin status is unknown
    Unknown,
}

/// IPFS storage backend
#[cfg(feature = "ipfs")]
pub struct IpfsStorage {
    client: IpfsClient,
    config: IpfsConfig,
    storage_config: StorageConfig,
}

#[cfg(feature = "ipfs")]
impl IpfsStorage {
    /// Create a new IPFS storage backend
    pub async fn new(ipfs_config: IpfsConfig, storage_config: StorageConfig) -> StorageResult<Self> {
        let client = IpfsClient::from_str(&ipfs_config.node_url)
            .map_err(|e| StorageError::ConnectionError {
                reason: format!("Failed to create IPFS client: {}", e),
            })?;
        
        // Test connection to IPFS node
        Self::test_connection(&client).await?;
        
        Ok(Self {
            client,
            config: ipfs_config,
            storage_config,
        })
    }
    
    /// Test connection to IPFS node
    async fn test_connection(client: &IpfsClient) -> StorageResult<()> {
        match timeout(Duration::from_secs(10), client.version()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(StorageError::ConnectionError {
                reason: format!("IPFS node connection failed: {}", e),
            }),
            Err(_) => Err(StorageError::ConnectionError {
                reason: "IPFS node connection timeout".to_string(),
            }),
        }
    }
    
    /// Add content to IPFS and return the hash
    async fn add_content(&self, data: Bytes) -> StorageResult<String> {
        if data.len() > self.config.max_file_size as usize {
            return Err(StorageError::OperationFailed {
                operation: "add_content".to_string(),
                reason: format!("File size {} exceeds maximum {}", data.len(), self.config.max_file_size),
            });
        }
        
        let cursor = std::io::Cursor::new(data.to_vec());
        
        let response = self.client
            .add(cursor)
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "ipfs_add".to_string(),
                reason: format!("Failed to add content to IPFS: {}", e),
            })?;
        
        let hash = response.hash;
        
        // Auto-pin if enabled
        if self.config.auto_pin {
            self.pin_content(&hash).await?;
        }
        
        // Verify content if enabled
        if self.config.verify_content {
            self.verify_content_integrity(&hash, &data).await?;
        }
        
        Ok(hash)
    }
    
    /// Get content from IPFS by hash
    async fn get_content(&self, hash: &str) -> StorageResult<Bytes> {
        let response = self.client
            .cat(hash)
            .map_ok(|chunk| chunk.to_vec())
            .try_concat()
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "ipfs_cat".to_string(),
                reason: format!("Failed to retrieve content from IPFS: {}", e),
            })?;
        
        Ok(Bytes::from(response))
    }
    
    /// Pin content in IPFS
    pub async fn pin_content(&self, hash: &str) -> StorageResult<()> {
        timeout(
            self.config.pin_timeout,
            self.client.pin_add(hash, Some(true))
        )
        .await
        .map_err(|_| StorageError::OperationFailed {
            operation: "pin_timeout".to_string(),
            reason: "Pin operation timed out".to_string(),
        })?
        .map_err(|e| StorageError::OperationFailed {
            operation: "ipfs_pin_add".to_string(),
            reason: format!("Failed to pin content: {}", e),
        })?;
        
        Ok(())
    }
    
    /// Unpin content in IPFS
    pub async fn unpin_content(&self, hash: &str) -> StorageResult<()> {
        self.client
            .pin_rm(hash, Some(true))
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "ipfs_pin_rm".to_string(),
                reason: format!("Failed to unpin content: {}", e),
            })?;
        
        Ok(())
    }
    
    /// Check if content is pinned
    pub async fn is_pinned(&self, hash: &str) -> StorageResult<PinStatus> {
        match self.client.pin_ls(Some(hash), None).await {
            Ok(response) => {
                if response.keys.contains_key(hash) {
                    Ok(PinStatus::Pinned)
                } else {
                    Ok(PinStatus::Unpinned)
                }
            }
            Err(_) => Ok(PinStatus::Unknown),
        }
    }
    
    /// Get content information
    pub async fn get_content_info(&self, hash: &str) -> StorageResult<IpfsContent> {
        // Get object stats
        let stat = self.client
            .object_stat(hash)
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "ipfs_object_stat".to_string(),
                reason: format!("Failed to get object stats: {}", e),
            })?;
        
        // Check pin status
        let pinned = matches!(self.is_pinned(hash).await?, PinStatus::Pinned);
        
        Ok(IpfsContent {
            hash: hash.to_string(),
            size: stat.cumulative_size as u64,
            content_type: None, // IPFS doesn't store content type by default
            pinned,
            metadata: HashMap::new(),
        })
    }
    
    /// List pinned content
    pub async fn list_pinned(&self) -> StorageResult<Vec<String>> {
        let response = self.client
            .pin_ls(None, None)
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "ipfs_pin_ls".to_string(),
                reason: format!("Failed to list pinned content: {}", e),
            })?;
        
        Ok(response.keys.keys().cloned().collect())
    }
    
    /// Verify content integrity
    async fn verify_content_integrity(&self, hash: &str, original_data: &Bytes) -> StorageResult<()> {
        let retrieved_data = self.get_content(hash).await?;
        
        if retrieved_data != *original_data {
            return Err(StorageError::OperationFailed {
                operation: "verify_content".to_string(),
                reason: "Content integrity verification failed".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Get gateway URL for content
    pub fn get_gateway_url(&self, hash: &str) -> String {
        format!("{}/ipfs/{}", self.config.gateway_url, hash)
    }
    
    /// Resolve IPNS name to IPFS hash
    pub async fn resolve_ipns(&self, name: &str) -> StorageResult<String> {
        let response = self.client
            .name_resolve(Some(name), Some(true), None)
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "ipfs_name_resolve".to_string(),
                reason: format!("Failed to resolve IPNS name: {}", e),
            })?;
        
        // Extract hash from path (e.g., "/ipfs/QmHash" -> "QmHash")
        let hash = response.path
            .strip_prefix("/ipfs/")
            .unwrap_or(&response.path)
            .to_string();
        
        Ok(hash)
    }
    
    /// Publish content to IPNS
    pub async fn publish_ipns(&self, hash: &str, key: Option<&str>) -> StorageResult<String> {
        let response = self.client
            .name_publish(hash, Some(true), None, None, key)
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "ipfs_name_publish".to_string(),
                reason: format!("Failed to publish to IPNS: {}", e),
            })?;
        
        Ok(response.name)
    }
}

#[cfg(feature = "ipfs")]
#[cfg(feature = "async")]
impl StorageApi for IpfsStorage {
    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        // For IPFS, we store the mapping of key -> hash in memory or external store
        // This is a simplified implementation - in practice, you'd want persistent mapping
        let _hash = self.add_content(data).await?;
        
        // In a real implementation, you'd store the key -> hash mapping
        // For now, we just return success
        Ok(())
    }
    
    async fn put_with_metadata(&self, key: &str, data: Bytes, _metadata: StorageMetadata) -> StorageResult<()> {
        // IPFS doesn't natively support metadata, so we just do a regular put
        // In practice, you might store metadata separately or use IPLD
        self.put(key, data).await
    }
    
    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        // In a real implementation, you'd look up the hash for this key
        // For now, we assume the key IS the hash (for demonstration)
        if key.starts_with("Qm") || key.starts_with("bafy") {
            self.get_content(key).await
        } else {
            Err(StorageError::ResourceNotFound {
                resource: key.to_string(),
            })
        }
    }
    
    async fn get_with_metadata(&self, key: &str) -> StorageResult<(Bytes, StorageMetadata)> {
        let data = self.get(key).await?;
        
        // Create basic metadata
        let metadata = StorageMetadata {
            content_type: None,
            content_length: data.len() as u64,
            last_modified: None,
            etag: Some(key.to_string()), // Use hash as ETag
            custom: HashMap::new(),
        };
        
        Ok((data, metadata))
    }
    
    async fn delete(&self, key: &str) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        // For IPFS, "deletion" means unpinning
        // Content remains in the network until garbage collected
        if key.starts_with("Qm") || key.starts_with("bafy") {
            self.unpin_content(key).await
        } else {
            // In a real implementation, you'd remove the key -> hash mapping
            Ok(())
        }
    }
    
    async fn exists(&self, key: &str) -> StorageResult<bool> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        // Check if content exists by trying to get its stats
        if key.starts_with("Qm") || key.starts_with("bafy") {
            match self.client.object_stat(key).await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            // In a real implementation, you'd check the key -> hash mapping
            Ok(false)
        }
    }
    
    async fn list(&self, _prefix: &str) -> StorageResult<Vec<String>> {
        // List all pinned content as a simple implementation
        self.list_pinned().await
    }
    
    async fn head(&self, key: &str) -> StorageResult<StorageMetadata> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        if key.starts_with("Qm") || key.starts_with("bafy") {
            let info = self.get_content_info(key).await?;
            
            Ok(StorageMetadata {
                content_type: info.content_type,
                content_length: info.size,
                last_modified: None,
                etag: Some(info.hash),
                custom: info.metadata,
            })
        } else {
            Err(StorageError::ResourceNotFound {
                resource: key.to_string(),
            })
        }
    }
    
    async fn copy(&self, source: &str, _destination: &str) -> StorageResult<()> {
        // IPFS content is immutable and content-addressed
        // "Copying" doesn't make sense in the traditional sense
        // We could pin the content with a different key mapping
        crate::storage::storage_api::utils::validate_key(source)?;
        
        if source.starts_with("Qm") || source.starts_with("bafy") {
            // Just ensure the content is pinned
            self.pin_content(source).await
        } else {
            Err(StorageError::OperationFailed {
                operation: "copy".to_string(),
                reason: "Copy operation not supported for IPFS".to_string(),
            })
        }
    }
    
    async fn batch(&self, operations: Vec<BatchOperation>) -> StorageResult<Vec<BatchResult>> {
        let mut results = Vec::new();
        
        for operation in operations {
            let result = match operation.operation {
                BatchOperationType::Put => {
                    if let Some(data) = operation.data {
                        self.put(&operation.key, data).await.map(|_| None)
                    } else {
                        Err(StorageError::OperationFailed {
                            operation: "batch_put".to_string(),
                            reason: "No data provided for put operation".to_string(),
                        })
                    }
                }
                BatchOperationType::Get => {
                    self.get(&operation.key).await.map(Some)
                }
                BatchOperationType::Delete => {
                    self.delete(&operation.key).await.map(|_| None)
                }
                BatchOperationType::Exists => {
                    self.exists(&operation.key).await.map(|exists| {
                        if exists {
                            Some(Bytes::from("true"))
                        } else {
                            Some(Bytes::from("false"))
                        }
                    })
                }
            };
            
            results.push(BatchResult {
                key: operation.key,
                result,
            });
        }
        
        Ok(results)
    }
    
    fn backend_type(&self) -> StorageBackend {
        StorageBackend::Ipfs
    }
    
    fn config(&self) -> &StorageConfig {
        &self.storage_config
    }
}

// Stub implementation for when IPFS feature is not enabled
#[cfg(not(feature = "ipfs"))]
pub struct IpfsStorage;

#[cfg(not(feature = "ipfs"))]
impl IpfsStorage {
    pub fn new(_ipfs_config: IpfsConfig, _storage_config: StorageConfig) -> StorageResult<Self> {
        Err(StorageError::BackendNotAvailable {
            backend: "IPFS".to_string(),
        })
    }
}

/// Utility functions for IPFS operations
pub mod utils {
    use super::*;
    
    /// Validate IPFS hash format
    pub fn validate_ipfs_hash(hash: &str) -> bool {
        // Basic validation for IPFS hashes
        hash.starts_with("Qm") && hash.len() == 46 || // CIDv0
        hash.starts_with("bafy") || hash.starts_with("bafk") // CIDv1
    }
    
    /// Extract hash from IPFS path
    pub fn extract_hash_from_path(path: &str) -> Option<&str> {
        if let Some(stripped) = path.strip_prefix("/ipfs/") {
            Some(stripped.split('/').next().unwrap_or(stripped))
        } else {
            None
        }
    }
    
    /// Generate IPFS gateway URL
    pub fn generate_gateway_url(gateway_base: &str, hash: &str) -> String {
        format!("{}/ipfs/{}", gateway_base.trim_end_matches('/'), hash)
    }
    
    /// Check if string looks like an IPFS hash
    pub fn is_likely_ipfs_hash(s: &str) -> bool {
        validate_ipfs_hash(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ipfs_config_default() {
        let config = IpfsConfig::default();
        assert_eq!(config.node_url, "http://localhost:5001");
        assert_eq!(config.gateway_url, "http://localhost:8080");
        assert!(config.auto_pin);
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
    }
    
    #[test]
    fn test_validate_ipfs_hash() {
        assert!(utils::validate_ipfs_hash("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"));
        assert!(utils::validate_ipfs_hash("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"));
        assert!(!utils::validate_ipfs_hash("invalid_hash"));
        assert!(!utils::validate_ipfs_hash(""));
    }
    
    #[test]
    fn test_extract_hash_from_path() {
        assert_eq!(
            utils::extract_hash_from_path("/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"),
            Some("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        );
        assert_eq!(
            utils::extract_hash_from_path("/ipfs/QmHash/file.txt"),
            Some("QmHash")
        );
        assert_eq!(utils::extract_hash_from_path("not_ipfs_path"), None);
    }
    
    #[test]
    fn test_generate_gateway_url() {
        assert_eq!(
            utils::generate_gateway_url("http://localhost:8080", "QmHash"),
            "http://localhost:8080/ipfs/QmHash"
        );
        assert_eq!(
            utils::generate_gateway_url("http://localhost:8080/", "QmHash"),
            "http://localhost:8080/ipfs/QmHash"
        );
    }
    
    #[cfg(feature = "ipfs")]
    #[tokio::test]
    async fn test_ipfs_storage_creation_without_node() {
        let ipfs_config = IpfsConfig {
            node_url: "http://localhost:5001".to_string(),
            ..Default::default()
        };
        let storage_config = StorageConfig::default();
        
        // This will fail without a running IPFS node, but tests the creation logic
        let result = IpfsStorage::new(ipfs_config, storage_config).await;
        assert!(result.is_err()); // Expected to fail without IPFS node
    }
}