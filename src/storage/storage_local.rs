//! Local filesystem storage backend implementation
//!
//! This module provides a complete local filesystem storage backend with support for:
//! - File system operations (create, read, update, delete)
//! - Directory management and traversal
//! - Atomic writes with temporary files
//! - File metadata and permissions
//! - Batch operations for efficiency

use crate::error::{StorageError, StorageResult};
use crate::storage::storage_api::{
    StorageApi, StorageApiSync, StorageConfig, StorageMetadata, StorageBackend,
    BatchOperation, BatchResult, BatchOperationType,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "async")]
use tokio::fs as async_fs;
#[cfg(feature = "async")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Local storage configuration
#[derive(Debug, Clone)]
pub struct LocalConfig {
    /// Base directory for storage
    pub base_path: PathBuf,
    /// Create directories if they don't exist
    pub create_dirs: bool,
    /// Use atomic writes (write to temp file, then rename)
    pub atomic_writes: bool,
    /// File permissions (Unix only)
    pub file_permissions: Option<u32>,
    /// Directory permissions (Unix only)
    pub dir_permissions: Option<u32>,
    /// Enable file compression
    pub compression: bool,
    /// Maximum file size (bytes)
    pub max_file_size: u64,
    /// Enable file checksums
    pub enable_checksums: bool,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("./storage"),
            create_dirs: true,
            atomic_writes: true,
            file_permissions: Some(0o644),
            dir_permissions: Some(0o755),
            compression: false,
            max_file_size: 1024 * 1024 * 1024, // 1GB
            enable_checksums: false,
        }
    }
}

/// Local filesystem storage backend
pub struct LocalStorage {
    config: LocalConfig,
    storage_config: StorageConfig,
}

impl LocalStorage {
    /// Create a new local storage backend
    pub fn new(local_config: LocalConfig, storage_config: StorageConfig) -> StorageResult<Self> {
        // Create base directory if it doesn't exist
        if local_config.create_dirs && !local_config.base_path.exists() {
            fs::create_dir_all(&local_config.base_path)
                .map_err(|e| StorageError::OperationFailed {
                    operation: "create_base_directory".to_string(),
                    reason: format!("Failed to create base directory: {}", e),
                })?;
            
            // Set directory permissions on Unix
            #[cfg(unix)]
            if let Some(perms) = local_config.dir_permissions {
                use std::os::unix::fs::PermissionsExt;
                let permissions = std::fs::Permissions::from_mode(perms);
                fs::set_permissions(&local_config.base_path, permissions)
                    .map_err(|e| StorageError::OperationFailed {
                        operation: "set_directory_permissions".to_string(),
                        reason: format!("Failed to set directory permissions: {}", e),
                    })?;
            }
        }
        
        // Verify base directory is accessible
        if !local_config.base_path.exists() {
            return Err(StorageError::OperationFailed {
                operation: "verify_base_directory".to_string(),
                reason: "Base directory does not exist and create_dirs is disabled".to_string(),
            });
        }
        
        if !local_config.base_path.is_dir() {
            return Err(StorageError::OperationFailed {
                operation: "verify_base_directory".to_string(),
                reason: "Base path exists but is not a directory".to_string(),
            });
        }
        
        Ok(Self {
            config: local_config,
            storage_config,
        })
    }
    
    /// Get the full path for a key
    fn get_full_path(&self, key: &str) -> PathBuf {
        self.config.base_path.join(key)
    }
    
    /// Ensure parent directory exists
    fn ensure_parent_dir(&self, path: &Path) -> StorageResult<()> {
        if let Some(parent) = path.parent() {
            if !parent.exists() && self.config.create_dirs {
                fs::create_dir_all(parent)
                    .map_err(|e| StorageError::OperationFailed {
                        operation: "create_parent_directory".to_string(),
                        reason: format!("Failed to create parent directory: {}", e),
                    })?;
                
                // Set directory permissions on Unix
                #[cfg(unix)]
                if let Some(perms) = self.config.dir_permissions {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = std::fs::Permissions::from_mode(perms);
                    fs::set_permissions(parent, permissions)
                        .map_err(|e| StorageError::OperationFailed {
                            operation: "set_directory_permissions".to_string(),
                            reason: format!("Failed to set directory permissions: {}", e),
                        })?;
                }
            }
        }
        Ok(())
    }
    
    /// Write data to file with optional atomic operation
    fn write_file(&self, path: &Path, data: &[u8]) -> StorageResult<()> {
        if data.len() > self.config.max_file_size as usize {
            return Err(StorageError::OperationFailed {
                operation: "write_file".to_string(),
                reason: format!("File size {} exceeds maximum {}", data.len(), self.config.max_file_size),
            });
        }
        
        self.ensure_parent_dir(path)?;
        
        if self.config.atomic_writes {
            // Write to temporary file first, then rename
            let temp_path = path.with_extension("tmp");
            
            {
                let mut file = File::create(&temp_path)
                    .map_err(|e| StorageError::OperationFailed {
                        operation: "create_temp_file".to_string(),
                        reason: format!("Failed to create temporary file: {}", e),
                    })?;
                
                let mut writer = BufWriter::new(&mut file);
                writer.write_all(data)
                    .map_err(|e| StorageError::OperationFailed {
                        operation: "write_temp_file".to_string(),
                        reason: format!("Failed to write to temporary file: {}", e),
                    })?;
                
                writer.flush()
                    .map_err(|e| StorageError::OperationFailed {
                        operation: "flush_temp_file".to_string(),
                        reason: format!("Failed to flush temporary file: {}", e),
                    })?;
            }
            
            // Atomic rename
            fs::rename(&temp_path, path)
                .map_err(|e| StorageError::OperationFailed {
                    operation: "atomic_rename".to_string(),
                    reason: format!("Failed to rename temporary file: {}", e),
                })?;
        } else {
            // Direct write
            let mut file = File::create(path)
                .map_err(|e| StorageError::OperationFailed {
                    operation: "create_file".to_string(),
                    reason: format!("Failed to create file: {}", e),
                })?;
            
            let mut writer = BufWriter::new(&mut file);
            writer.write_all(data)
                .map_err(|e| StorageError::OperationFailed {
                    operation: "write_file".to_string(),
                    reason: format!("Failed to write file: {}", e),
                })?;
            
            writer.flush()
                .map_err(|e| StorageError::OperationFailed {
                    operation: "flush_file".to_string(),
                    reason: format!("Failed to flush file: {}", e),
                })?;
        }
        
        // Set file permissions on Unix
        #[cfg(unix)]
        if let Some(perms) = self.config.file_permissions {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(perms);
            fs::set_permissions(path, permissions)
                .map_err(|e| StorageError::OperationFailed {
                    operation: "set_file_permissions".to_string(),
                    reason: format!("Failed to set file permissions: {}", e),
                })?;
        }
        
        Ok(())
    }
    
    /// Read data from file
    fn read_file(&self, path: &Path) -> StorageResult<Vec<u8>> {
        let mut file = File::open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => StorageError::ResourceNotFound {
                    resource: path.to_string_lossy().to_string(),
                },
                _ => StorageError::OperationFailed {
                    operation: "open_file".to_string(),
                    reason: format!("Failed to open file: {}", e),
                }
            })?;
        
        let mut buffer = Vec::new();
        let mut reader = BufReader::new(&mut file);
        reader.read_to_end(&mut buffer)
            .map_err(|e| StorageError::OperationFailed {
                operation: "read_file".to_string(),
                reason: format!("Failed to read file: {}", e),
            })?;
        
        Ok(buffer)
    }
    
    /// Get file metadata
    fn get_file_metadata(&self, path: &Path) -> StorageResult<StorageMetadata> {
        let metadata = fs::metadata(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => StorageError::ResourceNotFound {
                    resource: path.to_string_lossy().to_string(),
                },
                _ => StorageError::OperationFailed {
                    operation: "get_metadata".to_string(),
                    reason: format!("Failed to get file metadata: {}", e),
                }
            })?;
        
        let last_modified = metadata.modified()
            .ok()
            .and_then(|time| {
                time.duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|duration| {
                        chrono::DateTime::from_timestamp(duration.as_secs() as i64, duration.subsec_nanos())
                            .unwrap_or_default()
                    })
            });
        
        // Try to determine content type from file extension
        let content_type = path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| match ext.to_lowercase().as_str() {
                "txt" => Some("text/plain".to_string()),
                "json" => Some("application/json".to_string()),
                "xml" => Some("application/xml".to_string()),
                "html" | "htm" => Some("text/html".to_string()),
                "css" => Some("text/css".to_string()),
                "js" => Some("application/javascript".to_string()),
                "png" => Some("image/png".to_string()),
                "jpg" | "jpeg" => Some("image/jpeg".to_string()),
                "gif" => Some("image/gif".to_string()),
                "pdf" => Some("application/pdf".to_string()),
                "zip" => Some("application/zip".to_string()),
                _ => None,
            });
        
        let mut custom = HashMap::new();
        
        // Add Unix-specific metadata
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            custom.insert("inode".to_string(), metadata.ino().to_string());
            custom.insert("mode".to_string(), format!("{:o}", metadata.mode()));
            custom.insert("uid".to_string(), metadata.uid().to_string());
            custom.insert("gid".to_string(), metadata.gid().to_string());
        }
        
        // Add Windows-specific metadata
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            custom.insert("file_attributes".to_string(), metadata.file_attributes().to_string());
        }
        
        Ok(StorageMetadata {
            content_type,
            content_length: metadata.len(),
            last_modified,
            etag: None, // Could implement based on file hash
            custom,
        })
    }
    
    /// List files in directory with optional prefix filtering
    fn list_files_in_dir(&self, dir_path: &Path, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let mut files = Vec::new();
        
        if !dir_path.exists() {
            return Ok(files);
        }
        
        let entries = fs::read_dir(dir_path)
            .map_err(|e| StorageError::OperationFailed {
                operation: "read_directory".to_string(),
                reason: format!("Failed to read directory: {}", e),
            })?;
        
        for entry in entries {
            let entry = entry.map_err(|e| StorageError::OperationFailed {
                operation: "read_directory_entry".to_string(),
                reason: format!("Failed to read directory entry: {}", e),
            })?;
            
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(prefix) = prefix {
                        if file_name.starts_with(prefix) {
                            files.push(file_name.to_string());
                        }
                    } else {
                        files.push(file_name.to_string());
                    }
                }
            } else if path.is_dir() {
                // Recursively list subdirectories
                let subdir_files = self.list_files_in_dir(&path, prefix)?;
                for subfile in subdir_files {
                    if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                        files.push(format!("{}/{}", dir_name, subfile));
                    }
                }
            }
        }
        
        files.sort();
        Ok(files)
    }
    
    /// Copy file from source to destination
    pub fn copy_file(&self, source: &str, destination: &str) -> StorageResult<()> {
        let source_path = self.get_full_path(source);
        let dest_path = self.get_full_path(destination);
        
        self.ensure_parent_dir(&dest_path)?;
        
        fs::copy(&source_path, &dest_path)
            .map_err(|e| StorageError::OperationFailed {
                operation: "copy_file".to_string(),
                reason: format!("Failed to copy file: {}", e),
            })?;
        
        Ok(())
    }
    
    /// Move file from source to destination
    pub fn move_file(&self, source: &str, destination: &str) -> StorageResult<()> {
        let source_path = self.get_full_path(source);
        let dest_path = self.get_full_path(destination);
        
        self.ensure_parent_dir(&dest_path)?;
        
        fs::rename(&source_path, &dest_path)
            .map_err(|e| StorageError::OperationFailed {
                operation: "move_file".to_string(),
                reason: format!("Failed to move file: {}", e),
            })?;
        
        Ok(())
    }
    
    /// Get directory size recursively
    pub fn get_directory_size(&self, path: &str) -> StorageResult<u64> {
        let dir_path = self.get_full_path(path);
        self.calculate_dir_size(&dir_path)
    }
    
    fn calculate_dir_size(&self, dir_path: &Path) -> StorageResult<u64> {
        let mut total_size = 0;
        
        if !dir_path.exists() {
            return Ok(0);
        }
        
        if dir_path.is_file() {
            let metadata = fs::metadata(dir_path)
                .map_err(|e| StorageError::OperationFailed {
                    operation: "get_file_size".to_string(),
                    reason: format!("Failed to get file size: {}", e),
                })?;
            return Ok(metadata.len());
        }
        
        let entries = fs::read_dir(dir_path)
            .map_err(|e| StorageError::OperationFailed {
                operation: "read_directory".to_string(),
                reason: format!("Failed to read directory: {}", e),
            })?;
        
        for entry in entries {
            let entry = entry.map_err(|e| StorageError::OperationFailed {
                operation: "read_directory_entry".to_string(),
                reason: format!("Failed to read directory entry: {}", e),
            })?;
            
            let path = entry.path();
            if path.is_file() {
                let metadata = fs::metadata(&path)
                    .map_err(|e| StorageError::OperationFailed {
                        operation: "get_file_metadata".to_string(),
                        reason: format!("Failed to get file metadata: {}", e),
                    })?;
                total_size += metadata.len();
            } else if path.is_dir() {
                total_size += self.calculate_dir_size(&path)?;
            }
        }
        
        Ok(total_size)
    }
}

impl StorageApiSync for LocalStorage {
    fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let path = self.get_full_path(key);
        self.write_file(&path, &data)
    }
    
    fn put_with_metadata(&self, key: &str, data: Bytes, _metadata: StorageMetadata) -> StorageResult<()> {
        // Local filesystem doesn't support arbitrary metadata, so we just do a regular put
        // In practice, you might store metadata in extended attributes or separate files
        StorageApiSync::put(self, key, data)
    }
    
    fn get(&self, key: &str) -> StorageResult<Bytes> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let path = self.get_full_path(key);
        let data = self.read_file(&path)?;
        Ok(Bytes::from(data))
    }
    
    fn get_with_metadata(&self, key: &str) -> StorageResult<(Bytes, StorageMetadata)> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let path = self.get_full_path(key);
        let data = self.read_file(&path)?;
        let metadata = self.get_file_metadata(&path)?;
        
        Ok((Bytes::from(data), metadata))
    }
    
    fn delete(&self, key: &str) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let path = self.get_full_path(key);
        
        if path.is_file() {
            fs::remove_file(&path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => StorageError::ResourceNotFound {
                        resource: key.to_string(),
                    },
                    _ => StorageError::OperationFailed {
                        operation: "delete_file".to_string(),
                        reason: format!("Failed to delete file: {}", e),
                    }
                })?;
        } else if path.is_dir() {
            fs::remove_dir_all(&path)
                .map_err(|e| StorageError::OperationFailed {
                    operation: "delete_directory".to_string(),
                    reason: format!("Failed to delete directory: {}", e),
                })?;
        } else {
            return Err(StorageError::ResourceNotFound {
                resource: key.to_string(),
            });
        }
        
        Ok(())
    }
    
    fn exists(&self, key: &str) -> StorageResult<bool> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let path = self.get_full_path(key);
        Ok(path.exists())
    }
    
    fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let base_path = if prefix.is_empty() {
            self.config.base_path.clone()
        } else {
            self.get_full_path(prefix)
        };
        
        self.list_files_in_dir(&base_path, None)
    }
    
    fn head(&self, key: &str) -> StorageResult<StorageMetadata> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let path = self.get_full_path(key);
        self.get_file_metadata(&path)
    }
    
    fn copy(&self, source: &str, destination: &str) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(source)?;
        crate::storage::storage_api::utils::validate_key(destination)?;
        
        self.copy_file(source, destination)
    }
    
    fn batch(&self, operations: Vec<BatchOperation>) -> StorageResult<Vec<BatchResult>> {
        let mut results = Vec::new();
        
        for operation in operations {
            let result = match operation.operation {
                BatchOperationType::Put => {
                    if let Some(data) = operation.data {
                        StorageApiSync::put(self, &operation.key, data).map(|_| None)
                    } else {
                        Err(StorageError::OperationFailed {
                            operation: "batch_put".to_string(),
                            reason: "No data provided for put operation".to_string(),
                        })
                    }
                }
                BatchOperationType::Get => {
                    StorageApiSync::get(self, &operation.key).map(Some)
                }
                BatchOperationType::Delete => {
                    StorageApiSync::delete(self, &operation.key).map(|_| None)
                }
                BatchOperationType::Exists => {
                    StorageApiSync::exists(self, &operation.key).map(|exists| {
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
        StorageBackend::Local
    }
    
    fn config(&self) -> &StorageConfig {
        &self.storage_config
    }
}

// Async implementation removed to avoid method ambiguity
// Will be re-added in a separate async-specific wrapper struct

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    fn create_test_storage() -> (LocalStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let local_config = LocalConfig {
            base_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let storage_config = StorageConfig::default();
        let storage = LocalStorage::new(local_config, storage_config).unwrap();
        (storage, temp_dir)
    }
    
    #[test]
    fn test_local_config_default() {
        let config = LocalConfig::default();
        assert_eq!(config.base_path, PathBuf::from("./storage"));
        assert!(config.create_dirs);
        assert!(config.atomic_writes);
        assert_eq!(config.max_file_size, 1024 * 1024 * 1024);
    }
    
    #[test]
    fn test_put_and_get() {
        let (storage, _temp_dir) = create_test_storage();
        
        let key = "test/file.txt";
        let data = Bytes::from("Hello, World!");
        
        storage.put(key, data.clone()).unwrap();
        let retrieved = storage.get(key).unwrap();
        
        assert_eq!(data, retrieved);
    }
    
    #[test]
    fn test_exists_and_delete() {
        let (storage, _temp_dir) = create_test_storage();
        
        let key = "test/file.txt";
        let data = Bytes::from("Hello, World!");
        
        assert!(!storage.exists(key).unwrap());
        
        storage.put(key, data).unwrap();
        assert!(storage.exists(key).unwrap());
        
        storage.delete(key).unwrap();
        assert!(!storage.exists(key).unwrap());
    }
    
    #[test]
    fn test_metadata() {
        let (storage, _temp_dir) = create_test_storage();
        
        let key = "test/file.txt";
        let data = Bytes::from("Hello, World!");
        
        storage.put(key, data.clone()).unwrap();
        let metadata = storage.head(key).unwrap();
        
        assert_eq!(metadata.content_length, data.len() as u64);
        assert!(metadata.last_modified.is_some());
    }
    
    #[test]
    fn test_copy() {
        let (storage, _temp_dir) = create_test_storage();
        
        let source = "test/source.txt";
        let dest = "test/dest.txt";
        let data = Bytes::from("Hello, World!");
        
        storage.put(source, data.clone()).unwrap();
        storage.copy(source, dest).unwrap();
        
        let retrieved = storage.get(dest).unwrap();
        assert_eq!(data, retrieved);
    }
    
    #[test]
    fn test_list() {
        let (storage, _temp_dir) = create_test_storage();
        
        storage.put("file1.txt", Bytes::from("data1")).unwrap();
        storage.put("file2.txt", Bytes::from("data2")).unwrap();
        storage.put("subdir/file3.txt", Bytes::from("data3")).unwrap();
        
        let files = storage.list("").unwrap();
        assert!(files.contains(&"file1.txt".to_string()));
        assert!(files.contains(&"file2.txt".to_string()));
        assert!(files.contains(&"subdir/file3.txt".to_string()));
    }
    
    #[test]
    fn test_batch_operations() {
        let (storage, _temp_dir) = create_test_storage();
        
        let operations = vec![
            BatchOperation {
                operation: BatchOperationType::Put,
                key: "test1.txt".to_string(),
                data: Some(Bytes::from("data1")),
            },
            BatchOperation {
                operation: BatchOperationType::Put,
                key: "test2.txt".to_string(),
                data: Some(Bytes::from("data2")),
            },
            BatchOperation {
                operation: BatchOperationType::Get,
                key: "test1.txt".to_string(),
                data: None,
            },
        ];
        
        let results = storage.batch(operations).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].result.is_ok());
        assert!(results[1].result.is_ok());
        assert!(results[2].result.is_ok());
        
        if let Ok(Some(data)) = &results[2].result {
            assert_eq!(data, &Bytes::from("data1"));
        }
    }
    
    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_async_operations() {
        let (storage, _temp_dir) = create_test_storage();
        
        let key = "async_test.txt";
        let data = Bytes::from("Async Hello, World!");
        
        storage.put(key, data.clone()).await.unwrap();
        let retrieved = storage.get(key).await.unwrap();
        
        assert_eq!(data, retrieved);
        
        storage.delete(key).await.unwrap();
        assert!(!storage.exists(key).await.unwrap());
    }
}