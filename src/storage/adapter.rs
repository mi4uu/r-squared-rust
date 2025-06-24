//! Storage adapter trait and types

use crate::error::{StorageError, StorageResult};

/// Storage adapter trait for different storage backends
pub trait StorageAdapter {
    /// Store data with a key
    fn store(&self, key: &str, data: &[u8]) -> StorageResult<()>;
    
    /// Retrieve data by key
    fn retrieve(&self, key: &str) -> StorageResult<Vec<u8>>;
    
    /// Delete data by key
    fn delete(&self, key: &str) -> StorageResult<()>;
    
    /// Check if key exists
    fn exists(&self, key: &str) -> StorageResult<bool>;
}