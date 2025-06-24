//! Memory storage adapter

use crate::storage::adapter::StorageAdapter;
use crate::error::StorageResult;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// In-memory storage adapter
#[derive(Debug, Clone)]
pub struct MemoryAdapter {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl Default for MemoryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAdapter {
    /// Create a new memory adapter
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl StorageAdapter for MemoryAdapter {
    fn store(&self, key: &str, data: &[u8]) -> StorageResult<()> {
        let mut storage = self.data.write().unwrap();
        storage.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    fn retrieve(&self, key: &str) -> StorageResult<Vec<u8>> {
        let storage = self.data.read().unwrap();
        storage.get(key).cloned().ok_or_else(|| {
            crate::error::StorageError::ResourceNotFound {
                resource: key.to_string(),
            }
        })
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        let mut storage = self.data.write().unwrap();
        storage.remove(key);
        Ok(())
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        let storage = self.data.read().unwrap();
        Ok(storage.contains_key(key))
    }
}