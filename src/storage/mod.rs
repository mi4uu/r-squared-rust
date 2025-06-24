//! Storage module for data persistence
//!
//! This module provides pluggable storage backends including memory,
//! cloud storage (S3), and IPFS adapters.

pub mod adapter;
pub mod memory_adapter;
pub mod personal_data;

#[cfg(feature = "s3")]
pub mod s3_adapter;

#[cfg(feature = "ipfs")]
pub mod ipfs_adapter;

pub mod cloud_storage;

// Re-export main types for convenience
pub use adapter::{StorageAdapter, StorageResult as AdapterResult};
pub use memory_adapter::MemoryAdapter;
pub use personal_data::PersonalData;
pub use cloud_storage::CloudStorage;

#[cfg(feature = "s3")]
pub use s3_adapter::S3Adapter;

#[cfg(feature = "ipfs")]
pub use ipfs_adapter::IPFSAdapter;

use crate::error::{StorageError, StorageResult};

/// Storage constants
pub mod constants {
    //! Constants used throughout the storage module
    
    /// Maximum storage key length
    pub const MAX_KEY_LENGTH: usize = 256;
    
    /// Maximum storage value size
    pub const MAX_VALUE_SIZE: usize = 10 * 1024 * 1024; // 10MB
    
    /// Default timeout for storage operations in seconds
    pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(constants::MAX_KEY_LENGTH, 256);
        assert_eq!(constants::MAX_VALUE_SIZE, 10 * 1024 * 1024);
    }
}