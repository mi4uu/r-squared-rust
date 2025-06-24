//! # R-Squared Rust Library
//!
//! A pure Rust implementation of the R-Squared blockchain library, providing cryptographic
//! operations, blockchain transaction handling, data serialization, and storage capabilities.
//!
//! ## Features
//!
//! - **ECC Module**: Elliptic curve cryptography, key management, and digital signatures
//! - **Chain Module**: Blockchain operations, transaction building, and chain state management
//! - **Serializer Module**: Data serialization and deserialization for blockchain operations
//! - **Storage Module**: Pluggable storage backends including S3, IPFS, and memory adapters
//!
//! ## Optional Features
//!
//! - `wasm`: WebAssembly support for browser environments
//! - `async`: Asynchronous operations support
//! - `s3`: AWS S3 storage backend
//! - `ipfs`: IPFS storage backend
//! - `serde_support`: Serde serialization support
//!
//! ## Example
//!
//! ```rust
//! use r_squared_rust::ecc::PrivateKey;
//! use r_squared_rust::chain::TransactionBuilder;
//!
//! // Generate a new private key
//! let private_key = PrivateKey::generate()?;
//! let public_key = private_key.public_key();
//!
//! // Create a transaction builder
//! let mut tx_builder = TransactionBuilder::new();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![warn(clippy::all)]

// Re-export core error types
pub use error::{Error, Result};

// Core modules
pub mod error;
pub mod ecc;
pub mod chain;
pub mod serializer;
pub mod storage;

// Utility modules
mod utils;

// Re-export commonly used types
pub mod prelude {
    //! Common types and traits for convenient importing
    
    pub use crate::error::{Error, Result};
    pub use crate::ecc::{PrivateKey, PublicKey, Signature, Address};
    pub use crate::chain::{TransactionBuilder, ChainStore};
    pub use crate::serializer::{Serializer, SerializerError};
    pub use crate::storage::{StorageAdapter, StorageError};
}

// Version information
/// The version of this crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name of this crate
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
        assert_eq!(CRATE_NAME, "r-squared-rust");
    }
}