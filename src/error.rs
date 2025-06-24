//! Error types for the R-Squared Rust library
//!
//! This module provides a unified error handling system using `thiserror` for
//! all components of the R-Squared library.

use thiserror::Error;

/// The main error type for the R-Squared library
#[derive(Error, Debug)]
pub enum Error {
    /// ECC (Elliptic Curve Cryptography) related errors
    #[error("ECC error: {0}")]
    Ecc(#[from] EccError),

    /// Chain operation errors
    #[error("Chain error: {0}")]
    Chain(#[from] ChainError),

    /// Serialization/deserialization errors
    #[error("Serializer error: {0}")]
    Serializer(#[from] SerializerError),

    /// Storage operation errors
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Invalid input data
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    /// Network-related errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Generic I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other errors
    #[error("Other error: {message}")]
    Other { message: String },
}

/// ECC-specific error types
#[derive(Error, Debug)]
pub enum EccError {
    /// Invalid private key
    #[error("Invalid private key: {reason}")]
    InvalidPrivateKey { reason: String },

    /// Invalid public key
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey { reason: String },

    /// Invalid signature
    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },

    /// Invalid address format
    #[error("Invalid address: {reason}")]
    InvalidAddress { reason: String },

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {operation}")]
    CryptoOperationFailed { operation: String },

    /// Key derivation failed
    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed { reason: String },

    /// Encryption/decryption error
    #[error("Encryption error: {reason}")]
    EncryptionError { reason: String },
}

/// Chain-specific error types
#[derive(Error, Debug)]
pub enum ChainError {
    /// Invalid transaction
    #[error("Invalid transaction: {reason}")]
    InvalidTransaction { reason: String },

    /// Transaction building failed
    #[error("Transaction building failed: {reason}")]
    TransactionBuildFailed { reason: String },

    /// Invalid block
    #[error("Invalid block: {reason}")]
    InvalidBlock { reason: String },

    /// Chain state error
    #[error("Chain state error: {reason}")]
    ChainStateError { reason: String },

    /// Invalid object ID
    #[error("Invalid object ID: {id}")]
    InvalidObjectId { id: String },

    /// Object not found
    #[error("Object not found: {id}")]
    ObjectNotFound { id: String },

    /// Validation error
    #[error("Validation error: {field}: {reason}")]
    ValidationError { field: String, reason: String },
}

/// Serializer-specific error types
#[derive(Error, Debug)]
pub enum SerializerError {
    /// Serialization failed
    #[error("Serialization failed: {reason}")]
    SerializationFailed { reason: String },

    /// Deserialization failed
    #[error("Deserialization failed: {reason}")]
    DeserializationFailed { reason: String },

    /// Invalid data format
    #[error("Invalid data format: {expected}, got: {actual}")]
    InvalidFormat { expected: String, actual: String },

    /// Buffer overflow/underflow
    #[error("Buffer error: {reason}")]
    BufferError { reason: String },

    /// Type conversion error
    #[error("Type conversion error: {from} to {to}")]
    TypeConversionError { from: String, to: String },
}

/// Storage-specific error types
#[derive(Error, Debug)]
pub enum StorageError {
    /// Storage backend not available
    #[error("Storage backend not available: {backend}")]
    BackendNotAvailable { backend: String },

    /// Storage operation failed
    #[error("Storage operation failed: {operation}: {reason}")]
    OperationFailed { operation: String, reason: String },

    /// Authentication failed
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    /// Permission denied
    #[error("Permission denied: {resource}")]
    PermissionDenied { resource: String },

    /// Resource not found
    #[error("Resource not found: {resource}")]
    ResourceNotFound { resource: String },

    /// Storage quota exceeded
    #[error("Storage quota exceeded")]
    QuotaExceeded,

    /// Connection error
    #[error("Connection error: {reason}")]
    ConnectionError { reason: String },
}

/// Network-specific error types
#[derive(Error, Debug)]
pub enum NetworkError {
    /// Connection timeout
    #[error("Connection timeout")]
    Timeout,

    /// Connection refused
    #[error("Connection refused: {address}")]
    ConnectionRefused { address: String },

    /// DNS resolution failed
    #[error("DNS resolution failed: {hostname}")]
    DnsResolutionFailed { hostname: String },

    /// Invalid URL
    #[error("Invalid URL: {url}")]
    InvalidUrl { url: String },

    /// HTTP error
    #[error("HTTP error: {status}: {message}")]
    HttpError { status: u16, message: String },
}

/// Convenience type alias for Results
pub type Result<T> = std::result::Result<T, Error>;

/// Convenience type alias for ECC Results
pub type EccResult<T> = std::result::Result<T, EccError>;

/// Convenience type alias for Chain Results
pub type ChainResult<T> = std::result::Result<T, ChainError>;

/// Convenience type alias for Serializer Results
pub type SerializerResult<T> = std::result::Result<T, SerializerError>;

/// Convenience type alias for Storage Results
pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// Convenience type alias for Network Results
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let ecc_error = EccError::InvalidPrivateKey {
            reason: "Invalid format".to_string(),
        };
        let error = Error::Ecc(ecc_error);
        assert!(error.to_string().contains("ECC error"));
        assert!(error.to_string().contains("Invalid private key"));
    }

    #[test]
    fn test_error_chain() {
        let chain_error = ChainError::InvalidTransaction {
            reason: "Missing signature".to_string(),
        };
        let error = Error::Chain(chain_error);
        assert!(error.to_string().contains("Chain error"));
        assert!(error.to_string().contains("Invalid transaction"));
    }
}