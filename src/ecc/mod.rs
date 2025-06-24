//! Elliptic Curve Cryptography (ECC) module
//!
//! This module provides cryptographic primitives for the R-Squared library,
//! including private/public key management, digital signatures, address generation,
//! and encryption/decryption operations.

pub mod private_key;
pub mod public_key;
pub mod signature;
pub mod address;
pub mod brain_key;
pub mod key_utils;
pub mod hash;
pub mod aes;

// Re-export main types for convenience
pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::Signature;
pub use address::{Address, AddressFormat};
pub use brain_key::BrainKey;
pub use key_utils::{KeyUtils, KeyFormat};

// Re-export commonly used functions
pub use hash::{sha256, sha256d, hash160, hmac_sha256, ripemd160};
pub use aes::Aes;

use crate::error::{EccError, EccResult};

/// Secp256k1 curve parameters and utilities
pub mod secp256k1 {
    //! Secp256k1 elliptic curve operations
    
    pub use secp256k1::{Secp256k1, All, SecretKey, PublicKey as Secp256k1PublicKey};
    
    /// Global secp256k1 context for performance
    pub static SECP256K1: Secp256k1<All> = Secp256k1::new();
}

/// Common cryptographic constants
pub mod constants {
    //! Cryptographic constants used throughout the ECC module
    
    /// Size of a private key in bytes
    pub const PRIVATE_KEY_SIZE: usize = 32;
    
    /// Size of a compressed public key in bytes
    pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;
    
    /// Size of an uncompressed public key in bytes
    pub const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;
    
    /// Size of a signature in bytes
    pub const SIGNATURE_SIZE: usize = 65;
    
    /// Size of a hash in bytes (SHA-256)
    pub const HASH_SIZE: usize = 32;
    
    /// Size of an address checksum
    pub const ADDRESS_CHECKSUM_SIZE: usize = 4;
    
    /// Default number of PBKDF2 iterations
    pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 4096;
    
    /// Default AES key size in bytes
    pub const AES_KEY_SIZE: usize = 32;
    
    /// AES block size in bytes
    pub const AES_BLOCK_SIZE: usize = 16;
}

/// High-level ECC operations and utilities
pub struct Ecc;

impl Ecc {
    /// Generate a new key pair
    pub fn generate_key_pair() -> EccResult<(PrivateKey, PublicKey)> {
        let private_key = PrivateKey::generate()?;
        let public_key = private_key.public_key();
        Ok((private_key, public_key))
    }

    /// Generate a key pair from a brain key
    pub fn key_pair_from_brain_key(brain_key: &str) -> EccResult<(PrivateKey, PublicKey)> {
        let brain_key = BrainKey::from_words(brain_key)?;
        let private_key = brain_key.to_private_key()?;
        let public_key = private_key.public_key();
        Ok((private_key, public_key))
    }

    /// Generate a key pair from entropy
    pub fn key_pair_from_entropy(entropy: &[u8]) -> EccResult<(PrivateKey, PublicKey)> {
        let private_key = KeyUtils::master_key_from_entropy(entropy)?;
        let public_key = private_key.public_key();
        Ok((private_key, public_key))
    }

    /// Sign a message with a private key
    pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> EccResult<Signature> {
        let hash = sha256(message);
        private_key.sign(&hash)
    }

    /// Verify a signature with a public key
    pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> EccResult<bool> {
        let hash = sha256(message);
        public_key.verify(&hash, signature)
    }

    /// Create an address from a public key
    pub fn create_address(public_key: &PublicKey, prefix: &str) -> EccResult<Address> {
        Address::from_public_key(public_key, prefix)
    }

    /// Encrypt a memo with ECDH
    pub fn encrypt_memo(memo: &str, sender_private: &PrivateKey, recipient_public: &PublicKey) -> EccResult<Vec<u8>> {
        let sender_private_bytes = sender_private.to_bytes();
        let recipient_public_bytes = recipient_public.to_bytes();
        Aes::encrypt_memo(memo, &sender_private_bytes, &recipient_public_bytes)
    }

    /// Decrypt a memo with ECDH
    pub fn decrypt_memo(encrypted_memo: &[u8], recipient_private: &PrivateKey, sender_public: &PublicKey) -> EccResult<String> {
        let recipient_private_bytes = recipient_private.to_bytes();
        let sender_public_bytes = sender_public.to_bytes();
        Aes::decrypt_memo(encrypted_memo, &recipient_private_bytes, &sender_public_bytes)
    }

    /// Derive multiple addresses from a master key
    pub fn derive_addresses(master_key: &PrivateKey, prefix: &str, count: u32) -> EccResult<Vec<Address>> {
        let derived_keys = KeyUtils::derive_keys(master_key, count)?;
        let mut addresses = Vec::new();
        
        for key in derived_keys {
            let public_key = key.public_key();
            let address = Address::from_public_key(&public_key, prefix)?;
            addresses.push(address);
        }
        
        Ok(addresses)
    }

    /// Validate a complete key pair and address
    pub fn validate_key_set(private_key: &PrivateKey, public_key: &PublicKey, address: &Address) -> EccResult<bool> {
        // Check if private key matches public key
        if !KeyUtils::validate_key_pair(private_key, public_key) {
            return Ok(false);
        }
        
        // Check if public key matches address
        let derived_address = Address::from_public_key(public_key, address.prefix())?;
        Ok(derived_address == *address)
    }

    /// Create a multisig address (simplified)
    pub fn create_multisig_address(public_keys: &[PublicKey], threshold: usize, prefix: &str) -> EccResult<Address> {
        if threshold == 0 || threshold > public_keys.len() {
            return Err(EccError::InvalidPublicKey {
                reason: "Invalid multisig threshold".to_string(),
            });
        }

        // Create a combined hash from all public keys
        let mut combined_data = Vec::new();
        combined_data.push(threshold as u8);
        combined_data.push(public_keys.len() as u8);
        
        for pubkey in public_keys {
            combined_data.extend_from_slice(&pubkey.to_bytes());
        }
        
        let hash = hash160(&combined_data);
        Ok(Address::from_hash160(&hash, prefix))
    }

    /// Recover public key from signature and message
    pub fn recover_public_key(message: &[u8], signature: &Signature) -> EccResult<PublicKey> {
        signature.recover_public_key()
    }
}

/// Utility functions for common ECC operations
pub mod utils {
    use super::*;
    
    /// Check if a string is a valid WIF private key
    pub fn is_valid_wif(wif: &str) -> bool {
        KeyUtils::validate_wif(wif)
    }
    
    /// Check if a string is a valid public key
    pub fn is_valid_public_key(pubkey_hex: &str) -> bool {
        KeyUtils::validate_public_key_hex(pubkey_hex)
    }
    
    /// Check if a string is a valid address
    pub fn is_valid_address(address_str: &str) -> bool {
        Address::validate_string(address_str)
    }
    
    /// Generate a random brain key
    pub fn generate_brain_key(word_count: usize) -> EccResult<String> {
        let brain_key = BrainKey::generate(word_count)?;
        Ok(brain_key.words().to_string())
    }
    
    /// Normalize a brain key
    pub fn normalize_brain_key(brain_key: &str) -> String {
        KeyUtils::normalize_brain_key(brain_key)
    }
    
    /// Convert between key formats
    pub fn convert_key_format(key: &str, target_format: KeyFormat) -> EccResult<String> {
        KeyUtils::convert_key_format(key, target_format)
    }
    
    /// Create a secure random seed
    pub fn generate_secure_seed(length: usize) -> Vec<u8> {
        KeyUtils::generate_seed(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecc_key_pair_generation() {
        let (private_key, public_key) = Ecc::generate_key_pair().unwrap();
        assert!(KeyUtils::validate_key_pair(&private_key, &public_key));
    }

    #[test]
    fn test_ecc_brain_key_generation() {
        let brain_key_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (private_key, public_key) = Ecc::key_pair_from_brain_key(brain_key_str).unwrap();
        assert!(KeyUtils::validate_key_pair(&private_key, &public_key));
    }

    #[test]
    fn test_ecc_signing_and_verification() {
        let (private_key, public_key) = Ecc::generate_key_pair().unwrap();
        let message = b"Hello, R-Squared!";
        
        let signature = Ecc::sign_message(&private_key, message).unwrap();
        let is_valid = Ecc::verify_signature(&public_key, message, &signature).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_ecc_address_creation() {
        let (_, public_key) = Ecc::generate_key_pair().unwrap();
        let address = Ecc::create_address(&public_key, "RSQ").unwrap();
        
        assert_eq!(address.prefix(), "RSQ");
        assert!(address.is_valid());
    }

    #[test]
    fn test_ecc_memo_encryption() {
        let (sender_private, sender_public) = Ecc::generate_key_pair().unwrap();
        let (recipient_private, recipient_public) = Ecc::generate_key_pair().unwrap();
        
        let memo = "Secret message";
        let encrypted = Ecc::encrypt_memo(memo, &sender_private, &recipient_public).unwrap();
        let decrypted = Ecc::decrypt_memo(&encrypted, &recipient_private, &sender_public).unwrap();
        
        assert_eq!(memo, decrypted);
    }

    #[test]
    fn test_ecc_address_derivation() {
        let (master_key, _) = Ecc::generate_key_pair().unwrap();
        let addresses = Ecc::derive_addresses(&master_key, "TEST", 5).unwrap();
        
        assert_eq!(addresses.len(), 5);
        
        // All addresses should be different
        for i in 0..addresses.len() {
            for j in i+1..addresses.len() {
                assert_ne!(addresses[i], addresses[j]);
            }
        }
    }

    #[test]
    fn test_ecc_key_set_validation() {
        let (private_key, public_key) = Ecc::generate_key_pair().unwrap();
        let address = Ecc::create_address(&public_key, "RSQ").unwrap();
        
        let is_valid = Ecc::validate_key_set(&private_key, &public_key, &address).unwrap();
        assert!(is_valid);
        
        // Test with wrong address
        let wrong_address = Address::generate_random("RSQ");
        let is_invalid = Ecc::validate_key_set(&private_key, &public_key, &wrong_address).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_ecc_multisig_address() {
        let mut public_keys = Vec::new();
        for _ in 0..3 {
            let (_, public_key) = Ecc::generate_key_pair().unwrap();
            public_keys.push(public_key);
        }
        
        let multisig_address = Ecc::create_multisig_address(&public_keys, 2, "MULTISIG").unwrap();
        assert_eq!(multisig_address.prefix(), "MULTISIG");
    }

    #[test]
    fn test_ecc_public_key_recovery() {
        let (private_key, expected_public_key) = Ecc::generate_key_pair().unwrap();
        let message = b"Recovery test";
        
        let signature = Ecc::sign_message(&private_key, message).unwrap();
        let recovered_public_key = Ecc::recover_public_key(message, &signature).unwrap();
        
        assert_eq!(expected_public_key.to_bytes(), recovered_public_key.to_bytes());
    }

    #[test]
    fn test_ecc_utils() {
        let (private_key, public_key) = Ecc::generate_key_pair().unwrap();
        let wif = private_key.to_wif(true);
        let pubkey_hex = public_key.to_hex();
        let address = Ecc::create_address(&public_key, "RSQ").unwrap();
        let address_str = address.to_string();
        
        assert!(utils::is_valid_wif(&wif));
        assert!(utils::is_valid_public_key(&pubkey_hex));
        assert!(utils::is_valid_address(&address_str));
        
        let brain_key = utils::generate_brain_key(12).unwrap();
        assert!(!brain_key.is_empty());
        
        let normalized = utils::normalize_brain_key("  HELLO   world  ");
        assert_eq!(normalized, "hello world");
    }
}