//! Public key implementation for ECC operations

use crate::error::{EccError, EccResult};
use crate::ecc::{Address, Signature, secp256k1::SECP256K1, constants::{COMPRESSED_PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE}};
use secp256k1::{PublicKey as Secp256k1PublicKey, Message};
use sha2::{Sha256, Digest};
use ripemd::{Ripemd160, Digest as RipemdDigest};

/// A public key for elliptic curve cryptography
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    key: Secp256k1PublicKey,
}

impl PublicKey {
    /// Create a public key from a secp256k1 public key
    pub(crate) fn from_secp256k1(key: Secp256k1PublicKey) -> Self {
        Self { key }
    }

    /// Create a public key from compressed bytes
    pub fn from_bytes(bytes: &[u8]) -> EccResult<Self> {
        let key = Secp256k1PublicKey::from_slice(bytes)
            .map_err(|e| EccError::InvalidPublicKey {
                reason: format!("Invalid public key data: {}", e),
            })?;
        Ok(Self { key })
    }

    /// Create a public key from hex string
    pub fn from_hex(hex: &str) -> EccResult<Self> {
        let bytes = hex::decode(hex)
            .map_err(|e| EccError::InvalidPublicKey {
                reason: format!("Invalid hex format: {}", e),
            })?;
        Self::from_bytes(&bytes)
    }

    /// Convert to compressed bytes
    pub fn to_bytes(&self) -> [u8; COMPRESSED_PUBLIC_KEY_SIZE] {
        self.key.serialize()
    }

    /// Convert to uncompressed bytes
    pub fn to_uncompressed_bytes(&self) -> [u8; UNCOMPRESSED_PUBLIC_KEY_SIZE] {
        self.key.serialize_uncompressed()
    }

    /// Convert to hex string (compressed)
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Convert to hex string (uncompressed)
    pub fn to_hex_uncompressed(&self) -> String {
        hex::encode(self.to_uncompressed_bytes())
    }

    /// Generate an R-Squared address from this public key
    pub fn to_address(&self, address_prefix: &str) -> EccResult<Address> {
        Address::from_public_key(self, address_prefix)
    }

    /// Generate a legacy Bitcoin-style address
    pub fn to_legacy_address(&self, version_byte: u8) -> EccResult<Address> {
        Address::from_public_key_legacy(self, version_byte)
    }

    /// Verify a signature against a message hash
    pub fn verify(&self, message_hash: &[u8; 32], signature: &Signature) -> EccResult<bool> {
        let message = Message::from_slice(message_hash)
            .map_err(|e| EccError::CryptoOperationFailed {
                operation: format!("Message creation failed: {}", e),
            })?;

        signature.verify(&message, self)
    }

    /// Verify a signature against a message and signature (alternative interface)
    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> EccResult<bool> {
        let message_hash = crate::ecc::hash::sha256(message);
        self.verify(&message_hash, signature)
    }

    /// Get the public key hash (RIPEMD160 of SHA256)
    pub fn hash160(&self) -> [u8; 20] {
        let sha256_hash = Sha256::digest(&self.to_bytes());
        let ripemd_hash = Ripemd160::digest(&sha256_hash);
        ripemd_hash.into()
    }

    /// Get the SHA256 hash of the public key
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.to_bytes()).into()
    }

    /// Check if this public key is compressed
    pub fn is_compressed(&self) -> bool {
        // secp256k1 library always stores keys in compressed format internally
        // This is more about the serialization format preference
        true
    }

    /// Combine this public key with another (for multi-signature schemes)
    pub fn combine(&self, other: &PublicKey) -> EccResult<PublicKey> {
        let combined = self.key.combine(&other.key)
            .map_err(|e| EccError::CryptoOperationFailed {
                operation: format!("Public key combination failed: {}", e),
            })?;
        Ok(PublicKey::from_secp256k1(combined))
    }

    /// Tweak this public key by adding a scalar
    pub fn tweak_add(&self, tweak: &[u8; 32]) -> EccResult<PublicKey> {
        use secp256k1::Scalar;
        let scalar = Scalar::from_be_bytes(*tweak)
            .map_err(|e| EccError::CryptoOperationFailed {
                operation: format!("Invalid scalar: {}", e),
            })?;
        let tweaked = self.key.add_exp_tweak(&SECP256K1, &scalar)
            .map_err(|e| EccError::CryptoOperationFailed {
                operation: format!("Public key tweak failed: {}", e),
            })?;
        Ok(PublicKey::from_secp256k1(tweaked))
    }

    /// Get the inner secp256k1 public key
    pub(crate) fn inner(&self) -> &Secp256k1PublicKey {
        &self.key
    }

    /// Convert to secp256k1 public key
    pub fn to_secp256k1(&self) -> Secp256k1PublicKey {
        self.key
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::str::FromStr for PublicKey {
    type Err = EccError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PrivateKey;

    #[test]
    fn test_public_key_from_private() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        let bytes = public_key.to_bytes();
        let recovered = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let hex = public_key.to_hex();
        let recovered = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_public_key_hash160() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let hash160 = public_key.hash160();
        assert_eq!(hash160.len(), 20);
    }

    #[test]
    fn test_public_key_combine() {
        let private_key1 = PrivateKey::generate().unwrap();
        let private_key2 = PrivateKey::generate().unwrap();
        let public_key1 = private_key1.public_key().unwrap();
        let public_key2 = private_key2.public_key().unwrap();
        
        let combined = public_key1.combine(&public_key2).unwrap();
        assert_ne!(combined, public_key1);
        assert_ne!(combined, public_key2);
    }

    #[test]
    fn test_public_key_tweak() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let tweak = [1u8; 32];
        let tweaked = public_key.tweak_add(&tweak).unwrap();
        assert_ne!(tweaked, public_key);
    }

    #[test]
    fn test_signature_verification() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let message = b"Hello, R-Squared!";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = private_key.sign(&hash).unwrap();
        let is_valid = public_key.verify(&hash, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_address_generation() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let address = public_key.to_address("RSQ").unwrap();
        assert!(!address.to_string().is_empty());
    }
}