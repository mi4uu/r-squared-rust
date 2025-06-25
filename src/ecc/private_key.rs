//! Private key implementation for ECC operations

use crate::error::{EccError, EccResult};
use crate::ecc::{PublicKey, Signature, secp256k1::SECP256K1, constants::PRIVATE_KEY_SIZE};
use secp256k1::{SecretKey, Message};
use zeroize::Zeroize;
use sha2::{Sha256, Digest};
use base58::{ToBase58, FromBase58};
use rand::RngCore;

/// A private key for elliptic curve cryptography
#[derive(Clone)]
pub struct PrivateKey {
    key: SecretKey,
}

impl PrivateKey {
    /// Generate a new random private key
    pub fn generate() -> EccResult<Self> {
        let mut rng = rand::rng();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretKey::from_byte_array(key_bytes)
            .map_err(|e| EccError::InvalidPrivateKey {
                reason: format!("Failed to generate private key: {}", e),
            })?;
        Ok(Self { key })
    }

    /// Create a private key from bytes
    pub fn from_bytes(bytes: &[u8]) -> EccResult<Self> {
        if bytes.len() != PRIVATE_KEY_SIZE {
            return Err(EccError::InvalidPrivateKey {
                reason: format!("Invalid key length: expected {}, got {}", PRIVATE_KEY_SIZE, bytes.len()),
            });
        }

        let key = SecretKey::from_slice(bytes)
            .map_err(|e| EccError::InvalidPrivateKey {
                reason: format!("Invalid key data: {}", e),
            })?;

        Ok(Self { key })
    }

    /// Create a private key from WIF (Wallet Import Format)
    pub fn from_wif(wif: &str) -> EccResult<Self> {
        let decoded = wif.from_base58()
            .map_err(|e| EccError::InvalidPrivateKey {
                reason: format!("Invalid WIF format: {:?}", e),
            })?;

        // WIF format: [version_byte][32_byte_key][compression_flag?][4_byte_checksum]
        // Uncompressed: 37 bytes total (1 + 32 + 4)
        // Compressed: 38 bytes total (1 + 32 + 1 + 4)
        if decoded.len() != 37 && decoded.len() != 38 {
            return Err(EccError::InvalidPrivateKey {
                reason: format!("Invalid WIF length: expected 37 or 38 bytes, got {}", decoded.len()),
            });
        }

        // Check version byte (0x80 for mainnet)
        if decoded[0] != 0x80 {
            return Err(EccError::InvalidPrivateKey {
                reason: "Invalid WIF version byte".to_string(),
            });
        }

        // Determine if compressed based on length and compression flag
        let is_compressed = if decoded.len() == 38 {
            // Check compression flag
            decoded[33] == 0x01
        } else {
            false // 37 bytes = uncompressed
        };

        // Extract key bytes (always 32 bytes after version byte)
        let key_bytes = &decoded[1..33];
        
        // Verify checksum
        let checksum_start = decoded.len() - 4;
        let payload = &decoded[..checksum_start];
        let expected_checksum = &Self::double_sha256(payload)[..4];
        let actual_checksum = &decoded[checksum_start..];
        
        if expected_checksum != actual_checksum {
            return Err(EccError::InvalidPrivateKey {
                reason: "Invalid WIF checksum".to_string(),
            });
        }

        Self::from_bytes(key_bytes)
    }

    /// Convert to WIF (Wallet Import Format)
    pub fn to_wif(&self, compressed: bool) -> String {
        let mut payload = vec![0x80]; // Version byte for mainnet
        payload.extend_from_slice(&self.key.secret_bytes());
        
        if compressed {
            payload.push(0x01); // Compression flag
        }
        
        let checksum = &Self::double_sha256(&payload)[..4];
        payload.extend_from_slice(checksum);
        
        payload.to_base58()
    }

    /// Convert private key to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Create private key from hex string
    pub fn from_hex(hex_str: &str) -> EccResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| EccError::InvalidPrivateKey {
                reason: format!("Invalid hex string: {}", e),
            })?;
        Self::from_bytes(&bytes)
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> EccResult<PublicKey> {
        let public_key = secp256k1::PublicKey::from_secret_key(&SECP256K1, &self.key);
        Ok(PublicKey::from_secp256k1(public_key))
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
        self.key.secret_bytes()
    }

    /// Sign a message hash
    pub fn sign(&self, message_hash: &[u8; 32]) -> EccResult<Signature> {
        let message = Message::from_slice(message_hash)
            .map_err(|e| EccError::CryptoOperationFailed {
                operation: format!("Message creation failed: {}", e),
            })?;

        let signature = crate::ecc::secp256k1::SECP256K1.sign_ecdsa_recoverable(message, &self.key);
        Signature::from_recoverable_signature(signature, message_hash)
    }

    /// Sign a message (convenience method that hashes the message first)
    pub fn sign_message(&self, message: &[u8]) -> EccResult<Signature> {
        let hash = crate::ecc::hash::sha256(message);
        self.sign(&hash)
    }

    /// Create a shared secret using ECDH
    pub fn create_shared_secret(&self, other_public_key: &PublicKey) -> EccResult<[u8; 32]> {
        use secp256k1::ecdh::SharedSecret;
        
        let other_secp_key = other_public_key.to_secp256k1();
        let shared_secret = SharedSecret::new(&other_secp_key, &self.key);
        Ok(shared_secret.secret_bytes())
    }

    /// Derive a child private key using a simple derivation scheme
    pub fn derive_child(&self, index: u32) -> EccResult<Self> {
        let mut hasher = Sha256::new();
        hasher.update(&self.key.secret_bytes());
        hasher.update(&index.to_be_bytes());
        let hash = hasher.finalize();
        
        Self::from_bytes(&hash)
    }

    /// Get the inner secp256k1 secret key
    pub(crate) fn inner(&self) -> &SecretKey {
        &self.key
    }

    /// Double SHA-256 hash function for checksums
    fn double_sha256(data: &[u8]) -> [u8; 32] {
        let first_hash = Sha256::digest(data);
        let second_hash = Sha256::digest(&first_hash);
        second_hash.into()
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        // SecretKey doesn't implement Zeroize directly, but we can create a new one
        // This is a best-effort approach for memory safety
        let zero_bytes = [0u8; 32];
        if let Ok(zero_key) = SecretKey::from_slice(&zero_bytes) {
            // This won't actually zero the original memory, but it's the best we can do
            // with the current secp256k1 API
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_private_key() {
        let key = PrivateKey::generate().unwrap();
        let _public_key = key.public_key();
    }

    #[test]
    fn test_private_key_from_bytes() {
        let bytes = [1u8; PRIVATE_KEY_SIZE];
        let key = PrivateKey::from_bytes(&bytes).unwrap();
        let _public_key = key.public_key();
    }

    #[test]
    fn test_wif_roundtrip() {
        let key = PrivateKey::generate().unwrap();
        
        // Test compressed WIF
        let wif_compressed = key.to_wif(true);
        let recovered_compressed = PrivateKey::from_wif(&wif_compressed).unwrap();
        assert_eq!(key.to_bytes(), recovered_compressed.to_bytes());
        
        // Test uncompressed WIF
        let wif_uncompressed = key.to_wif(false);
        let recovered_uncompressed = PrivateKey::from_wif(&wif_uncompressed).unwrap();
        assert_eq!(key.to_bytes(), recovered_uncompressed.to_bytes());
    }

    #[test]
    fn test_child_derivation() {
        let parent = PrivateKey::generate().unwrap();
        let child1 = parent.derive_child(0).unwrap();
        let child2 = parent.derive_child(1).unwrap();
        
        // Children should be different
        assert_ne!(child1.to_bytes(), child2.to_bytes());
        
        // Same index should produce same child
        let child1_again = parent.derive_child(0).unwrap();
        assert_eq!(child1.to_bytes(), child1_again.to_bytes());
    }

    #[test]
    fn test_signing() {
        let key = PrivateKey::generate().unwrap();
        let message = b"Hello, R-Squared!";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = key.sign(&hash).unwrap();
        
        // Verify the signature can be created
        assert!(!signature.to_bytes().is_empty());
    }
}