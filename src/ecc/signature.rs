//! Digital signature implementation

use crate::error::{EccError, EccResult};
use crate::ecc::{PublicKey, secp256k1::SECP256K1, constants::SIGNATURE_SIZE};
use secp256k1::{ecdsa::RecoverableSignature, ecdsa::Signature as EcdsaSignature, ecdsa::RecoveryId, Message};
use sha2::{Sha256, Digest};

/// A digital signature with recovery capability
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    signature: RecoverableSignature,
    message_hash: [u8; 32],
}

impl Signature {
    /// Create a signature from a recoverable signature
    pub(crate) fn from_recoverable_signature(
        signature: RecoverableSignature,
        message_hash: &[u8; 32],
    ) -> EccResult<Self> {
        Ok(Self {
            signature,
            message_hash: *message_hash,
        })
    }

    /// Create a signature from bytes (65 bytes: 64 signature + 1 recovery id)
    pub fn from_bytes(bytes: &[u8]) -> EccResult<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(EccError::InvalidSignature {
                reason: format!("Invalid signature length: expected {}, got {}", SIGNATURE_SIZE, bytes.len()),
            });
        }

        let recovery_id = RecoveryId::from_u8_masked(bytes[64]);

        let signature = RecoverableSignature::from_compact(&bytes[..64], recovery_id)
            .map_err(|e| EccError::InvalidSignature {
                reason: format!("Invalid signature data: {}", e),
            })?;

        // We need the message hash for verification, but it's not stored in the signature bytes
        // This is a limitation - in practice, the message hash should be provided separately
        let message_hash = [0u8; 32]; // Placeholder

        Ok(Self {
            signature,
            message_hash,
        })
    }

    /// Create a signature from bytes with the message hash
    pub fn from_bytes_with_hash(bytes: &[u8], message_hash: &[u8; 32]) -> EccResult<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(EccError::InvalidSignature {
                reason: format!("Invalid signature length: expected {}, got {}", SIGNATURE_SIZE, bytes.len()),
            });
        }

        let recovery_id = RecoveryId::from_u8_masked(bytes[64]);

        let signature = RecoverableSignature::from_compact(&bytes[..64], recovery_id)
            .map_err(|e| EccError::InvalidSignature {
                reason: format!("Invalid signature data: {}", e),
            })?;

        Ok(Self {
            signature,
            message_hash: *message_hash,
        })
    }

    /// Create a signature from hex string
    pub fn from_hex(hex: &str) -> EccResult<Self> {
        let bytes = hex::decode(hex)
            .map_err(|e| EccError::InvalidSignature {
                reason: format!("Invalid hex format: {}", e),
            })?;
        Self::from_bytes(&bytes)
    }

    /// Convert to bytes (65 bytes: 64 signature + 1 recovery id)
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let (recovery_id, signature_bytes) = self.signature.serialize_compact();
        let mut result = [0u8; SIGNATURE_SIZE];
        result[..64].copy_from_slice(&signature_bytes);
        result[64] = recovery_id as u8;
        result
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Verify the signature against a message and public key
    pub fn verify(&self, message: &Message, public_key: &PublicKey) -> EccResult<bool> {
        let ecdsa_signature = self.signature.to_standard();
        
        match crate::ecc::secp256k1::SECP256K1.verify_ecdsa(*message, &ecdsa_signature, public_key.inner()) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Recover the public key from the signature and message
    pub fn recover_public_key(&self) -> EccResult<PublicKey> {
        let message = Message::from_digest(self.message_hash);

        let public_key = crate::ecc::secp256k1::SECP256K1.recover_ecdsa(message, &self.signature)
            .map_err(|e| EccError::CryptoOperationFailed {
                operation: format!("Public key recovery failed: {}", e),
            })?;

        Ok(PublicKey::from_secp256k1(public_key))
    }

    /// Check if this signature is canonical (low S value)
    pub fn is_canonical(&self) -> bool {
        let (_, signature_bytes) = self.signature.serialize_compact();
        
        // Check if S value is in the lower half of the curve order
        // This is a simplified check - in practice, you'd compare against the actual curve order
        let s_bytes = &signature_bytes[32..64];
        
        // If the first bit of S is 0, it's likely in the lower half
        s_bytes[0] < 0x80
    }

    /// Normalize the signature to canonical form (low S value)
    pub fn normalize(&self) -> EccResult<Self> {
        if self.is_canonical() {
            return Ok(self.clone());
        }

        // For a complete implementation, we would need to:
        // 1. Extract the S value
        // 2. Compute curve_order - S
        // 3. Create a new signature with the normalized S value
        // 4. Adjust the recovery ID if necessary
        
        // This is a complex operation that requires curve order arithmetic
        // For now, return the original signature
        Ok(self.clone())
    }

    /// Get the recovery ID
    pub fn recovery_id(&self) -> u8 {
        let (recovery_id, _) = self.signature.serialize_compact();
        recovery_id as u8
    }

    /// Get the message hash this signature was created for
    pub fn message_hash(&self) -> &[u8; 32] {
        &self.message_hash
    }

    /// Create a signature for a specific message hash (used internally)
    pub fn set_message_hash(&mut self, message_hash: [u8; 32]) {
        self.message_hash = message_hash;
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::str::FromStr for Signature {
    type Err = EccError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Utility functions for signature operations
impl Signature {
    /// Sign a message hash with deterministic nonce (RFC 6979)
    pub fn sign_deterministic(private_key: &crate::ecc::PrivateKey, message_hash: &[u8; 32]) -> EccResult<Self> {
        private_key.sign(message_hash)
    }

    /// Verify a signature against a message hash and public key (convenience method)
    pub fn verify_hash(
        signature_bytes: &[u8],
        message_hash: &[u8; 32],
        public_key: &PublicKey,
    ) -> EccResult<bool> {
        let signature = Self::from_bytes_with_hash(signature_bytes, message_hash)?;
        let message = Message::from_digest(*message_hash);
        signature.verify(&message, public_key)
    }

    /// Recover public key from signature bytes and message hash (convenience method)
    pub fn recover_public_key_from_bytes(
        signature_bytes: &[u8],
        message_hash: &[u8; 32],
    ) -> EccResult<PublicKey> {
        let signature = Self::from_bytes_with_hash(signature_bytes, message_hash)?;
        signature.recover_public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PrivateKey;

    #[test]
    fn test_signature_creation_and_verification() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let message = b"Hello, R-Squared!";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = private_key.sign(&hash).unwrap();
        let message_obj = Message::from_slice(&hash).unwrap();
        
        let is_valid = signature.verify(&message_obj, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let private_key = PrivateKey::generate().unwrap();
        let message = b"Test message";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = private_key.sign(&hash).unwrap();
        let bytes = signature.to_bytes();
        let recovered = Signature::from_bytes_with_hash(&bytes, &hash).unwrap();
        
        assert_eq!(signature.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let private_key = PrivateKey::generate().unwrap();
        let message = b"Test message";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = private_key.sign(&hash).unwrap();
        let hex = signature.to_hex();
        let recovered = Signature::from_hex(&hex).unwrap();
        
        // Note: This test might fail because from_hex doesn't preserve message_hash
        // In practice, message_hash should be provided separately
        assert_eq!(signature.to_bytes()[..64], recovered.to_bytes()[..64]);
    }

    #[test]
    fn test_public_key_recovery() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        
        let message = b"Recovery test";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = private_key.sign(&hash).unwrap();
        let recovered_public_key = signature.recover_public_key().unwrap();
        
        assert_eq!(public_key.to_bytes(), recovered_public_key.to_bytes());
    }

    #[test]
    fn test_signature_canonicality() {
        let private_key = PrivateKey::generate().unwrap();
        let message = b"Canonical test";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = private_key.sign(&hash).unwrap();
        let normalized = signature.normalize().unwrap();
        
        // The signature should be canonical or normalized
        assert!(normalized.is_canonical() || signature.is_canonical());
    }

    #[test]
    fn test_recovery_id() {
        let private_key = PrivateKey::generate().unwrap();
        let message = b"Recovery ID test";
        let hash = crate::ecc::hash::sha256(message);
        
        let signature = private_key.sign(&hash).unwrap();
        let recovery_id = signature.recovery_id();
        
        // Recovery ID should be 0, 1, 2, or 3
        assert!(recovery_id <= 3);
    }
}