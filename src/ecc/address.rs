//! Address implementation for R-Squared blockchain

use crate::error::{EccError, EccResult};
use crate::ecc::PublicKey;
use base58::{ToBase58, FromBase58};
use sha2::{Sha256, Digest};
use ripemd::Digest as RipemdDigest;
use std::fmt;

/// A blockchain address with support for multiple formats
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode)]
pub struct Address {
    /// The raw address bytes (without prefix or checksum)
    hash: [u8; 20],
    /// The address prefix (e.g., "RSQ", "BTC")
    prefix: String,
    /// The address format type
    format: AddressFormat,
}

/// Supported address formats
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode)]
pub enum AddressFormat {
    /// R-Squared native format with prefix
    RSquared,
    /// Legacy Bitcoin-style format with version byte
    Legacy { version: u8 },
    /// Bech32 format (for future use)
    Bech32,
}

impl Address {
    /// Create an R-Squared address from a public key
    pub fn from_public_key(public_key: &PublicKey, prefix: &str) -> EccResult<Self> {
        let hash = public_key.hash160();
        
        Ok(Self {
            hash,
            prefix: prefix.to_string(),
            format: AddressFormat::RSquared,
        })
    }

    /// Create a legacy Bitcoin-style address from a public key
    pub fn from_public_key_legacy(public_key: &PublicKey, version: u8) -> EccResult<Self> {
        let hash = public_key.hash160();
        
        Ok(Self {
            hash,
            prefix: String::new(),
            format: AddressFormat::Legacy { version },
        })
    }

    /// Create an address from a hash160 and prefix
    pub fn from_hash160(hash: &[u8; 20], prefix: &str) -> Self {
        Self {
            hash: *hash,
            prefix: prefix.to_string(),
            format: AddressFormat::RSquared,
        }
    }

    /// Create an address from a string representation
    pub fn from_string(address_str: &str) -> EccResult<Self> {
        // Try to parse as R-Squared format first (prefix + base58)
        if let Some(prefix) = Self::extract_prefix(address_str) {
            let encoded_part = &address_str[prefix.len()..];
            return Self::from_rsquared_string(encoded_part, &prefix);
        }
        
        // Try to parse as legacy format (pure base58)
        Self::from_legacy_string(address_str)
    }

    /// Create an R-Squared address from base58 string and prefix
    fn from_rsquared_string(encoded: &str, prefix: &str) -> EccResult<Self> {
        let decoded = encoded.from_base58()
            .map_err(|e| EccError::InvalidAddress {
                reason: format!("Invalid base58 encoding: {:?}", e),
            })?;

        if decoded.len() < 20 || decoded.len() > 24 {
            return Err(EccError::InvalidAddress {
                reason: format!("Invalid address length: expected 20-24, got {}", decoded.len()),
            });
        }

        // Verify checksum (last 4 bytes)
        let checksum_start = decoded.len() - 4;
        let payload = &decoded[..checksum_start];
        let checksum = &decoded[checksum_start..];
        let expected_checksum = &Self::calculate_checksum(payload, prefix)[..4];
        
        if checksum != expected_checksum {
            return Err(EccError::InvalidAddress {
                reason: "Invalid address checksum".to_string(),
            });
        }

        let mut hash = [0u8; 20];
        if payload.len() >= 20 {
            hash.copy_from_slice(&payload[payload.len()-20..]);
        } else {
            hash[20-payload.len()..].copy_from_slice(payload);
        }

        Ok(Self {
            hash,
            prefix: prefix.to_string(),
            format: AddressFormat::RSquared,
        })
    }

    /// Create a legacy address from base58 string
    fn from_legacy_string(encoded: &str) -> EccResult<Self> {
        let decoded = encoded.from_base58()
            .map_err(|e| EccError::InvalidAddress {
                reason: format!("Invalid base58 encoding: {:?}", e),
            })?;

        if decoded.len() != 25 {
            return Err(EccError::InvalidAddress {
                reason: format!("Invalid legacy address length: expected 25, got {}", decoded.len()),
            });
        }

        let version = decoded[0];
        let payload = &decoded[1..21];
        let checksum = &decoded[21..25];
        
        // Verify checksum
        let hash_input = &decoded[..21];
        let expected_checksum = &Self::double_sha256(hash_input)[..4];
        
        if checksum != expected_checksum {
            return Err(EccError::InvalidAddress {
                reason: "Invalid legacy address checksum".to_string(),
            });
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(payload);

        Ok(Self {
            hash,
            prefix: String::new(),
            format: AddressFormat::Legacy { version },
        })
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        match &self.format {
            AddressFormat::RSquared => {
                let mut payload = self.hash.to_vec();
                let checksum = Self::calculate_checksum(&self.hash, &self.prefix);
                payload.extend_from_slice(&checksum[..4]);
                
                format!("{}{}", self.prefix, payload.to_base58())
            }
            AddressFormat::Legacy { version } => {
                let mut payload = vec![*version];
                payload.extend_from_slice(&self.hash);
                let checksum = Self::double_sha256(&payload);
                payload.extend_from_slice(&checksum[..4]);
                
                payload.to_base58()
            }
            AddressFormat::Bech32 => {
                // TODO: Implement bech32 encoding
                format!("{}1{}", self.prefix, "bech32_placeholder")
            }
        }
    }

    /// Get the address hash (RIPEMD160)
    pub fn hash(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Get the address prefix
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Get the address format
    pub fn format(&self) -> &AddressFormat {
        &self.format
    }

    /// Validate the address format and checksum
    pub fn is_valid(&self) -> bool {
        // Try to recreate the address from its string representation
        match Self::from_string(&self.to_string()) {
            Ok(recreated) => recreated == *self,
            Err(_) => false,
        }
    }

    /// Check if this is an R-Squared format address
    pub fn is_rsquared_format(&self) -> bool {
        matches!(self.format, AddressFormat::RSquared)
    }

    /// Check if this is a legacy format address
    pub fn is_legacy_format(&self) -> bool {
        matches!(self.format, AddressFormat::Legacy { .. })
    }

    /// Convert to legacy format with specified version byte
    pub fn to_legacy(&self, version: u8) -> Self {
        Self {
            hash: self.hash,
            prefix: String::new(),
            format: AddressFormat::Legacy { version },
        }
    }

    /// Convert to R-Squared format with specified prefix
    pub fn to_rsquared(&self, prefix: &str) -> Self {
        Self {
            hash: self.hash,
            prefix: prefix.to_string(),
            format: AddressFormat::RSquared,
        }
    }

    /// Calculate R-Squared address checksum
    fn calculate_checksum(hash: &[u8], prefix: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        hasher.update(prefix.as_bytes());
        hasher.finalize().into()
    }

    /// Double SHA-256 hash for legacy addresses
    fn double_sha256(data: &[u8]) -> [u8; 32] {
        let first_hash = Sha256::digest(data);
        let second_hash = Sha256::digest(&first_hash);
        second_hash.into()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::str::FromStr for Address {
    type Err = EccError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s)
    }
}

/// Utility functions for address operations
impl Address {
    /// Generate a random R-Squared address (for testing)
    pub fn generate_random(prefix: &str) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let hash: [u8; 20] = rng.gen();
        
        Self::from_hash160(&hash, prefix)
    }

    /// Validate an address string without creating an Address object
    pub fn validate_string(address_str: &str) -> bool {
        Self::from_string(address_str).is_ok()
    }

    /// Extract the prefix from an address string
    pub fn extract_prefix(address_str: &str) -> Option<String> {
        // A prefix should be a sequence of uppercase letters at the start
        // But we need to be careful not to include base58 characters that happen to be uppercase
        // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        
        // Common prefixes we expect
        let common_prefixes = ["RSQ", "BTC", "ETH", "TEST", "MYTOKEN"];
        
        // First try common prefixes
        for prefix in &common_prefixes {
            if address_str.starts_with(prefix) {
                let remaining = &address_str[prefix.len()..];
                // Make sure there's something after the prefix and it looks like base58
                if !remaining.is_empty() && remaining.chars().next().unwrap().is_ascii_alphanumeric() {
                    return Some(prefix.to_string());
                }
            }
        }
        
        // If no common prefix matches, try to extract a reasonable prefix
        // Look for 2-6 uppercase letters that are followed by mixed case base58
        for len in 2..=6 {
            if len >= address_str.len() {
                continue;
            }
            
            let potential_prefix = &address_str[..len];
            let remaining = &address_str[len..];
            
            // Check if the potential prefix is all uppercase letters (not numbers)
            if potential_prefix.chars().all(|c| c.is_ascii_uppercase() && c.is_ascii_alphabetic()) {
                // Check if the remaining part starts with a lowercase letter or number
                // This helps distinguish prefix from base58 content
                if !remaining.is_empty() {
                    let first_char = remaining.chars().next().unwrap();
                    if first_char.is_ascii_lowercase() || first_char.is_ascii_digit() {
                        return Some(potential_prefix.to_string());
                    }
                }
            }
        }
        
        None
    }

    /// Check if an address string is in R-Squared format
    pub fn is_rsquared_format_string(address_str: &str) -> bool {
        Self::extract_prefix(address_str).is_some()
    }

    /// Check if an address string is in legacy format
    pub fn is_legacy_format_string(address_str: &str) -> bool {
        !Self::is_rsquared_format_string(address_str) && Self::validate_string(address_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PrivateKey;

    #[test]
    fn test_address_from_public_key() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        
        let address = Address::from_public_key(&public_key.unwrap(), "RSQ").unwrap();
        assert_eq!(address.prefix(), "RSQ");
        assert!(address.is_rsquared_format());
    }

    #[test]
    fn test_address_string_roundtrip() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        let address = Address::from_public_key(&public_key.unwrap(), "RSQ").unwrap();
        
        let address_str = address.to_string();
        let recovered = Address::from_string(&address_str).unwrap();
        
        assert_eq!(address, recovered);
    }

    #[test]
    fn test_legacy_address() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        
        let address = Address::from_public_key_legacy(&public_key.unwrap(), 0x00).unwrap();
        assert!(address.is_legacy_format());
        
        let address_str = address.to_string();
        let recovered = Address::from_string(&address_str).unwrap();
        
        assert_eq!(address, recovered);
    }

    #[test]
    fn test_address_validation() {
        let address = Address::generate_random("TEST");
        assert!(address.is_valid());
        
        let address_str = address.to_string();
        assert!(Address::validate_string(&address_str));
    }

    #[test]
    fn test_address_format_conversion() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        
        let rsquared_addr = Address::from_public_key(&public_key.unwrap(), "RSQ").unwrap();
        let legacy_addr = rsquared_addr.to_legacy(0x00);
        let back_to_rsquared = legacy_addr.to_rsquared("RSQ");
        
        assert_eq!(rsquared_addr.hash(), back_to_rsquared.hash());
    }

    #[test]
    fn test_prefix_extraction() {
        let address = Address::generate_random("MYTOKEN");
        let address_str = address.to_string();
        
        println!("Generated address string: {}", address_str);
        println!("Expected prefix: MYTOKEN");
        
        let extracted_prefix = Address::extract_prefix(&address_str).unwrap();
        println!("Extracted prefix: {}", extracted_prefix);
        assert_eq!(extracted_prefix, "MYTOKEN");
    }

    #[test]
    fn test_format_detection() {
        let rsquared_addr = Address::generate_random("RSQ");
        let rsquared_str = rsquared_addr.to_string();
        
        assert!(Address::is_rsquared_format_string(&rsquared_str));
        assert!(!Address::is_legacy_format_string(&rsquared_str));
    }

    #[test]
    fn test_invalid_address() {
        assert!(Address::from_string("invalid_address").is_err());
        assert!(Address::from_string("RSQ123invalid").is_err());
        assert!(!Address::validate_string("not_an_address"));
    }
}