//! Hash functions for cryptographic operations

use sha2::{Sha256, Sha512, Digest};
use sha1::Sha1;
use sha3::{Sha3_256, Sha3_512};
use ripemd::{Ripemd160, Digest as RipemdDigest};
use hmac::{Hmac, Mac};

/// SHA-1 hash function
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 hash function
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-512 hash function
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-256 hash function
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-512 hash function
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// RIPEMD-160 hash function
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Double SHA-256 hash function (Bitcoin-style)
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Hash160: RIPEMD-160 of SHA-256 (Bitcoin-style address hash)
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA512
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify HMAC-SHA256
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    let computed = hmac_sha256(key, data);
    computed == *expected
}

/// Verify HMAC-SHA512
pub fn verify_hmac_sha512(key: &[u8], data: &[u8], expected: &[u8; 64]) -> bool {
    let computed = hmac_sha512(key, data);
    computed == *expected
}

/// Hash-based Key Derivation Function (HKDF) using SHA-256
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // Extract phase
    let prk = hmac_sha256(salt, ikm);
    
    // Expand phase
    let mut output = Vec::new();
    let mut t = Vec::new();
    let n = (length + 31) / 32; // ceil(length / 32)
    
    for i in 1..=n {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i as u8);
        t = hmac_sha256(&prk, &input).to_vec();
        output.extend_from_slice(&t);
    }
    
    output.truncate(length);
    output
}

/// Merkle tree hash (for blockchain applications)
pub fn merkle_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    sha256(&combined)
}

/// Calculate Merkle root from a list of hashes
pub fn merkle_root(mut hashes: Vec<[u8; 32]>) -> Option<[u8; 32]> {
    if hashes.is_empty() {
        return None;
    }
    
    if hashes.len() == 1 {
        return Some(hashes[0]);
    }
    
    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in hashes.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            next_level.push(merkle_hash(&left, &right));
        }
        
        hashes = next_level;
    }
    
    Some(hashes[0])
}

/// Checksum calculation for addresses and other data
pub fn checksum(data: &[u8], length: usize) -> Vec<u8> {
    let hash = sha256d(data);
    hash[..length.min(hash.len())].to_vec()
}

/// Verify checksum
pub fn verify_checksum(data: &[u8], expected_checksum: &[u8]) -> bool {
    let computed = checksum(data, expected_checksum.len());
    computed == expected_checksum
}

/// Password-based key derivation using PBKDF2 with SHA-256
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    use pbkdf2::pbkdf2;
    let mut output = vec![0u8; length];
    let _=pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output).expect("pbkdf2 error");
    output
}

/// Scrypt key derivation function
pub fn scrypt_hash(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, length: usize) -> Result<Vec<u8>, scrypt::errors::InvalidParams> {
    use scrypt::{scrypt, Params};
    
    let params = Params::new(
        (n as f64).log2() as u8,
        r,
        p,
        length,
    )?;
    
    let mut output = vec![0u8; length];
    scrypt(password, salt, &params, &mut output)
        .map_err(|_| scrypt::errors::InvalidParams)?;
    Ok(output)
}

/// Hash utilities for common operations
pub mod utils {
    use super::*;
    
    /// Hash a string using SHA-256
    pub fn hash_string(s: &str) -> [u8; 32] {
        sha256(s.as_bytes())
    }
    
    /// Hash multiple data pieces together
    pub fn hash_multiple(data_pieces: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for piece in data_pieces {
            hasher.update(piece);
        }
        hasher.finalize().into()
    }
    
    /// Create a hash chain (hash of hash of hash...)
    pub fn hash_chain(data: &[u8], iterations: usize) -> [u8; 32] {
        let mut result = sha256(data);
        for _ in 1..iterations {
            result = sha256(&result);
        }
        result
    }
    
    /// Time-based hash for proof-of-work or rate limiting
    pub fn time_hash(data: &[u8], timestamp: u64) -> [u8; 32] {
        let mut input = data.to_vec();
        input.extend_from_slice(&timestamp.to_be_bytes());
        sha256(&input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
        
        // Test known vector
        let expected = hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();
        assert_eq!(hash.to_vec(), expected);
    }

    #[test]
    fn test_sha256d() {
        let data = b"hello";
        let hash = sha256d(data);
        assert_eq!(hash.len(), 32);
        
        // Should be different from single SHA-256
        let single_hash = sha256(data);
        assert_ne!(hash, single_hash);
    }

    #[test]
    fn test_hash160() {
        let data = b"test data";
        let hash = hash160(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let data = b"message";
        let hmac = hmac_sha256(key, data);
        assert_eq!(hmac.len(), 32);
        
        // Verify the HMAC
        assert!(verify_hmac_sha256(key, data, &hmac));
        assert!(!verify_hmac_sha256(b"wrong key", data, &hmac));
    }

    #[test]
    fn test_merkle_root() {
        let hashes = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];
        
        let root = merkle_root(hashes).unwrap();
        assert_eq!(root.len(), 32);
        
        // Empty case
        assert!(merkle_root(vec![]).is_none());
        
        // Single hash case
        let single = vec![[5u8; 32]];
        let single_root = merkle_root(single).unwrap();
        assert_eq!(single_root, [5u8; 32]);
    }

    #[test]
    fn test_checksum() {
        let data = b"test data for checksum";
        let cs = checksum(data, 4);
        assert_eq!(cs.len(), 4);
        
        assert!(verify_checksum(data, &cs));
        assert!(!verify_checksum(b"different data", &cs));
    }

    #[test]
    fn test_pbkdf2() {
        let password = b"password";
        let salt = b"salt";
        let derived = pbkdf2_sha256(password, salt, 1000, 32);
        assert_eq!(derived.len(), 32);
        
        // Same inputs should produce same output
        let derived2 = pbkdf2_sha256(password, salt, 1000, 32);
        assert_eq!(derived, derived2);
        
        // Different salt should produce different output
        let derived3 = pbkdf2_sha256(password, b"different salt", 1000, 32);
        assert_ne!(derived, derived3);
    }

    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let derived = hkdf_sha256(ikm, salt, info, 32);
        assert_eq!(derived.len(), 32);
        
        // Different info should produce different output
        let derived2 = hkdf_sha256(ikm, salt, b"different info", 32);
        assert_ne!(derived, derived2);
    }

    #[test]
    fn test_hash_utils() {
        let s = "test string";
        let hash = utils::hash_string(s);
        assert_eq!(hash.len(), 32);
        
        let data_pieces = vec![b"piece1".as_slice(), b"piece2".as_slice()];
        let multi_hash = utils::hash_multiple(&data_pieces);
        assert_eq!(multi_hash.len(), 32);
        
        let chain_hash = utils::hash_chain(b"data", 5);
        assert_eq!(chain_hash.len(), 32);
        
        let time_hash = utils::time_hash(b"data", 1234567890);
        assert_eq!(time_hash.len(), 32);
    }

    #[test]
    fn test_all_hash_functions() {
        let data = b"test data";
        
        assert_eq!(sha1(data).len(), 20);
        assert_eq!(sha256(data).len(), 32);
        assert_eq!(sha512(data).len(), 64);
        assert_eq!(sha3_256(data).len(), 32);
        assert_eq!(sha3_512(data).len(), 64);
        assert_eq!(ripemd160(data).len(), 20);
    }
}