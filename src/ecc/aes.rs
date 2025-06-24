//! AES encryption/decryption implementation

use crate::error::{EccError, EccResult};
use crate::ecc::hash;
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// AES encryption/decryption utilities
pub struct Aes;

impl Aes {
    /// Encrypt data with AES-256-CBC
    pub fn encrypt(data: &[u8], key: &[u8]) -> EccResult<Vec<u8>> {
        Self::encrypt_with_iv(data, key, None)
    }

    /// Encrypt data with AES-256-CBC using a specific IV
    pub fn encrypt_with_iv(data: &[u8], key: &[u8], iv: Option<&[u8; 16]>) -> EccResult<Vec<u8>> {
        // Derive 256-bit key from input
        let derived_key = Self::derive_key(key);
        
        // Generate or use provided IV
        let iv_bytes = match iv {
            Some(iv) => *iv,
            None => {
                let mut rng = thread_rng();
                rng.gen()
            }
        };

        // Pad data to block size (16 bytes for AES)
        let padded_data = Self::pkcs7_pad(data, 16);

        // Encrypt
        let cipher = Aes256CbcEnc::new(&derived_key.into(), &iv_bytes.into());
        let mut encrypted = padded_data.clone();
        cipher.encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut encrypted, padded_data.len())
            .map_err(|e| EccError::EncryptionError {
                reason: format!("AES encryption failed: {:?}", e),
            })?;

        // Prepend IV to encrypted data
        let mut result = iv_bytes.to_vec();
        result.extend_from_slice(&encrypted);
        
        Ok(result)
    }

    /// Decrypt data with AES-256-CBC
    pub fn decrypt(encrypted_data: &[u8], key: &[u8]) -> EccResult<Vec<u8>> {
        if encrypted_data.len() < 16 {
            return Err(EccError::EncryptionError {
                reason: "Encrypted data too short (missing IV)".to_string(),
            });
        }

        // Extract IV and encrypted data
        let iv = &encrypted_data[..16];
        let ciphertext = &encrypted_data[16..];

        // Derive 256-bit key from input
        let derived_key = Self::derive_key(key);

        // Decrypt
        let cipher = Aes256CbcDec::new(&derived_key.into(), iv.into());
        let mut decrypted = ciphertext.to_vec();
        let decrypted_len = cipher.decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut decrypted)
            .map_err(|e| EccError::EncryptionError {
                reason: format!("AES decryption failed: {:?}", e),
            })?
            .len();

        decrypted.truncate(decrypted_len);
        Ok(decrypted)
    }

    /// Encrypt memo data with checksum validation (R-Squared specific)
    pub fn encrypt_memo(memo: &str, private_key: &[u8], public_key: &[u8]) -> EccResult<Vec<u8>> {
        // Create shared secret using ECDH-like approach
        let shared_secret = Self::create_shared_secret(private_key, public_key)?;
        
        // Add checksum to memo
        let memo_bytes = memo.as_bytes();
        let checksum = hash::sha256(memo_bytes);
        let mut memo_with_checksum = memo_bytes.to_vec();
        memo_with_checksum.extend_from_slice(&checksum[..4]); // 4-byte checksum
        
        // Encrypt with shared secret
        Self::encrypt(&memo_with_checksum, &shared_secret)
    }

    /// Decrypt memo data with checksum validation (R-Squared specific)
    pub fn decrypt_memo(encrypted_memo: &[u8], private_key: &[u8], public_key: &[u8]) -> EccResult<String> {
        // Create shared secret using ECDH-like approach
        let shared_secret = Self::create_shared_secret(private_key, public_key)?;
        
        // Decrypt
        let decrypted = Self::decrypt(encrypted_memo, &shared_secret)?;
        
        if decrypted.len() < 4 {
            return Err(EccError::EncryptionError {
                reason: "Decrypted memo too short for checksum".to_string(),
            });
        }
        
        // Extract memo and checksum
        let memo_len = decrypted.len() - 4;
        let memo_bytes = &decrypted[..memo_len];
        let stored_checksum = &decrypted[memo_len..];
        
        // Verify checksum
        let computed_checksum = &hash::sha256(memo_bytes)[..4];
        if stored_checksum != computed_checksum {
            return Err(EccError::EncryptionError {
                reason: "Memo checksum verification failed".to_string(),
            });
        }
        
        // Convert to string
        String::from_utf8(memo_bytes.to_vec())
            .map_err(|e| EccError::EncryptionError {
                reason: format!("Invalid UTF-8 in decrypted memo: {}", e),
            })
    }

    /// Encrypt data with checksum validation
    pub fn encrypt_with_checksum(key: &[u8], data: &[u8]) -> EccResult<Vec<u8>> {
        // Add checksum to data
        let checksum = hash::sha256(data);
        let mut data_with_checksum = data.to_vec();
        data_with_checksum.extend_from_slice(&checksum[..4]); // 4-byte checksum
        
        // Encrypt with key
        Self::encrypt(&data_with_checksum, key)
    }

    /// Decrypt data with checksum validation
    pub fn decrypt_with_checksum(key: &[u8], encrypted_data: &[u8]) -> EccResult<Vec<u8>> {
        // Decrypt
        let decrypted = Self::decrypt(encrypted_data, key)?;
        
        if decrypted.len() < 4 {
            return Err(EccError::EncryptionError {
                reason: "Decrypted data too short for checksum".to_string(),
            });
        }
        
        // Extract data and checksum
        let data_len = decrypted.len() - 4;
        let data_bytes = &decrypted[..data_len];
        let stored_checksum = &decrypted[data_len..];
        
        // Verify checksum
        let computed_checksum = &hash::sha256(data_bytes)[..4];
        if stored_checksum != computed_checksum {
            return Err(EccError::EncryptionError {
                reason: "Data checksum verification failed".to_string(),
            });
        }
        
        Ok(data_bytes.to_vec())
    }

    /// Encrypt with password-based key derivation
    pub fn encrypt_with_password(data: &[u8], password: &str, salt: Option<&[u8]>) -> EccResult<Vec<u8>> {
        let salt_bytes = match salt {
            Some(s) => s.to_vec(),
            None => {
                let mut rng = thread_rng();
                (0..16).map(|_| rng.gen()).collect()
            }
        };
        
        // Derive key using PBKDF2
        let key = hash::pbkdf2_sha256(password.as_bytes(), &salt_bytes, 10000, 32);
        
        // Encrypt
        let encrypted = Self::encrypt(data, &key)?;
        
        // Prepend salt to result
        let mut result = salt_bytes;
        result.extend_from_slice(&encrypted);
        
        Ok(result)
    }

    /// Decrypt with password-based key derivation
    pub fn decrypt_with_password(encrypted_data: &[u8], password: &str) -> EccResult<Vec<u8>> {
        if encrypted_data.len() < 32 { // 16 bytes salt + 16 bytes IV minimum
            return Err(EccError::EncryptionError {
                reason: "Encrypted data too short (missing salt/IV)".to_string(),
            });
        }
        
        // Extract salt and encrypted data
        let salt = &encrypted_data[..16];
        let encrypted = &encrypted_data[16..];
        
        // Derive key using PBKDF2
        let key = hash::pbkdf2_sha256(password.as_bytes(), salt, 10000, 32);
        
        // Decrypt
        Self::decrypt(encrypted, &key)
    }

    /// Derive a 256-bit key from input using SHA-256
    fn derive_key(input: &[u8]) -> [u8; 32] {
        hash::sha256(input)
    }

    /// Create shared secret for memo encryption (simplified ECDH)
    fn create_shared_secret(private_key: &[u8], public_key: &[u8]) -> EccResult<[u8; 32]> {
        // Simplified shared secret creation
        // In a real implementation, this would use proper ECDH
        let mut combined = private_key.to_vec();
        combined.extend_from_slice(public_key);
        Ok(hash::sha256(&combined))
    }

    /// PKCS#7 padding
    fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(vec![padding_len as u8; padding_len]);
        padded
    }

    /// Remove PKCS#7 padding
    fn pkcs7_unpad(data: &[u8]) -> EccResult<Vec<u8>> {
        if data.is_empty() {
            return Err(EccError::EncryptionError {
                reason: "Cannot unpad empty data".to_string(),
            });
        }
        
        let padding_len = data[data.len() - 1] as usize;
        
        if padding_len == 0 || padding_len > data.len() {
            return Err(EccError::EncryptionError {
                reason: "Invalid padding".to_string(),
            });
        }
        
        // Verify padding
        for i in 0..padding_len {
            if data[data.len() - 1 - i] != padding_len as u8 {
                return Err(EccError::EncryptionError {
                    reason: "Invalid padding bytes".to_string(),
                });
            }
        }
        
        Ok(data[..data.len() - padding_len].to_vec())
    }
}

/// AES key management utilities
pub mod key_utils {
    use super::*;
    
    /// Generate a random AES key
    pub fn generate_key() -> [u8; 32] {
        let mut rng = thread_rng();
        rng.gen()
    }
    
    /// Generate a random IV
    pub fn generate_iv() -> [u8; 16] {
        let mut rng = thread_rng();
        rng.gen()
    }
    
    /// Derive key from password with custom parameters
    pub fn derive_key_from_password(
        password: &str,
        salt: &[u8],
        iterations: u32,
    ) -> [u8; 32] {
        let derived = hash::pbkdf2_sha256(password.as_bytes(), salt, iterations, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        key
    }
    
    /// Create a key from multiple sources (key stretching)
    pub fn stretch_key(sources: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for source in sources {
            hasher.update(source);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let data = b"Hello, R-Squared!";
        let key = b"secret key for testing";
        
        let encrypted = Aes::encrypt(data, key).unwrap();
        let decrypted = Aes::decrypt(&encrypted, key).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_aes_with_custom_iv() {
        let data = b"Test data";
        let key = b"test key";
        let iv = [1u8; 16];
        
        let encrypted = Aes::encrypt_with_iv(data, key, Some(&iv)).unwrap();
        let decrypted = Aes::decrypt(&encrypted, key).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
        
        // IV should be at the beginning
        assert_eq!(&encrypted[..16], iv);
    }

    #[test]
    fn test_memo_encryption() {
        let memo = "This is a secret memo";
        let private_key = [1u8; 32];
        let public_key = [2u8; 33];
        
        let encrypted = Aes::encrypt_memo(memo, &private_key, &public_key).unwrap();
        let decrypted = Aes::decrypt_memo(&encrypted, &private_key, &public_key).unwrap();
        
        assert_eq!(memo, decrypted);
    }

    #[test]
    fn test_password_based_encryption() {
        let data = b"Sensitive data";
        let password = "strong password";
        let salt = [3u8; 16];
        
        let encrypted = Aes::encrypt_with_password(data, password, Some(&salt)).unwrap();
        let decrypted = Aes::decrypt_with_password(&encrypted, password).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_pkcs7_padding() {
        let data = b"test";
        let padded = Aes::pkcs7_pad(data, 16);
        assert_eq!(padded.len() % 16, 0);
        
        let unpadded = Aes::pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data.to_vec());
    }

    #[test]
    fn test_key_utils() {
        let key = key_utils::generate_key();
        assert_eq!(key.len(), 32);
        
        let iv = key_utils::generate_iv();
        assert_eq!(iv.len(), 16);
        
        let password_key = key_utils::derive_key_from_password("password", b"salt", 1000);
        assert_eq!(password_key.len(), 32);
        
        let sources = vec![b"source1".as_slice(), b"source2".as_slice()];
        let stretched = key_utils::stretch_key(&sources);
        assert_eq!(stretched.len(), 32);
    }

    #[test]
    fn test_encryption_errors() {
        // Test decryption with wrong key
        let data = b"test data";
        let key1 = b"key1";
        let key2 = b"key2";
        
        let encrypted = Aes::encrypt(data, key1).unwrap();
        let result = Aes::decrypt(&encrypted, key2);
        assert!(result.is_err());
        
        // Test decryption with too short data
        let short_data = b"short";
        let result = Aes::decrypt(short_data, key1);
        assert!(result.is_err());
    }

    #[test]
    fn test_memo_checksum_validation() {
        let memo = "Test memo";
        let private_key = [1u8; 32];
        let public_key = [2u8; 33];
        
        let mut encrypted = Aes::encrypt_memo(memo, &private_key, &public_key).unwrap();
        
        // Corrupt the encrypted data
        if let Some(last) = encrypted.last_mut() {
            *last = last.wrapping_add(1);
        }
        
        // Decryption should fail due to checksum mismatch
        let result = Aes::decrypt_memo(&encrypted, &private_key, &public_key);
        assert!(result.is_err());
    }
}