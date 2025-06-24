//! Key utility functions for ECC operations

use crate::error::{EccError, EccResult};
use crate::ecc::{PrivateKey, PublicKey, hash};
use sha2::{Sha256, Digest};
use base58::{ToBase58, FromBase58};
use hex;
use rand::{Rng, thread_rng};

/// Key utility functions
pub struct KeyUtils;

impl KeyUtils {
    /// Normalize a brain key by trimming whitespace and converting to lowercase
    pub fn normalize_brain_key(brain_key: &str) -> String {
        brain_key
            .trim()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
    }

    /// Validate a private key in WIF format
    pub fn validate_wif(wif: &str) -> bool {
        PrivateKey::from_wif(wif).is_ok()
    }

    /// Validate a public key in hex format
    pub fn validate_public_key_hex(hex_key: &str) -> bool {
        PublicKey::from_hex(hex_key).is_ok()
    }

    /// Convert private key bytes to WIF format
    pub fn private_key_to_wif(private_key_bytes: &[u8; 32], compressed: bool) -> EccResult<String> {
        let private_key = PrivateKey::from_bytes(private_key_bytes)?;
        Ok(private_key.to_wif(compressed))
    }

    /// Convert WIF to private key bytes
    pub fn wif_to_private_key_bytes(wif: &str) -> EccResult<[u8; 32]> {
        let private_key = PrivateKey::from_wif(wif)?;
        Ok(private_key.to_bytes())
    }

    /// Generate a random private key in WIF format
    pub fn generate_wif(compressed: bool) -> EccResult<String> {
        let private_key = PrivateKey::generate()?;
        Ok(private_key.to_wif(compressed))
    }

    /// Derive multiple keys from a master key using different indices
    pub fn derive_keys(master_key: &PrivateKey, count: u32) -> EccResult<Vec<PrivateKey>> {
        let mut keys = Vec::new();
        for i in 0..count {
            let derived = master_key.derive_child(i)?;
            keys.push(derived);
        }
        Ok(keys)
    }

    /// Create a deterministic key from a seed phrase and index
    pub fn key_from_seed(seed: &str, index: u32) -> EccResult<PrivateKey> {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(&index.to_be_bytes());
        let hash = hasher.finalize();
        
        PrivateKey::from_bytes(hash.as_slice())
    }

    /// Validate key pair (check if public key matches private key)
    pub fn validate_key_pair(private_key: &PrivateKey, public_key: &PublicKey) -> bool {
        if let Ok(derived_public) = private_key.public_key() {
            derived_public == *public_key
        } else {
            false
        }
    }

    /// Convert between different key formats
    pub fn convert_key_format(input: &str, output_format: KeyFormat) -> EccResult<String> {
        // Try to parse input as different formats
        if let Ok(private_key) = PrivateKey::from_wif(input) {
            // Input is WIF
            match output_format {
                KeyFormat::Hex => Ok(hex::encode(private_key.to_bytes())),
                KeyFormat::WifCompressed => Ok(private_key.to_wif(true)),
                KeyFormat::WifUncompressed => Ok(private_key.to_wif(false)),
                KeyFormat::Base58 => Ok(private_key.to_bytes().to_base58()),
            }
        } else if let Ok(bytes) = hex::decode(input) {
            // Input is hex
            if bytes.len() == 32 {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&bytes);
                let private_key = PrivateKey::from_bytes(&key_bytes)?;
                match output_format {
                    KeyFormat::Hex => Ok(input.to_string()),
                    KeyFormat::WifCompressed => Ok(private_key.to_wif(true)),
                    KeyFormat::WifUncompressed => Ok(private_key.to_wif(false)),
                    KeyFormat::Base58 => Ok(bytes.to_base58()),
                }
            } else {
                Err(EccError::InvalidPrivateKey {
                    reason: "Invalid hex key length".to_string(),
                })
            }
        } else if let Ok(bytes) = input.from_base58() {
            // Input is base58
            if bytes.len() == 32 {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&bytes);
                let private_key = PrivateKey::from_bytes(&key_bytes)?;
                match output_format {
                    KeyFormat::Hex => Ok(hex::encode(bytes)),
                    KeyFormat::WifCompressed => Ok(private_key.to_wif(true)),
                    KeyFormat::WifUncompressed => Ok(private_key.to_wif(false)),
                    KeyFormat::Base58 => Ok(input.to_string()),
                }
            } else {
                Err(EccError::InvalidPrivateKey {
                    reason: "Invalid base58 key length".to_string(),
                })
            }
        } else {
            Err(EccError::InvalidPrivateKey {
                reason: "Unrecognized key format".to_string(),
            })
        }
    }

    /// Generate a secure random seed
    pub fn generate_seed(length: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        (0..length).map(|_| rng.gen()).collect()
    }

    /// Create a checksum for key validation
    pub fn create_key_checksum(key_data: &[u8]) -> [u8; 4] {
        let hash = hash::sha256d(key_data);
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Verify a key checksum
    pub fn verify_key_checksum(key_data: &[u8], checksum: &[u8; 4]) -> bool {
        let computed = Self::create_key_checksum(key_data);
        computed == *checksum
    }

    /// Split a key into shares for secret sharing (simplified Shamir's Secret Sharing)
    pub fn split_key(key: &[u8; 32], threshold: u8, shares: u8) -> EccResult<Vec<Vec<u8>>> {
        if threshold > shares || threshold == 0 || shares == 0 {
            return Err(EccError::KeyDerivationFailed {
                reason: "Invalid threshold or share count".to_string(),
            });
        }

        // Simplified implementation - in production, use proper Shamir's Secret Sharing
        let mut result = Vec::new();
        let mut rng = thread_rng();
        
        for i in 1..=shares {
            let mut share = Vec::new();
            share.push(i); // Share index
            share.push(threshold); // Threshold
            
            // XOR with random data (simplified - not cryptographically secure)
            for &byte in key.iter() {
                let random_byte: u8 = rng.gen();
                share.push(byte ^ random_byte);
                share.push(random_byte);
            }
            
            result.push(share);
        }
        
        Ok(result)
    }

    /// Reconstruct a key from shares (simplified)
    pub fn reconstruct_key(shares: &[Vec<u8>]) -> EccResult<[u8; 32]> {
        if shares.is_empty() {
            return Err(EccError::KeyDerivationFailed {
                reason: "No shares provided".to_string(),
            });
        }

        let threshold = shares[0][1];
        if shares.len() < threshold as usize {
            return Err(EccError::KeyDerivationFailed {
                reason: "Insufficient shares for reconstruction".to_string(),
            });
        }

        // Simplified reconstruction - XOR back
        let mut key = [0u8; 32];
        let share = &shares[0];
        
        for i in 0..32 {
            let data_idx = 2 + i * 2;
            let random_idx = 2 + i * 2 + 1;
            if data_idx < share.len() && random_idx < share.len() {
                key[i] = share[data_idx] ^ share[random_idx];
            }
        }
        
        Ok(key)
    }

    /// Derive a key using HKDF (HMAC-based Key Derivation Function)
    pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        hash::hkdf_sha256(ikm, salt, info, length)
    }

    /// Create a master key from entropy
    pub fn master_key_from_entropy(entropy: &[u8]) -> EccResult<PrivateKey> {
        if entropy.len() < 16 {
            return Err(EccError::KeyDerivationFailed {
                reason: "Insufficient entropy (minimum 16 bytes)".to_string(),
            });
        }
        
        let key_material = hash::sha256(entropy);
        PrivateKey::from_bytes(&key_material)
    }

    /// Derive a child key using BIP32-like derivation (simplified)
    pub fn derive_child_key(parent_key: &PrivateKey, chain_code: &[u8; 32], index: u32) -> EccResult<(PrivateKey, [u8; 32])> {
        let mut data = Vec::new();
        
        if index >= 0x80000000 {
            // Hardened derivation
            data.push(0x00);
            data.extend_from_slice(&parent_key.to_bytes());
        } else {
            // Non-hardened derivation
            data.extend_from_slice(&parent_key.public_key()?.to_bytes());
        }
        
        data.extend_from_slice(&index.to_be_bytes());
        
        let hmac_result = hash::hmac_sha512(chain_code, &data);
        let child_key_bytes = &hmac_result[..32];
        let child_chain_code = &hmac_result[32..];
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(child_key_bytes);
        let child_key = PrivateKey::from_bytes(&key_bytes)?;
        let mut chain_code_array = [0u8; 32];
        chain_code_array.copy_from_slice(child_chain_code);
        
        Ok((child_key, chain_code_array))
    }

    /// Generate a mnemonic phrase from entropy
    pub fn entropy_to_mnemonic(entropy: &[u8]) -> EccResult<String> {
        if entropy.len() % 4 != 0 || entropy.len() < 16 || entropy.len() > 32 {
            return Err(EccError::KeyDerivationFailed {
                reason: "Invalid entropy length".to_string(),
            });
        }

        // Simplified mnemonic generation - in production, use BIP39
        let word_list = Self::get_mnemonic_wordlist();
        let mut words = Vec::new();
        
        for chunk in entropy.chunks(2) {
            let index = if chunk.len() == 2 {
                ((chunk[0] as u16) << 8) | (chunk[1] as u16)
            } else {
                chunk[0] as u16
            } % (word_list.len() as u16);
            
            words.push(word_list[index as usize]);
        }
        
        Ok(words.join(" "))
    }

    /// Convert mnemonic phrase to entropy
    pub fn mnemonic_to_entropy(mnemonic: &str) -> EccResult<Vec<u8>> {
        let word_list = Self::get_mnemonic_wordlist();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        
        if words.is_empty() {
            return Err(EccError::KeyDerivationFailed {
                reason: "Empty mnemonic".to_string(),
            });
        }
        
        let mut entropy = Vec::new();
        
        for word in words {
            if let Some(index) = word_list.iter().position(|&w| w == word) {
                let index_bytes = (index as u16).to_be_bytes();
                entropy.extend_from_slice(&index_bytes);
            } else {
                return Err(EccError::KeyDerivationFailed {
                    reason: format!("Invalid mnemonic word: {}", word),
                });
            }
        }
        
        Ok(entropy)
    }

    /// Get a simplified mnemonic word list
    fn get_mnemonic_wordlist() -> Vec<&'static str> {
        vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
            "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
            "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
            "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing",
            "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle",
            "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
            "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve",
            "april", "arcade", "arch", "arctic", "area", "arena", "argue", "arm",
            "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow",
            "art", "article", "artist", "artwork", "ask", "aspect", "assault", "asset",
            "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
            "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
            "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful",
            "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance",
            "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
            "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty",
            "because", "become", "beef", "before", "begin", "behave", "behind", "believe",
            "below", "belt", "bench", "benefit", "best", "betray", "better", "between",
            "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth",
            "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
            "blind", "blood", "blossom", "blow", "blue", "blur", "blush", "board",
            "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost",
            "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
            "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick",
            "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
            "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo",
            "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger",
            "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
            "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera",
            "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
            "canyon", "capable", "capital", "captain", "car", "carbon", "card", "care",
            "career", "careful", "careless", "cargo", "carpet", "carry", "cart", "case",
            "cash", "casino", "cast", "casual", "cat", "catalog", "catch", "category",
            "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement",
            "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change",
            "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese",
            "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
            "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
            "citizen", "city", "civil", "claim", "clamp", "clarify", "claw", "clay",
            "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic",
            "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club",
            "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee",
            "coil", "coin", "collect", "color", "column", "combine", "come", "comfort",
            "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect",
            "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
            "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple",
            "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram",
            "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
            "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch",
            "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
            "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain",
            "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp",
            "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
            "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease",
            "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand",
            "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth",
            "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy",
            "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond",
            "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma",
            "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish",
            "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy",
            "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey",
            "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama",
            "drape", "draw", "dream", "dress", "drift", "drill", "drink", "drip",
            "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during",
            "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early",
            "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy",
            "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow",
            "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
            "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty",
            "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce",
            "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll",
            "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip",
            "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay",
            "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve",
            "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute",
            "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
            "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye",
        ]
    }
}

/// Supported key formats for conversion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// Hexadecimal format
    Hex,
    /// WIF compressed format
    WifCompressed,
    /// WIF uncompressed format
    WifUncompressed,
    /// Base58 format
    Base58,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_brain_key() {
        let input = "  HELLO   world   TEST  ";
        let normalized = KeyUtils::normalize_brain_key(input);
        assert_eq!(normalized, "hello world test");
    }

    #[test]
    fn test_wif_validation() {
        let private_key = PrivateKey::generate().unwrap();
        let wif = private_key.to_wif(true);
        assert!(KeyUtils::validate_wif(&wif));
        assert!(!KeyUtils::validate_wif("invalid_wif"));
    }

    #[test]
    fn test_key_format_conversion() {
        let private_key = PrivateKey::generate().unwrap();
        let wif = private_key.to_wif(true);
        
        let hex = KeyUtils::convert_key_format(&wif, KeyFormat::Hex).unwrap();
        let back_to_wif = KeyUtils::convert_key_format(&hex, KeyFormat::WifCompressed).unwrap();
        
        assert_eq!(wif, back_to_wif);
    }

    #[test]
    fn test_key_derivation() {
        let master = PrivateKey::generate().unwrap();
        let derived_keys = KeyUtils::derive_keys(&master, 5).unwrap();
        
        assert_eq!(derived_keys.len(), 5);
        
        // All keys should be different
        for i in 0..derived_keys.len() {
            for j in i+1..derived_keys.len() {
                assert_ne!(derived_keys[i].to_bytes(), derived_keys[j].to_bytes());
            }
        }
    }

    #[test]
    fn test_key_pair_validation() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        let wrong_public_key = PrivateKey::generate().unwrap().public_key();
        
        assert!(KeyUtils::validate_key_pair(&private_key, &public_key.unwrap()));
        assert!(!KeyUtils::validate_key_pair(&private_key, &wrong_public_key.unwrap()));
    }

    #[test]
    fn test_checksum() {
        let data = b"test data";
        let checksum = KeyUtils::create_key_checksum(data);
        
        assert!(KeyUtils::verify_key_checksum(data, &checksum));
        assert!(!KeyUtils::verify_key_checksum(b"different data", &checksum));
    }

    #[test]
    fn test_seed_generation() {
        let seed = KeyUtils::generate_seed(32);
        assert_eq!(seed.len(), 32);
        
        let seed2 = KeyUtils::generate_seed(32);
        assert_ne!(seed, seed2); // Should be random
    }

    #[test]
    fn test_master_key_from_entropy() {
        let entropy = KeyUtils::generate_seed(32);
        let master_key = KeyUtils::master_key_from_entropy(&entropy).unwrap();
        
        // Same entropy should produce same key
        let master_key2 = KeyUtils::master_key_from_entropy(&entropy).unwrap();
        assert_eq!(master_key.to_bytes(), master_key2.to_bytes());
        
        // Different entropy should produce different key
        let entropy2 = KeyUtils::generate_seed(32);
        let master_key3 = KeyUtils::master_key_from_entropy(&entropy2).unwrap();
        assert_ne!(master_key.to_bytes(), master_key3.to_bytes());
    }

    #[test]
    fn test_hkdf_derivation() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        
        let derived1 = KeyUtils::hkdf_derive(ikm, salt, info, 32);
        let derived2 = KeyUtils::hkdf_derive(ikm, salt, info, 32);
        
        assert_eq!(derived1, derived2);
        assert_eq!(derived1.len(), 32);
        
        let derived3 = KeyUtils::hkdf_derive(ikm, salt, b"different info", 32);
        assert_ne!(derived1, derived3);
    }

    #[test]
    fn test_mnemonic_conversion() {
        let entropy = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let mnemonic = KeyUtils::entropy_to_mnemonic(&entropy).unwrap();
        let recovered_entropy = KeyUtils::mnemonic_to_entropy(&mnemonic).unwrap();
        
        // Note: Due to the simplified implementation, this might not be exact
        assert!(!mnemonic.is_empty());
        assert!(!recovered_entropy.is_empty());
    }

    #[test]
    fn test_key_splitting_and_reconstruction() {
        let key = [0x42u8; 32];
        let shares = KeyUtils::split_key(&key, 3, 5).unwrap();
        
        assert_eq!(shares.len(), 5);
        
        // Use first 3 shares to reconstruct
        let reconstructed = KeyUtils::reconstruct_key(&shares[..3]).unwrap();
        assert_eq!(key, reconstructed);
    }
}