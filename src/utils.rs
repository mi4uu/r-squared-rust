//! Utility functions for the R-Squared library

/// Convert bytes to hexadecimal string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hexadecimal string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

/// Validate key length
pub fn validate_key_length(key: &[u8], expected_len: usize) -> bool {
    key.len() == expected_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "01020304");
        
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_validate_key_length() {
        let key = vec![0u8; 32];
        assert!(validate_key_length(&key, 32));
        assert!(!validate_key_length(&key, 16));
    }
}