use std::fmt;

use hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Custom serializers for serde
pub mod serde_helpers {
    use super::*;

    /// Serialize a 32-byte array as hex
    pub fn serialize_array_32<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let hex_string = hex::encode(bytes);
        hex_string.serialize(serializer)
    }

    /// Deserialize a 32-byte array from hex
    pub fn deserialize_array_32<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where D: Deserializer<'de> {
        let hex_string = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;

        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

/// Error types for hex encoding/decoding operations
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HexError {
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),
    #[error("Invalid hex length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Hex string is empty")]
    EmptyString,
    #[error("Hex string has odd length: {0}")]
    OddLength(usize),
}

impl From<hex::FromHexError> for HexError {
    fn from(err: hex::FromHexError) -> Self {
        HexError::InvalidHex(err.to_string())
    }
}

/// Trait for types that can be converted to and from hex strings
pub trait HexEncodable {
    /// Convert the value to a hex string
    fn to_hex(&self) -> String;

    /// Convert the value to a hex string with a prefix (e.g., "0x")
    fn to_hex_with_prefix(&self, prefix: &str) -> String {
        format!("{}{}", prefix, self.to_hex())
    }

    /// Convert from a hex string
    fn from_hex(hex: &str) -> Result<Self, HexError>
    where Self: Sized;

    /// Convert from a hex string, optionally removing a prefix
    fn from_hex_with_prefix(hex: &str, prefix: &str) -> Result<Self, HexError>
    where Self: Sized {
        let hex = hex.strip_prefix(prefix).unwrap_or(hex);
        Self::from_hex(hex)
    }
}

/// Utility functions for hex encoding/decoding
pub struct HexUtils;

impl HexUtils {
    /// Convert bytes to hex string
    pub fn to_hex(bytes: &[u8]) -> String {
        bytes.encode_hex()
    }

    /// Convert bytes to hex string with prefix
    pub fn to_hex_with_prefix(bytes: &[u8], prefix: &str) -> String {
        format!("{}{}", prefix, Self::to_hex(bytes))
    }

    /// Convert hex string to bytes
    pub fn from_hex(hex: &str) -> Result<Vec<u8>, HexError> {
        if hex.is_empty() {
            return Err(HexError::EmptyString);
        }

        if hex.len() % 2 != 0 {
            return Err(HexError::OddLength(hex.len()));
        }

        Vec::from_hex(hex).map_err(Into::into)
    }

    /// Convert hex string to bytes, optionally removing a prefix
    pub fn from_hex_with_prefix(hex: &str, prefix: &str) -> Result<Vec<u8>, HexError> {
        let hex = hex.strip_prefix(prefix).unwrap_or(hex);
        Self::from_hex(hex)
    }

    /// Convert hex string to fixed-size byte array
    pub fn from_hex_to_array<const N: usize>(hex: &str) -> Result<[u8; N], HexError> {
        let bytes = Self::from_hex(hex)?;

        if bytes.len() != N {
            return Err(HexError::InvalidLength {
                expected: N,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    /// Convert hex string to fixed-size byte array, optionally removing a prefix
    pub fn from_hex_to_array_with_prefix<const N: usize>(hex: &str, prefix: &str) -> Result<[u8; N], HexError> {
        let hex = hex.strip_prefix(prefix).unwrap_or(hex);
        Self::from_hex_to_array(hex)
    }

    /// Validate that a string is a valid hex string
    pub fn is_valid_hex(hex: &str) -> bool {
        if hex.is_empty() {
            return false;
        }

        if hex.len() % 2 != 0 {
            return false;
        }

        hex.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validate that a string is a valid hex string, optionally removing a prefix
    pub fn is_valid_hex_with_prefix(hex: &str, prefix: &str) -> bool {
        let hex = hex.strip_prefix(prefix).unwrap_or(hex);
        Self::is_valid_hex(hex)
    }

    /// Format a hex string with proper spacing (e.g., "12 34 56 78")
    pub fn format_hex_with_spacing(bytes: &[u8], bytes_per_line: Option<usize>) -> String {
        let hex = Self::to_hex(bytes);
        let mut formatted = String::new();

        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            if i > 0 {
                if let Some(bytes_per_line) = bytes_per_line {
                    if i % bytes_per_line == 0 {
                        formatted.push('\n');
                    } else {
                        formatted.push(' ');
                    }
                } else {
                    formatted.push(' ');
                }
            }
            formatted.push_str(std::str::from_utf8(chunk).unwrap_or("??"));
        }

        formatted
    }

    /// Convert a hex string to uppercase
    pub fn to_uppercase_hex(bytes: &[u8]) -> String {
        Self::to_hex(bytes).to_uppercase()
    }

    /// Convert a hex string to lowercase
    pub fn to_lowercase_hex(bytes: &[u8]) -> String {
        Self::to_hex(bytes).to_lowercase()
    }
}

/// Display wrapper for hex formatting
pub struct HexDisplay<'a>(&'a [u8]);

impl<'a> HexDisplay<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn with_prefix(bytes: &'a [u8], prefix: &'a str) -> HexDisplayWithPrefix<'a> {
        HexDisplayWithPrefix { bytes, prefix }
    }
}

impl<'a> fmt::Display for HexDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", HexUtils::to_hex(self.0))
    }
}

impl<'a> fmt::Debug for HexDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexDisplay(\"{self}\")")
    }
}

/// Display wrapper for hex formatting with prefix
pub struct HexDisplayWithPrefix<'a> {
    bytes: &'a [u8],
    prefix: &'a str,
}

impl<'a> fmt::Display for HexDisplayWithPrefix<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.prefix, HexUtils::to_hex(self.bytes))
    }
}

impl<'a> fmt::Debug for HexDisplayWithPrefix<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexDisplayWithPrefix(\"{self}\")")
    }
}

#[cfg(test)]
mod tests {
    use tari_common_types::types::{CompressedCommitment, CompressedPublicKey, PrivateKey};
    use tari_crypto::keys::SecretKey;
    use tari_transaction_components::transaction_components::EncryptedData;
    use tari_utilities::{hex::Hex, ByteArray};

    use super::*;

    #[test]
    fn test_hex_utils_basic() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];

        // Test basic hex conversion
        let hex = HexUtils::to_hex(&data);
        assert_eq!(hex, "123456789abcdef0");

        // Test hex conversion with prefix
        let hex_with_prefix = HexUtils::to_hex_with_prefix(&data, "0x");
        assert_eq!(hex_with_prefix, "0x123456789abcdef0");

        // Test hex parsing
        let parsed = HexUtils::from_hex(&hex).unwrap();
        assert_eq!(parsed, data);

        // Test hex parsing with prefix
        let parsed_with_prefix = HexUtils::from_hex_with_prefix(&hex_with_prefix, "0x").unwrap();
        assert_eq!(parsed_with_prefix, data);
    }

    #[test]
    fn test_hex_utils_array() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let hex = "12345678";

        // Test array conversion
        let parsed = HexUtils::from_hex_to_array::<4>(hex).unwrap();
        assert_eq!(parsed, data);

        // Test array conversion with prefix
        let parsed_with_prefix = HexUtils::from_hex_to_array_with_prefix::<4>("0x12345678", "0x").unwrap();
        assert_eq!(parsed_with_prefix, data);
    }

    #[test]
    fn test_hex_utils_validation() {
        // Valid hex strings
        assert!(HexUtils::is_valid_hex("123456789abcdef0"));
        assert!(HexUtils::is_valid_hex("ABCDEF"));
        assert!(!HexUtils::is_valid_hex("")); // Empty string is invalid

        // Invalid hex strings
        assert!(!HexUtils::is_valid_hex("123456789abcdef")); // Odd length
        assert!(!HexUtils::is_valid_hex("123456789abcdefg")); // Invalid characters

        // Test with prefix
        assert!(HexUtils::is_valid_hex_with_prefix("0x123456789abcdef0", "0x"));
        assert!(!HexUtils::is_valid_hex_with_prefix("0x123456789abcdef", "0x"));
    }

    #[test]
    fn test_hex_utils_formatting() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];

        // Test spacing
        let formatted = HexUtils::format_hex_with_spacing(&data, None);
        assert_eq!(formatted, "12 34 56 78 9a bc de f0");

        // Test with line breaks
        let formatted_with_lines = HexUtils::format_hex_with_spacing(&data, Some(4));
        assert_eq!(formatted_with_lines, "12 34 56 78\n9a bc de f0");

        // Test case conversion
        let uppercase = HexUtils::to_uppercase_hex(&data);
        assert_eq!(uppercase, "123456789ABCDEF0");

        let lowercase = HexUtils::to_lowercase_hex(&data);
        assert_eq!(lowercase, "123456789abcdef0");
    }

    #[test]
    fn test_hex_display() {
        let data = [0x12, 0x34, 0x56, 0x78];

        // Test basic display
        let display = HexDisplay::new(&data);
        assert_eq!(display.to_string(), "12345678");

        // Test display with prefix
        let display_with_prefix = HexDisplay::with_prefix(&data, "0x");
        assert_eq!(display_with_prefix.to_string(), "0x12345678");
    }

    #[test]
    fn test_hex_errors() {
        // Test empty string
        assert!(matches!(HexUtils::from_hex(""), Err(HexError::EmptyString)));

        // Test odd length
        assert!(matches!(HexUtils::from_hex("123"), Err(HexError::OddLength(3))));

        // Test invalid hex
        assert!(matches!(
            HexUtils::from_hex("123456789abcdefg"),
            Err(HexError::InvalidHex(_))
        ));

        // Test wrong array size
        assert!(matches!(
            HexUtils::from_hex_to_array::<4>("1234567890"),
            Err(HexError::InvalidLength { expected: 4, actual: 5 })
        ));
    }

    #[test]
    fn test_private_key_hex() {
        let mut rng = rand::thread_rng();
        let key = PrivateKey::random(&mut rng);
        let hex = key.to_hex();
        let key_from_hex = PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(key, key_from_hex);
    }

    #[test]
    fn test_compressed_commitment_hex() {
        let commitment = CompressedCommitment::default();

        // Test to_hex
        let hex = commitment.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes * 2 hex chars per byte

        // Test from_hex
        let parsed = CompressedCommitment::from_hex(&hex).unwrap();
        assert_eq!(parsed, commitment);
    }

    #[test]
    fn test_compressed_public_key_hex() {
        let key_bytes = [0x56; 32];
        let public_key = CompressedPublicKey::from_canonical_bytes(&key_bytes).unwrap();

        // Test to_hex
        let hex = public_key.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes * 2 hex chars per byte

        // Test from_hex
        let parsed = CompressedPublicKey::from_hex(&hex).unwrap();
        assert_eq!(parsed, public_key);
    }

    #[test]
    fn test_encrypted_data_hex() {
        let data = vec![0x9a; 80]; // Use minimum required size
        let encrypted_data = EncryptedData::from_bytes(&data).unwrap();

        // Test to_hex
        let hex = encrypted_data.to_hex();
        assert_eq!(hex, hex::encode(&data));

        // Test from_hex
        let parsed = EncryptedData::from_hex(&hex).unwrap();
        assert_eq!(parsed.as_bytes(), data.as_slice());
    }

    #[test]
    fn test_hex_encodable_traits() {
        // Test that all types implement HexEncodable and HexValidatable
        let private_key = PrivateKey::from_uniform_bytes(&[0x12; 32]).unwrap();
        let commitment = CompressedCommitment::from_canonical_bytes(&[0u8; 32]).unwrap();
        let public_key = CompressedPublicKey::from_canonical_bytes(&[0x56; 32]).unwrap();
        let encrypted_data = EncryptedData::from_bytes(&[0x9a; 80]).unwrap();

        // Test that they all have hex methods
        assert!(!private_key.to_hex().is_empty());
        assert!(!commitment.to_hex().is_empty());
        assert!(!public_key.to_hex().is_empty());
        assert!(!encrypted_data.to_hex().is_empty());
    }
}
