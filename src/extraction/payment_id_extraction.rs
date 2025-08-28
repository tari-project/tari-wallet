//! Payment ID extraction from encrypted data
//!
//! This module provides functionality to extract the payment ID from
//! an EncryptedData instance, using a provided decryption key and commitment.
//! It supports all payment ID types: Empty, U256, Open, AddressAndData, TransactionInfo, and Raw.

use std::str::FromStr;

use primitive_types::U256;
use tari_common_types::{
    tari_address::TariAddress,
    transaction::{TransactionDirection, TransactionStatus},
    types::{CompressedPublicKey, CompressedSignature, FixedHash, PrivateKey},
};
use tari_common_types::types::CompressedCommitment;
use tari_transaction_components::{
    aggregated_body::AggregateBody,
    transaction_components::{
        covenants::Covenant,
        CoinBaseExtra,
        EncryptedData,
        KernelFeatures,
        MemoField,
        OutputFeatures,
        OutputFeaturesVersion,
        OutputType,
        RangeProofType,
        SideChainFeature,
        Transaction,
        TransactionInput,
        TransactionInputVersion,
        TransactionKernel,
        TransactionKernelVersion,
        TransactionOutput,
        TransactionOutputVersion,
    },
    MicroMinotari,
};
use tari_transaction_components::transaction_components::memo_field::TxType;
use crate::hex_utils::HexEncodable;

/// Result of payment ID extraction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoFieldExtractionResult {
    /// The extracted payment ID (if successful)
    pub payment_id: Option<MemoField>,
    /// Error message if extraction failed
    pub error: Option<String>,
    /// Additional metadata about the extraction
    pub metadata: MemoFieldMetadata,
}

/// Metadata about the extracted payment ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoFieldMetadata {
    /// The transaction type inferred from the payment ID
    pub transaction_type: Option<TxType>,
    /// Whether the payment ID contains valid UTF-8 data
    pub has_valid_utf8: bool,
    /// The size of the payment ID in bytes
    pub size_bytes: usize,
    /// Whether this is a standard payment ID format
    pub is_standard_format: bool,
}

impl MemoFieldMetadata {
    pub fn new(payment_id: &MemoField) -> Self {
        let transaction_type = payment_id.get_type();
        let size_bytes = payment_id.get_size();
        let has_valid_utf8 = Self::check_utf8_validity(payment_id);
        let is_standard_format = Self::is_standard_format(payment_id);

        Self {
            transaction_type: Some(transaction_type),
            has_valid_utf8,
            size_bytes,
            is_standard_format,
        }
    }

    fn check_utf8_validity(payment_id: &MemoField) -> bool {
        match payment_id {
            MemoField::Empty => true,
            MemoField::U256 { .. } => true,
            MemoField::Open { user_data, tx_type: _ } => std::str::from_utf8(user_data).is_ok(),
            MemoField::AddressAndData { user_data, .. } => std::str::from_utf8(user_data).is_ok(),
            MemoField::TransactionInfo { .. } => true,
            MemoField::Raw(data) => std::str::from_utf8(data).is_ok(),
        }
    }

    fn is_standard_format(payment_id: &MemoField) -> bool {
        match payment_id {
            MemoField::Empty => true,
            MemoField::U256 { .. } => true,
            MemoField::Open { user_data, tx_type: _ } => user_data.len() <= 256, // Standard limit
            MemoField::AddressAndData { user_data, .. } => {
                user_data.len() <= 256 // Standard limits
            },
            MemoField::TransactionInfo { .. } => true, // Standard tx ID size
            MemoField::Raw(data) => data.len() <= 256, // Standard limit
        }
    }
}

impl MemoFieldExtractionResult {
    pub fn success(payment_id: MemoField) -> Self {
        let metadata = MemoFieldMetadata::new(&payment_id);
        Self {
            payment_id: Some(payment_id),
            error: None,
            metadata,
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            payment_id: None,
            error: Some(error),
            metadata: MemoFieldMetadata {
                transaction_type: None,
                has_valid_utf8: false,
                size_bytes: 0,
                is_standard_format: false,
            },
        }
    }

    pub fn is_success(&self) -> bool {
        self.payment_id.is_some()
    }

    pub fn error_message(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn get_payment_id(&self) -> Option<&MemoField> {
        self.payment_id.as_ref()
    }

    pub fn get_metadata(&self) -> &MemoFieldMetadata {
        &self.metadata
    }
}

/// Enhanced payment ID extractor with comprehensive support for all payment ID types
pub struct MemoFieldExtractor;

impl MemoFieldExtractor {
    /// Attempt to extract the payment ID from encrypted data
    pub fn extract(
        encrypted_data: &EncryptedData,
        decryption_key: &PrivateKey,
        commitment: &CompressedCommitment,
    ) -> MemoFieldExtractionResult {
        match EncryptedData::decrypt_data(decryption_key, commitment, encrypted_data) {
            Ok((_value, _mask, payment_id)) => match Self::validate_payment_id(&payment_id) {
                Ok(()) => MemoFieldExtractionResult::success(payment_id),
                Err(e) => MemoFieldExtractionResult::failure(format!("Payment ID validation failed: {e}")),
            },
            Err(e) => MemoFieldExtractionResult::failure(format!("Failed to decrypt data: {e}")),
        }
    }

    /// Extract and validate a specific payment ID type
    pub fn extract_with_validation(
        encrypted_data: &EncryptedData,
        decryption_key: &PrivateKey,
        commitment: &CompressedCommitment,
        expected_type: Option<MemoFieldType>,
    ) -> MemoFieldExtractionResult {
        let result = Self::extract(encrypted_data, decryption_key, commitment);

        if let Some(payment_id) = &result.payment_id {
            if let Some(expected) = expected_type {
                if !Self::matches_type(payment_id, &expected) {
                    return MemoFieldExtractionResult::failure(format!(
                        "Payment ID type mismatch: expected {:?}, got {:?}",
                        expected,
                        Self::get_payment_id_type(payment_id)
                    ));
                }
            }
        }

        result
    }

    /// Extract payment ID and convert to string representation
    pub fn extract_as_string(
        encrypted_data: &EncryptedData,
        decryption_key: &PrivateKey,
        commitment: &CompressedCommitment,
    ) -> Result<String, String> {
        let result = Self::extract(encrypted_data, decryption_key, commitment);

        if let Some(payment_id) = result.payment_id {
            Ok(Self::payment_id_to_string(&payment_id))
        } else {
            Err(result.error.unwrap_or_else(|| "Unknown error".to_string()))
        }
    }

    /// Extract payment ID and convert to hex representation
    pub fn extract_as_hex(
        encrypted_data: &EncryptedData,
        decryption_key: &PrivateKey,
        commitment: &CompressedCommitment,
    ) -> Result<String, String> {
        let result = Self::extract(encrypted_data, decryption_key, commitment);

        if let Some(payment_id) = result.payment_id {
            Ok(payment_id.to_hex())
        } else {
            Err(result.error.unwrap_or_else(|| "Unknown error".to_string()))
        }
    }

    /// Validate a payment ID
    fn validate_payment_id(payment_id: &MemoField) -> Result<(), String> {
        match payment_id {
            MemoField::Empty => Ok(()),
            MemoField::U256(value) => {
                if *value == U256::zero() {
                    Err("U256 payment ID cannot be zero".to_string())
                } else {
                    Ok(())
                }
            },
            MemoField::Open { user_data, tx_type: _ } => {
                if user_data.is_empty() {
                    Err("Open payment ID data cannot be empty".to_string())
                } else if user_data.len() > 256 {
                    Err("Open payment ID data too large (max 256 bytes)".to_string())
                } else {
                    Ok(())
                }
            },
            MemoField::AddressAndData { user_data, .. } => {
                if user_data.is_empty() {
                    Err("AddressAndData payment ID data cannot be empty".to_string())
                } else if user_data.len() > 256 {
                    Err("AddressAndData payment ID data too large (max 256 bytes)".to_string())
                } else {
                    Ok(())
                }
            },
            MemoField::TransactionInfo { user_data, amount, .. } => {
                if amount.as_u64() == 0 {
                    Err("TransactionInfo payment ID amount cannot be zero".to_string())
                } else if user_data.is_empty() {
                    Err("TransactionInfo payment ID data cannot be empty".to_string())
                } else if user_data.len() > 256 {
                    Err("TransactionInfo payment ID data too large (max 256 bytes)".to_string())
                } else {
                    Ok(())
                }
            },
            MemoField::Raw(data) => {
                if data.is_empty() {
                    Err("Raw payment ID data cannot be empty".to_string())
                } else if data.len() > 256 {
                    Err("Raw payment ID data too large (max 256 bytes)".to_string())
                } else {
                    Ok(())
                }
            },
        }
    }

    /// Convert payment ID to string representation
    fn payment_id_to_string(payment_id: &MemoField) -> String {
        match payment_id {
            MemoField::Empty => "Empty".to_string(),
            MemoField::U256(value) => {
                // Format as zero-padded 64-character hex string
                let mut bytes = [0u8; 32];
                value.to_big_endian(&mut bytes);
                format!("U256: {:064x}", U256::from_big_endian(&bytes))
            },
            MemoField::Open { user_data, tx_type: _ } => {
                if let Ok(s) = std::str::from_utf8(user_data) {
                    format!("Open: {s}")
                } else {
                    format!("Open: {}", hex::encode(user_data))
                }
            },
            MemoField::AddressAndData {
                sender_address,
                user_data,
                ..
            } => {
                let address_str = sender_address.to_base58();
                let data_str = if let Ok(s) = std::str::from_utf8(user_data) {
                    s.to_string()
                } else {
                    hex::encode(user_data)
                };
                format!("AddressAndData: address={address_str}, data={data_str}")
            },
            MemoField::TransactionInfo {
                recipient_address,
                amount,
                user_data,
                ..
            } => {
                format!(
                    "TransactionInfo: address={}, amount={}, data={}",
                    recipient_address.to_base58(),
                    amount,
                    String::from_utf8_lossy(user_data)
                )
            },
            MemoField::Raw(data) => {
                if let Ok(s) = std::str::from_utf8(data) {
                    format!("Raw: {s}")
                } else {
                    format!("Raw: {}", hex::encode(data))
                }
            },
        }
    }

    /// Check if payment ID matches a specific type
    fn matches_type(payment_id: &MemoField, expected_type: &MemoFieldType) -> bool {
        Self::get_payment_id_type(payment_id) == *expected_type
    }

    /// Get the type of a payment ID
    fn get_payment_id_type(payment_id: &MemoField) -> MemoFieldType {
        match payment_id {
            MemoField::Empty => MemoFieldType::Empty,
            MemoField::U256(..) => MemoFieldType::U256,
            MemoField::Open { .. } => MemoFieldType::Open,
            MemoField::AddressAndData { .. } => MemoFieldType::AddressAndData,
            MemoField::TransactionInfo { .. } => MemoFieldType::TransactionInfo,
            MemoField::Raw(..) => MemoFieldType::Raw,
        }
    }

    /// Create a payment ID from string representation
    pub fn from_string(s: &str) -> Result<MemoField, String> {
        if s.is_empty() || s == "Empty" {
            return Ok(MemoField::Empty);
        }

        if let Some(value_str) = s.strip_prefix("U256: ") {
            let value = U256::from_str(value_str).map_err(|e| format!("Invalid U256 value: {e}"))?;
            return Ok(MemoField::U256(value));
        }

        if let Some(data_str) = s.strip_prefix("Open: ") {
            let user_data = data_str.as_bytes().to_vec();
            return Ok(MemoField::Open {
                user_data,
                tx_type: TxType::PaymentToOther,
            });
        }

        if let Some(data_str) = s.strip_prefix("Raw: ") {
            let data = data_str.as_bytes().to_vec();
            return Ok(MemoField::Raw(data));
        }

        // Try to parse as hex for other types
        if let Ok(bytes) = hex::decode(s) {
            return Ok(MemoField::Raw(bytes));
        }

        Err(format!("Unable to parse payment ID from string: {s}"))
    }
}

/// Payment ID type enumeration for validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoFieldType {
    Empty,
    U256,
    Open,
    AddressAndData,
    TransactionInfo,
    Raw,
}

impl std::fmt::Display for MemoFieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoFieldType::Empty => write!(f, "Empty"),
            MemoFieldType::U256 => write!(f, "U256"),
            MemoFieldType::Open => write!(f, "Open"),
            MemoFieldType::AddressAndData => write!(f, "AddressAndData"),
            MemoFieldType::TransactionInfo => write!(f, "TransactionInfo"),
            MemoFieldType::Raw => write!(f, "Raw"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{
        encrypted_data::EncryptedData,
        payment_id::MemoField,
        types::{CompressedCommitment, MicroMinotari, PrivateKey},
        TariAddress,
    };

    fn create_test_encrypted_data(payment_id: MemoField) -> (EncryptedData, CompressedCommitment, PrivateKey) {
        let encryption_key = PrivateKey::random();
        let commitment = CompressedCommitment::new([0x08; 32]);
        let value = MicroMinotari::new(1000);
        let mask = PrivateKey::random();
        let encrypted_data =
            EncryptedData::encrypt_data(&encryption_key, &commitment, value, &mask, payment_id).unwrap();
        (encrypted_data, commitment, encryption_key)
    }

    #[test]
    fn test_extract_payment_id_success() {
        let u256_bytes = [0u8; 31].iter().cloned().chain([1u8]).collect::<Vec<u8>>();
        let (encrypted_data, commitment, key) =
            create_test_encrypted_data(MemoField::U256(U256::from_big_endian(&u256_bytes)));
        let result = MemoFieldExtractor::extract(&encrypted_data, &key, &commitment);
        assert!(result.is_success());
        assert!(matches!(result.payment_id, Some(MemoField::U256(..))));
    }

    #[test]
    fn test_extract_payment_id_failure_wrong_key() {
        let (encrypted_data, commitment, _key) = create_test_encrypted_data(MemoField::Empty);
        let wrong_key = PrivateKey::random();
        let result = MemoFieldExtractor::extract(&encrypted_data, &wrong_key, &commitment);
        assert!(!result.is_success());
        assert!(result.error_message().is_some());
    }

    #[test]
    fn test_extract_all_payment_id_types() {
        let encryption_key = PrivateKey::random();
        let commitment = CompressedCommitment::new([0x09; 32]);
        let value = MicroMinotari::new(1234);
        let mask = PrivateKey::random();

        // Test Empty
        let empty_payment_id = MemoField::Empty;
        let encrypted_empty =
            EncryptedData::encrypt_data(&encryption_key, &commitment, value, &mask, empty_payment_id).unwrap();
        let result_empty = MemoFieldExtractor::extract(&encrypted_empty, &encryption_key, &commitment);
        assert!(result_empty.is_success());
        assert!(matches!(result_empty.payment_id, Some(MemoField::Empty)));

        // Test U256
        let u256_bytes = [0u8; 31].iter().cloned().chain([1u8]).collect::<Vec<u8>>();
        let u256_payment_id = MemoField::U256(U256::from_big_endian(&u256_bytes));
        let encrypted_u256 =
            EncryptedData::encrypt_data(&encryption_key, &commitment, value, &mask, u256_payment_id).unwrap();
        let result_u256 = MemoFieldExtractor::extract(&encrypted_u256, &encryption_key, &commitment);
        assert!(result_u256.is_success());
        assert!(matches!(result_u256.payment_id, Some(MemoField::U256(..))));

        // Test Open
        let open_payment_id = MemoField::Open {
            user_data: b"test_data".to_vec(),
            tx_type: TxType::PaymentToOther,
        };
        let encrypted_open =
            EncryptedData::encrypt_data(&encryption_key, &commitment, value, &mask, open_payment_id).unwrap();
        let result_open = MemoFieldExtractor::extract(&encrypted_open, &encryption_key, &commitment);
        assert!(result_open.is_success());
        assert!(matches!(result_open.payment_id, Some(MemoField::Open { .. })));

        // Test AddressAndData
        use crate::data_structures::{address::TariAddress, types::MicroMinotari};
        let tari_address = TariAddress::default(); // This may need to be adjusted based on your TariAddress implementation
        let address_data_payment_id = MemoField::AddressAndData {
            sender_address: tari_address,
            sender_one_sided: false,
            fee: MicroMinotari::new(100),
            tx_type: TxType::PaymentToOther,
            user_data: b"test_data".to_vec(),
        };
        let encrypted_address_data =
            EncryptedData::encrypt_data(&encryption_key, &commitment, value, &mask, address_data_payment_id).unwrap();
        let result_address_data = MemoFieldExtractor::extract(&encrypted_address_data, &encryption_key, &commitment);
        assert!(result_address_data.is_success());
        assert!(matches!(
            result_address_data.payment_id,
            Some(MemoField::AddressAndData { .. })
        ));

        // Test TransactionInfo
        let tx_info_payment_id = MemoField::TransactionInfo {
            recipient_address: TariAddress::default(),
            amount: MicroMinotari::new(100),
            user_data: b"test_data".to_vec(),
            tx_type: TxType::PaymentToOther,
            sent_output_hashes: vec![],
            sender_one_sided: false,
            fee: MicroMinotari::new(100),
        };
        let encrypted_tx_info =
            EncryptedData::encrypt_data(&encryption_key, &commitment, value, &mask, tx_info_payment_id).unwrap();
        let result_tx_info = MemoFieldExtractor::extract(&encrypted_tx_info, &encryption_key, &commitment);
        assert!(result_tx_info.is_success());
        assert!(matches!(
            result_tx_info.payment_id,
            Some(MemoField::TransactionInfo { .. })
        ));

        // Test Raw
        let raw_payment_id = MemoField::Raw(b"raw_data".to_vec());
        let encrypted_raw =
            EncryptedData::encrypt_data(&encryption_key, &commitment, value, &mask, raw_payment_id).unwrap();
        let result_raw = MemoFieldExtractor::extract(&encrypted_raw, &encryption_key, &commitment);
        assert!(result_raw.is_success());
        assert!(matches!(result_raw.payment_id, Some(MemoField::Raw(..))));
    }

    #[test]
    fn test_payment_id_validation() {
        // Test valid payment IDs
        assert!(MemoFieldExtractor::validate_payment_id(&MemoField::Empty).is_ok());
        let u256_bytes = [0u8; 31].iter().cloned().chain([1u8]).collect::<Vec<u8>>();
        assert!(MemoFieldExtractor::validate_payment_id(&MemoField::U256(U256::from_big_endian(&u256_bytes))).is_ok());
        assert!(MemoFieldExtractor::validate_payment_id(&MemoField::Open {
            user_data: b"test".to_vec(),
            tx_type: TxType::PaymentToOther
        })
        .is_ok());

        // Test invalid payment IDs
        assert!(MemoFieldExtractor::validate_payment_id(&MemoField::U256(U256::zero())).is_err());
        assert!(MemoFieldExtractor::validate_payment_id(&MemoField::Open {
            user_data: vec![],
            tx_type: TxType::PaymentToOther
        })
        .is_err());
        assert!(MemoFieldExtractor::validate_payment_id(&MemoField::Open {
            user_data: vec![0u8; 300],
            tx_type: TxType::PaymentToOther
        })
        .is_err());
    }

    #[test]
    fn test_payment_id_to_string() {
        assert_eq!(MemoFieldExtractor::payment_id_to_string(&MemoField::Empty), "Empty");
        assert_eq!(
            MemoFieldExtractor::payment_id_to_string(&MemoField::U256(U256::from_big_endian(
                &[0u8; 31].iter().cloned().chain([1u8]).collect::<Vec<u8>>()[..]
            ))),
            "U256: 0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            MemoFieldExtractor::payment_id_to_string(&MemoField::Open {
                user_data: b"test".to_vec(),
                tx_type: TxType::PaymentToOther
            }),
            "Open: test"
        );
        assert_eq!(
            MemoFieldExtractor::payment_id_to_string(&MemoField::Raw(b"raw".to_vec())),
            "Raw: raw"
        );
    }

    #[test]
    fn test_payment_id_from_string() {
        assert!(matches!(
            MemoFieldExtractor::from_string("Empty").unwrap(),
            MemoField::Empty
        ));
        assert!(matches!(MemoFieldExtractor::from_string("").unwrap(), MemoField::Empty));
        assert!(matches!(
            MemoFieldExtractor::from_string("Open: test").unwrap(),
            MemoField::Open { .. }
        ));
        assert!(matches!(
            MemoFieldExtractor::from_string("Raw: raw_data").unwrap(),
            MemoField::Raw(..)
        ));
    }

    #[test]
    fn test_extract_as_string() {
        let (encrypted_data, commitment, key) = create_test_encrypted_data(MemoField::Open {
            user_data: b"test_string".to_vec(),
            tx_type: TxType::PaymentToOther,
        });
        let result = MemoFieldExtractor::extract_as_string(&encrypted_data, &key, &commitment);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Open: test_string");
    }

    #[test]
    fn test_extract_as_hex() {
        let u256_bytes = [0u8; 31].iter().cloned().chain([1u8]).collect::<Vec<u8>>();
        let (encrypted_data, commitment, key) =
            create_test_encrypted_data(MemoField::U256(U256::from_big_endian(&u256_bytes)));
        let result = MemoFieldExtractor::extract_as_hex(&encrypted_data, &key, &commitment);
        assert!(result.is_ok());
        let hex_result = result.unwrap();
        // The hex result should start with "01" (tag for U256) and contain the value in little-endian format
        assert!(hex_result.starts_with("01"));
        assert!(hex_result.contains("01000000000000000000000000000000"));
    }

    #[test]
    fn test_metadata_extraction() {
        let (encrypted_data, commitment, key) = create_test_encrypted_data(MemoField::AddressAndData {
            sender_address: TariAddress::default(),
            sender_one_sided: false,
            fee: MicroMinotari::new(100),
            tx_type: TxType::PaymentToOther,
            user_data: b"data".to_vec(),
        });
        let result = MemoFieldExtractor::extract(&encrypted_data, &key, &commitment);
        assert!(result.is_success());

        let metadata = result.get_metadata();
        assert_eq!(metadata.transaction_type, Some(TxType::PaymentToOther));
        assert!(metadata.has_valid_utf8);
        assert!(metadata.is_standard_format);
        assert!(metadata.size_bytes > 0);
    }
}
