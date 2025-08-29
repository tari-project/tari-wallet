use std::str::FromStr;

use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use tari_common_types::types::{ComAndPubSignature, CompressedCommitment, CompressedPublicKey, PrivateKey, RangeProof};
use tari_script::{ExecutionStack, TariScript};
use tari_transaction_components::{
    key_manager::TariKeyId,
    transaction_components::{EncryptedData, MemoField, TransactionOutputVersion, WalletOutput},
    MicroMinotari,
};
use tari_utilities::byte_array::ByteArray;

use crate::{DataStructureError, SerializationError, WalletError, WalletResult};

/// A stored UTXO output with all data needed for spending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOutput {
    /// Unique output ID (database primary key)
    pub id: Option<u32>,
    /// Wallet ID this output belongs to
    pub wallet_id: u32,

    // Core UTXO identification
    pub commitment: Vec<u8>, // 32 bytes commitment
    pub hash: Vec<u8>,       // Output hash for identification
    pub value: u64,          // Value in microMinotari

    // Spending keys
    pub commitment_mask_key: String, // Commitment mask key
    pub script_key: String,          // Script key

    // Script and covenant data
    pub script: Vec<u8>,     // Script that governs spending
    pub input_data: Vec<u8>, // Execution stack data for script
    pub covenant: Vec<u8>,   // Covenant restrictions

    // Output features and type
    pub features_json: String, // Serialized output features

    // Maturity and lock constraints
    pub maturity: u64,           // Block height when spendable
    pub script_lock_height: u64, // Script lock height

    // Metadata signature components
    pub sender_offset_public_key: Vec<u8>, // Sender offset public key
    pub metadata_signature_ephemeral_commitment: Vec<u8>, // Ephemeral commitment
    pub metadata_signature_ephemeral_pubkey: Vec<u8>, // Ephemeral public key
    pub metadata_signature_u_a: Vec<u8>,   // Signature component u_a
    pub metadata_signature_u_x: Vec<u8>,   // Signature component u_x
    pub metadata_signature_u_y: Vec<u8>,   // Signature component u_y

    // Payment information
    pub encrypted_data: Vec<u8>,    // Contains payment information
    pub minimum_value_promise: u64, // Minimum value promise
    pub payment_id: Vec<u8>,        // Payment ID

    // Range proof
    pub rangeproof: Option<Vec<u8>>, // Range proof bytes (nullable)

    // Status and spending tracking
    pub status: u32,                 // 0=Unspent, 1=Spent, 2=Locked, etc.
    pub mined_height: Option<u64>,   // Block height when mined
    pub block_hash: Option<String>,  // Block hash when mined (hex string)
    pub spent_in_tx_id: Option<u64>, // Transaction ID where spent

    // Timestamps
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl TryFrom<&StoredOutput> for WalletOutput {
    type Error = WalletError;

    fn try_from(o: &StoredOutput) -> WalletResult<Self> {
        Ok(WalletOutput::new_with_rangeproof(
            TransactionOutputVersion::get_current_version(),
            MicroMinotari::from(o.value),
            TariKeyId::from_str(&o.commitment_mask_key).map_err(DataStructureError::InvalidKeyId)?,
            serde_json::from_str(&o.features_json).map_err(|e| {
                SerializationError::SerdeSerializationError(format!("Could not convert json into OutputFeatures: {e}"))
            })?,
            TariScript::from_bytes(o.script.as_slice())?,
            ExecutionStack::from_bytes(o.input_data.as_slice())?,
            TariKeyId::from_str(&o.script_key).map_err(DataStructureError::InvalidKeyId)?,
            CompressedPublicKey::from_vec(&o.sender_offset_public_key).map(|e| {
                DataStructureError::InvalidPublicKey(format!("Could not deserialize sender offset public key: {e}"))
            })?,
            ComAndPubSignature::new(
                CompressedCommitment::from_vec(&o.metadata_signature_ephemeral_commitment).map_err(|e| {
                    DataStructureError::InvalidCommitment(format!("Could not deserialize ephemeral commitment: {e}"))
                })?,
                CompressedPublicKey::from_vec(&o.metadata_signature_ephemeral_pubkey).map_err(|e| {
                    DataStructureError::InvalidPublicKey(format!("Could not deserialize ephemeral public key: {e}"))
                })?,
                PrivateKey::from_vec(&o.metadata_signature_u_a)
                    .map_err(|e| DataStructureError::InvalidPrivateKey(format!("Could not deserialize u_a: {e}")))?,
                PrivateKey::from_vec(&o.metadata_signature_u_x)
                    .map_err(|e| DataStructureError::InvalidPrivateKey(format!("Could not deserialize u_x: {e}")))?,
                PrivateKey::from_vec(&o.metadata_signature_u_y)
                    .map_err(|e| DataStructureError::InvalidPrivateKey(format!("Could not deserialize u_y: {e}")))?,
            ),
            o.script_lock_height,
            BorshDeserialize::deserialize(&mut o.covenant.as_bytes()).map_err(|e| {
                SerializationError::BorshDeserializationError(format!(
                    "Could not create covenant from stored bytes: {e}"
                ))
            })?,
            EncryptedData::from_bytes(&o.encrypted_data)
                .map_err(|e| DataStructureError::InvalidEncryptedData(e.to_string()))?,
            MicroMinotari::from(o.minimum_value_promise),
            match o.rangeproof {
                Some(bytes) => Some(
                    RangeProof::from_canonical_bytes(&bytes)
                        .map_err(|e| DataStructureError::InvalidRangeProof(e.to_string()))?,
                ),
                None => None,
            },
            MemoField::from_bytes(&o.payment_id),
        ))
    }
}

// impl StoredOutput {
// fn from_wallet_output(o: &WalletOutput, wallet_id: u32) -> WalletResult<Self> {
// Ok(StoredOutput {
// id: None, // Will be set by database
// wallet_id,
// commitment: (),
// hash: (),
// value: (),
// commitment_mask_key: (),
// script_key: (),
// script: (),
// input_data: (),
// covenant: (),
// features_json: (),
// maturity: (),
// script_lock_height: (),
// sender_offset_public_key: (),
// metadata_signature_ephemeral_commitment: (),
// metadata_signature_ephemeral_pubkey: (),
// metadata_signature_u_a: (),
// metadata_signature_u_x: (),
// metadata_signature_u_y: (),
// encrypted_data: (),
// minimum_value_promise: (),
// payment_id: (),
// rangeproof: (),
// status: (),
// mined_height: (),
// block_hash: (),
// spent_in_tx_id: (),
// created_at: (),
// updated_at: (),
// })
// }
// }
