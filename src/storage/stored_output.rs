use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tari_common_types::types::{
    ComAndPubSignature,
    CompressedCommitment,
    CompressedPublicKey,
    FixedHash,
    PrivateKey,
    RangeProof,
};
use tari_script::{ExecutionStack, TariScript};
use tari_transaction_components::{
    key_manager::{TariKeyId, TransactionKeyManagerInterface},
    transaction_components::{EncryptedData, MemoField, TransactionOutputVersion, WalletOutput},
    MicroMinotari,
};
use tari_utilities::byte_array::ByteArray;

use crate::{events::BlockInfo, DataStructureError, OutputStatus, SerializationError, WalletError, WalletResult};

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
    pub status: u32,                    // 0=Unspent, 1=Spent, 2=Locked, etc.
    pub mined_height: Option<u64>,      // Block height when mined
    pub block_hash: Option<String>,     // Block hash when mined (hex string)
    pub spent_in_tx_id: Option<u64>,    // Transaction ID where spent
    pub received_in_tx_id: Option<u64>, // Transaction ID received in

    // Timestamps
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl TryFrom<&StoredOutput> for WalletOutput {
    type Error = WalletError;

    fn try_from(o: &StoredOutput) -> WalletResult<Self> {
        Ok(WalletOutput::new_from_parts(
            TransactionOutputVersion::get_current_version(),
            MicroMinotari::from(o.value),
            TariKeyId::from_str(&o.commitment_mask_key).map_err(DataStructureError::InvalidKeyId)?,
            serde_json::from_str(&o.features_json).map_err(|e| {
                SerializationError::SerdeSerializationError(format!("Could not convert json into OutputFeatures: {e}"))
            })?,
            TariScript::from_bytes(o.script.as_slice())?,
            ExecutionStack::from_bytes(o.input_data.as_slice())?,
            TariKeyId::from_str(&o.script_key).map_err(DataStructureError::InvalidKeyId)?,
            CompressedPublicKey::from_vec(&o.sender_offset_public_key).map_err(|e| {
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
            match &o.rangeproof {
                Some(bytes) => Some(
                    RangeProof::from_canonical_bytes(&bytes)
                        .map_err(|e| DataStructureError::InvalidRangeProof(e.to_string()))?,
                ),
                None => None,
            },
            MemoField::from_bytes(&o.payment_id),
            FixedHash::try_from(o.hash.clone()).map_err(|e| DataStructureError::InvalidHash(e.to_string()))?,
            CompressedCommitment::from_vec(&o.commitment)
                .map_err(|e| DataStructureError::InvalidCommitment(format!("Could not deserialize commitment: {e}")))?,
        ))
    }
}

impl StoredOutput {
    async fn from_wallet_output<KM: TransactionKeyManagerInterface>(
        wallet_id: u32,
        o: &WalletOutput,
        bi: Option<&BlockInfo>,
    ) -> WalletResult<Self> {
        let tx_output = o.to_transaction_output()?;

        let mut covenant = Vec::new();
        BorshSerialize::serialize(o.covenant(), &mut covenant)
            .map_err(|err| SerializationError::BorshSerializationError(err.to_string()))?;

        Ok(StoredOutput {
            id: None, // Will be set by database
            wallet_id,
            commitment: tx_output.commitment.to_vec(),
            hash: tx_output.hash().to_vec(),
            value: o.value().into(),
            commitment_mask_key: o.commitment_mask_key_id().to_string(),
            script_key: o.script_key_id().to_string(),
            script: o.script().to_bytes(),
            input_data: o.input_data().to_bytes(),
            covenant,
            features_json: serde_json::to_string(o.features())
                .map_err(|e| SerializationError::SerdeSerializationError(e.to_string()))?,
            maturity: o.features().maturity,
            script_lock_height: o.script_lock_height(),
            sender_offset_public_key: o.sender_offset_public_key().to_vec(),
            metadata_signature_ephemeral_commitment: o.metadata_signature().ephemeral_commitment().to_vec(),
            metadata_signature_ephemeral_pubkey: o.metadata_signature().ephemeral_pubkey().to_vec(),
            metadata_signature_u_a: o.metadata_signature().u_a().to_vec(),
            metadata_signature_u_x: o.metadata_signature().u_x().to_vec(),
            metadata_signature_u_y: o.metadata_signature().u_y().to_vec(),
            encrypted_data: o.encrypted_data().to_byte_vec(),
            minimum_value_promise: o.minimum_value_promise().into(),
            payment_id: o.payment_id().to_bytes(),
            rangeproof: o.range_proof().as_ref().map(|rp| rp.to_vec()),
            status: OutputStatus::Unspent as u32,
            mined_height: bi.map(|bi| bi.height),
            block_hash: bi.map(|bi| bi.hash.clone()),
            spent_in_tx_id: None,
            received_in_tx_id: None,
            created_at: None,
            updated_at: None,
        })
    }
}
