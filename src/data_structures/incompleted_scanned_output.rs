use serde::{Deserialize, Serialize};
use tari_common_types::types::{CompressedCommitment, CompressedPublicKey};
use tari_crypto::compressed_key::CompressedKey;
use tari_transaction_components::{
    key_manager::TariKeyId,
    rpc::models::MinimalUtxoSyncInfo,
    transaction_components::{EncryptedData, MemoField},
    MicroMinotari,
};
use tari_utilities::ByteArray;

use crate::WalletError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncompleteScannedOutput {
    pub output_hash: Vec<u8>,
    pub value: MicroMinotari,
    pub commitment_mask_key_id: TariKeyId,
    pub sender_offset_public_key: CompressedPublicKey,
    pub encrypted_data: EncryptedData,
    pub memo: MemoField,
}

impl IncompleteScannedOutput {
    pub fn new(
        scanning_info: &ScanningOutputStruct,
        value: MicroMinotari,
        commitment_mask_key_id: TariKeyId,
        memo: MemoField,
    ) -> Result<Self, WalletError> {
        Ok(Self {
            output_hash: scanning_info.min_info.output_hash.clone(),
            value,
            commitment_mask_key_id,
            sender_offset_public_key: scanning_info.sender_offset_public_key.clone(),
            encrypted_data: scanning_info.encrypted_data.clone(),
            memo,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ScanningOutputStruct {
    pub min_info: MinimalUtxoSyncInfo,
    pub commitment: CompressedCommitment,
    pub encrypted_data: EncryptedData,
    pub sender_offset_public_key: CompressedPublicKey,
}

impl TryFrom<MinimalUtxoSyncInfo> for ScanningOutputStruct {
    type Error = WalletError;

    fn try_from(mim_info: MinimalUtxoSyncInfo) -> Result<Self, Self::Error> {
        let commitment = CompressedCommitment::from_canonical_bytes(&mim_info.commitment)
            .map_err(|e| WalletError::DataError(e.to_string()))?;
        let encrypted_data =
            EncryptedData::from_bytes(&mim_info.encrypted_data).map_err(|e| WalletError::DataError(e.to_string()))?;
        let sender_offset_public_key = CompressedKey::from_canonical_bytes(&mim_info.sender_offset_public_key)
            .map_err(|e| WalletError::DataError(e.to_string()))?;
        Ok(Self {
            min_info: mim_info,
            commitment,
            encrypted_data,
            sender_offset_public_key,
        })
    }
}
