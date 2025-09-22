use serde::{Deserialize, Serialize};
use tari_common_types::types::{CompressedCommitment, CompressedPublicKey, PrivateKey};
use tari_crypto::{compressed_key::CompressedKey, keys::SecretKey};
use tari_script::{inputs, script, ExecutionStack, Opcode, TariScript};
use tari_transaction_components::{
    key_manager::{SerializedKeyString, TariKeyId, TransactionKeyManagerInterface},
    rpc::models::MinimalUtxoSyncInfo,
    transaction_components::{EncryptedData, MemoField, TransactionOutput, WalletOutput},
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

    async fn get_script_private_key_id<KM: TransactionKeyManagerInterface>(
        &self,
        script: &TariScript,
        key_manager: &KM,
    ) -> Result<Option<(ExecutionStack, TariKeyId)>, WalletError> {
        if script == &script!(Nop)? {
            // This is a nop, so we can just create a new key for the input stack.
            let private_key = PrivateKey::random(&mut rand::thread_rng());
            let key_id = key_manager.import_key(private_key).await?;
            let public_key = key_manager.get_public_key_at_key_id(&key_id).await?;
            return Ok(Some((inputs!(public_key), key_id)));
        }
        // this is push public key script, so lets see if we know the public key
        if let [Opcode::PushPubKey(public_key)] = script.as_slice() {
            // first lets check the commitment mask derived keys
            let result = key_manager
                .find_script_key_id_from_commitment_mask_key_id(&self.commitment_mask_key_id, Some(&public_key))
                .await?;
            if let Some(script_key_id) = result {
                return Ok(Some((ExecutionStack::default(), script_key_id)));
            }
            // now lets try stealth
            let spend_key = key_manager.get_spend_key().await?;
            let script_spending_key = key_manager
                .stealth_address_script_spending_key(&self.commitment_mask_key_id, &spend_key.pub_key)
                .await?;

            if script_spending_key == **public_key {
                let script_key = TariKeyId::Derived {
                    key: SerializedKeyString::from(self.commitment_mask_key_id.to_string()),
                };
                return Ok(Some((ExecutionStack::default(), script_key)));
            }
        }

        // no match

        Ok(None)
    }

    pub async fn to_wallet_output<KM: TransactionKeyManagerInterface>(
        &self,
        output: TransactionOutput,
        key_manager: &KM,
    ) -> Result<Option<WalletOutput>, WalletError> {
        match WalletOutput::new_imported(
            self.value,
            self.commitment_mask_key_id.clone(),
            self.memo.clone(),
            output,
            key_manager,
        )
        .await
        {
            Ok(wo) => Ok(Some(wo)),
            Err(_e) => Ok(None),
        }
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
