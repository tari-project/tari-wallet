use crate::{
    key_manager::TransactionKeyManager, util::key_id::make_key_id_export_safe, SerializationError,
    StoredOutput, WalletError, WalletResult,
};
use borsh::BorshDeserialize;
use std::str::FromStr;
use tari_common_types::types::{ComAndPubSignature, CompressedCommitment, CompressedPublicKey};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_script::ExecutionStack;
use tari_script::TariScript;
use tari_transaction_components::{
    key_manager::TariKeyId,
    tari_amount::MicroMinotari,
    transaction_components::{memo_field::MemoField, EncryptedData, WalletOutput},
};
use tari_utilities::ByteArray;

pub struct OutputConverter {
    transaction_key_manager: TransactionKeyManager,
}

impl OutputConverter {
    pub fn new(transaction_key_manager: TransactionKeyManager) -> Self {
        Self {
            transaction_key_manager,
        }
    }

    pub async fn convert_to_wallet_output(&self, o: StoredOutput) -> WalletResult<WalletOutput> {
        let commitment_mask_key_id = TariKeyId::from_str(&o.commitment_mask_key)?;
        let features = serde_json::from_str(&o.features_json)
            .map_err(|err| WalletError::ConversionError(err.to_string()))?;
        let input_data = ExecutionStack::from_bytes(&o.input_data)?;
        let export_safe_script_key_id = make_key_id_export_safe(
            &self.transaction_key_manager,
            &TariKeyId::from_str(&o.script_key)?,
        )
        .await?;
        let sender_offset_public_key =
            CompressedPublicKey::from_canonical_bytes(&o.sender_offset_public_key)
                .map_err(|err| WalletError::ConversionError(err.to_string()))?;
        let metadata_signature = ComAndPubSignature::new(
            CompressedCommitment::from_canonical_bytes(&o.metadata_signature_ephemeral_commitment)
                .map_err(|err| WalletError::ConversionError(err.to_string()))?,
            CompressedPublicKey::from_canonical_bytes(&o.metadata_signature_ephemeral_pubkey)
                .map_err(|err| WalletError::ConversionError(err.to_string()))?,
            RistrettoSecretKey::from_canonical_bytes(&o.metadata_signature_u_a)
                .map_err(|err| WalletError::ConversionError(err.to_string()))?,
            RistrettoSecretKey::from_canonical_bytes(&o.metadata_signature_u_x)
                .map_err(|err| WalletError::ConversionError(err.to_string()))?,
            RistrettoSecretKey::from_canonical_bytes(&o.metadata_signature_u_y)
                .map_err(|err| WalletError::ConversionError(err.to_string()))?,
        );
        let script_lock_height = o.script_lock_height;
        let mut covenant = o.covenant.as_bytes();
        let covenant = BorshDeserialize::deserialize(&mut covenant)
            .map_err(|e| SerializationError::BorshDeserializationError(e.to_string()))?;
        let encrypted_data = EncryptedData::from_bytes(&o.encrypted_data)
            .map_err(|e| WalletError::ConversionError(e.to_string()))?;
        let minimum_value_promise = MicroMinotari(o.minimum_value_promise);
        let payment_id = MemoField::from_bytes(&o.payment_id);

        let script_bytes = &hex::decode(o.script).map_err(SerializationError::from)?;
        let script = TariScript::from_bytes(script_bytes)?;

        println!(
            "TODO: commitment_mask_key_id: {}, export_safe_script_key_id: {}",
            commitment_mask_key_id, export_safe_script_key_id
        );

        let wallet_output = WalletOutput::new_current_version(
            MicroMinotari(o.value),
            commitment_mask_key_id,
            features,
            script,
            input_data,
            export_safe_script_key_id.clone(),
            sender_offset_public_key,
            metadata_signature,
            script_lock_height,
            covenant,
            encrypted_data,
            minimum_value_promise,
            payment_id,
            &self.transaction_key_manager.as_interface(),
        )
        .await?;
        Ok(wallet_output)
    }
}
