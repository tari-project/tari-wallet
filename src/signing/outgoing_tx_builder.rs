use std::sync::Arc;

use tari_common::configuration::Network;
use tari_common_types::{
    key_branches::TransactionKeyManagerBranch,
    tari_address::TariAddress,
    wallet_types::WalletType,
};
use tari_script::push_pubkey_script;
use tari_transaction_components::{
    consensus::ConsensusConstantsBuilder,
    key_manager::TransactionKeyManagerInterface,
    tari_amount::MicroMinotari,
    transaction_builder::FinalizedTransaction,
    transaction_components::{memo_field::MemoField, OutputFeatures, TransactionError, WalletOutputBuilder},
    TransactionBuilder,
};

use crate::{
    key_manager::TransactionKeyManager,
    prepare::{
        input_selector::{InputSelector, UtxoSelection},
        output_converter::OutputConverter,
    },
    WalletError,
    WalletResult,
    WalletStorage,
};

pub struct OutgoingTxBuilder {
    database: Arc<dyn WalletStorage>,
    wallet_id: u32,
    transaction_key_manager: TransactionKeyManager,
}

impl OutgoingTxBuilder {
    fn new(database: Arc<dyn WalletStorage>, wallet_id: u32, transaction_key_manager: TransactionKeyManager) -> Self {
        Self {
            database,
            wallet_id,
            transaction_key_manager,
        }
    }

    pub async fn build(database: Arc<dyn WalletStorage>, wallet_id: u32) -> WalletResult<Self> {
        let stored_wallet = database
            .get_wallet_by_id(wallet_id)
            .await?
            .ok_or_else(|| WalletError::ResourceNotFound(format!("Wallet with ID {} not found", wallet_id,)))?;
        let transaction_key_manager = TransactionKeyManager::build(
            database.clone(),
            stored_wallet.master_key,
            WalletType::default(),
            wallet_id,
        )
        .await?;

        Ok(Self::new(database, wallet_id, transaction_key_manager))
    }

    pub async fn build_tx(
        &self,
        network: Network,
        dest_address: TariAddress,
        amount: MicroMinotari,
        fee_per_gram: MicroMinotari,
        payment_id: MemoField,
    ) -> WalletResult<FinalizedTransaction> {
        let consensus_constants = ConsensusConstantsBuilder::new(network).build();
        let builder_key_manager = self.transaction_key_manager.clone().as_interface();
        let mut builder = TransactionBuilder::new(consensus_constants, builder_key_manager, network)
            .await
            .map_err(|err| TransactionError::BuilderError(err.to_string()))?;

        let (commitment_mask_key, script_key) = self
            .transaction_key_manager
            .as_interface()
            .get_next_commitment_mask_and_script_key()
            .await?;

        let sender_offset = self
            .transaction_key_manager
            .get_next_key(TransactionKeyManagerBranch::SenderOffset.get_branch_key())
            .await
            .unwrap();

        let output_builder_key_manager = self.transaction_key_manager.clone().as_interface();

        let script_spending_key = output_builder_key_manager
            .stealth_address_script_spending_key(&commitment_mask_key.key_id, dest_address.public_spend_key())
            .await?;
        let script = push_pubkey_script(&script_spending_key);

        let recipient_output = WalletOutputBuilder::new(amount, commitment_mask_key.key_id)
            .with_features(OutputFeatures::default())
            .with_script(script)
            .encrypt_data_for_recovery(&output_builder_key_manager, None, payment_id.clone())
            .await?
            .with_input_data(Default::default())
            .with_sender_offset_public_key(sender_offset.pub_key)
            .with_script_key(script_key.key_id)
            .with_minimum_value_promise(0.into())
            .sign_as_sender_and_receiver_verified(&output_builder_key_manager, &sender_offset.key_id, &dest_address)
            .await?
            .try_build(&output_builder_key_manager)
            .await?;

        let input_selector = InputSelector::new(self.wallet_id, self.database.clone());
        let unspent_outputs = input_selector.fetch_unspent_outputs(amount, fee_per_gram).await?;
        let output_converter = OutputConverter::new(self.transaction_key_manager.clone());
        for utxo in &unspent_outputs.utxos {
            let input = output_converter.convert_to_wallet_output(utxo.clone()).await?;
            builder
                .with_input(input)
                .await
                .map_err(|err| TransactionError::BuilderError(err.to_string()))?;
        }

        builder
            .with_lock_height(0)
            .with_fee_per_gram(fee_per_gram)
            .with_memo(payment_id)
            .add_recipient(dest_address, recipient_output, Some(sender_offset.key_id))
            .await
            .map_err(|err| TransactionError::BuilderError(err.to_string()))?;

        let finalized = builder
            .build()
            .await
            .map_err(|err| TransactionError::BuilderError(err.to_string()))?;

        self.lock_outputs(&unspent_outputs).await?;

        Ok(finalized)
    }

    async fn lock_outputs(&self, unspent_outputs: &UtxoSelection) -> WalletResult<()> {
        let output_ids: Vec<u32> = unspent_outputs.utxos.iter().filter_map(|o| o.id).collect();
        self.database.mark_outputs_locked(&output_ids).await?;
        Ok(())
    }
}
