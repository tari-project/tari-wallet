use std::{str::FromStr, sync::Arc};

use tari_common::configuration::Network;
use tari_common_types::{
    key_branches::TransactionKeyManagerBranch,
    seeds::seed_words::SeedWords,
    tari_address::{TariAddress, TariAddressFeatures},
    transaction::TxId,
    wallet_types::WalletType,
};
use tari_script::{script, ExecutionStack};
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{TariKeyId, TransactionKeyManagerInterface},
    tari_amount::MicroMinotari,
    transaction_components::{
        covenants::Covenant,
        memo_field::{MemoField, TxType},
        OutputFeatures,
        TransactionOutput,
        TransactionOutputVersion,
        WalletOutput,
    },
};

use crate::{
    key_manager::{TransactionKeyManager, TransactionKeyManagerWalletStorage},
    models::{
        marshal_output_pair::{MarshalOutputPair, OutputPair},
        transaction_metadata::TransactionMetadata,
        types::{
            get_supported_version,
            OneSidedTransactionInfo,
            PaymentRecipient,
            PrepareOneSidedTransactionForSigningResult,
        },
    },
    prepare::{
        input_selector::{InputSelector, UtxoSelection},
        output_converter::OutputConverter,
    },
    util::key_id::make_key_id_export_safe,
    KeyManagementError,
    Wallet,
    WalletError,
    WalletResult,
    WalletStorage,
};

pub struct OneSidedTransaction {
    database: Arc<dyn WalletStorage>,
    wallet_id: u32,
    wallet: Wallet<TransactionKeyManagerWalletStorage>,
    transaction_key_manager: TransactionKeyManager,
    output_converter: OutputConverter,
}

impl OneSidedTransaction {
    fn new(
        database: Arc<dyn WalletStorage>,
        wallet_id: u32,
        wallet: Wallet<TransactionKeyManagerWalletStorage>,
        transaction_key_manager: TransactionKeyManager,
        output_converter: OutputConverter,
    ) -> Self {
        Self {
            database,
            wallet_id,
            wallet,
            transaction_key_manager,
            output_converter,
        }
    }

    pub async fn build(database: Arc<dyn WalletStorage>, wallet_id: u32) -> WalletResult<Self> {
        let stored_wallet = database
            .get_wallet_by_id(wallet_id)
            .await?
            .ok_or_else(|| WalletError::ResourceNotFound(format!("Wallet with ID {} not found", wallet_id,)))?;
        // TODO: we need to be able to create a wallet (to get dual address) from view key only
        let seed_phrase = stored_wallet.seed_phrase.ok_or_else(|| {
            WalletError::InternalError(format!("Wallet with ID {} does not have a seed phrase", wallet_id,))
        })?;
        let seed_words =
            SeedWords::from_str(&seed_phrase).map_err(|e| KeyManagementError::SeedPhraseError(e.to_string()))?;
        let network = Network::default(); // TODO: fetch network from somewhere

        let transaction_key_manager = TransactionKeyManager::build(
            database.clone(),
            stored_wallet.master_key,
            WalletType::default(),
            wallet_id,
        )
        .await?;

        let storage = TransactionKeyManagerWalletStorage::build(database.clone(), wallet_id).await?;

        let wallet = Wallet::new_from_seed_phrase(
            &seed_words,
            None,
            CryptoFactories::default(),
            Arc::new(WalletType::DerivedKeys),
            storage,
            network,
        )
        .await?;

        let output_converter = OutputConverter::new(transaction_key_manager.clone());

        Ok(Self::new(
            database,
            wallet_id,
            wallet,
            transaction_key_manager,
            output_converter,
        ))
    }

    async fn build_marshal_output_pair(
        &self,
        output: WalletOutput,
        sender_offset_key_id: Option<TariKeyId>,
    ) -> WalletResult<MarshalOutputPair> {
        let nonce = self
            .transaction_key_manager
            .get_next_key(TransactionKeyManagerBranch::KernelNonce.get_branch_key())
            .await?;
        let output_pair = OutputPair {
            output,
            kernel_nonce: nonce.key_id,
            sender_offset_key_id,
        };

        MarshalOutputPair::marshal(&self.transaction_key_manager.as_interface(), output_pair).await
    }

    async fn build_change_output(
        &self,
        unspent_outputs: &UtxoSelection,
        sender_address: &TariAddress,
        original_payment_id: &MemoField,
        recipient: &PaymentRecipient,
    ) -> WalletResult<Option<MarshalOutputPair>> {
        if !unspent_outputs.requires_change_output {
            return Ok(None);
        }

        let change_amount = unspent_outputs
            .total_value
            .checked_sub(unspent_outputs.fee_with_change)
            .ok_or_else(|| {
                WalletError::InsufficientFunds(format!(
                    "You are spending more than you're providing: provided {}, required {}.",
                    unspent_outputs.total_value, unspent_outputs.fee_with_change
                ))
            })?;
        if change_amount <= MicroMinotari::zero() {
            return Ok(None);
        }

        let sender_offset_public = self
            .transaction_key_manager
            .get_next_key(TransactionKeyManagerBranch::SenderOffset.get_branch_key())
            .await
            .map_err(|e| e.to_string())?;

        let (change_commitment_mask_key, change_script_key) = self
            .transaction_key_manager
            .get_next_commitment_mask_and_script_key()
            .await?;

        let sender_one_sided = true;
        let payment_id_recipient_address = match original_payment_id.get_type() {
            TxType::PaymentToOther => recipient.address.clone(),
            TxType::PaymentToSelf |
            TxType::CoinSplit |
            TxType::CoinJoin |
            TxType::ValidatorNodeRegistration |
            TxType::CodeTemplateRegistration |
            TxType::ClaimAtomicSwap |
            TxType::HtlcAtomicSwapRefund => sender_address.clone(),
            _ => TariAddress::default(),
        };
        let payment_id = MemoField::new_transaction_info(
            payment_id_recipient_address,
            recipient.amount,
            unspent_outputs.fee_with_change + change_amount,
            sender_one_sided,
            original_payment_id.get_type(),
            Vec::new(),
            original_payment_id.payment_id_as_bytes(),
        )
        .map_err(|e| e.to_string())?;

        let change_script = script!(PushPubKey(Box::new(change_script_key.pub_key))).map_err(|e| e.to_string())?;

        let encrypted_data = self
            .transaction_key_manager
            .encrypt_data_for_recovery(
                &change_commitment_mask_key.key_id,
                None,
                change_amount.as_u64(),
                payment_id.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;

        let output_version = TransactionOutputVersion::get_current_version();
        let features = OutputFeatures::default();
        let covenant = Covenant::default();
        let minimum_value_promise = MicroMinotari::zero();
        let metadata_message = TransactionOutput::metadata_signature_message_from_parts(
            &output_version,
            &change_script,
            &features,
            &covenant,
            &encrypted_data,
            &minimum_value_promise,
        );
        let metadata_sig = self
            .transaction_key_manager
            .get_metadata_signature(
                &change_commitment_mask_key.key_id,
                &change_amount.into(),
                &sender_offset_public.key_id,
                &output_version,
                &metadata_message,
                features.range_proof_type,
            )
            .await
            .map_err(|e| e.to_string())?;

        let export_safe_change_script_key_id =
            make_key_id_export_safe(&self.transaction_key_manager, &change_script_key.key_id).await?;
        let change_wallet_output = WalletOutput::new_current_version(
            change_amount,
            change_commitment_mask_key.key_id,
            features,
            change_script,
            ExecutionStack::default(),
            export_safe_change_script_key_id,
            sender_offset_public.pub_key.clone(),
            metadata_sig,
            0,
            Covenant::default(),
            encrypted_data,
            minimum_value_promise,
            payment_id,
            &self.transaction_key_manager.as_interface(),
        )
        .await
        .map_err(|e| e.to_string())?;

        Ok(Some(
            self.build_marshal_output_pair(change_wallet_output, Some(sender_offset_public.key_id))
                .await?,
        ))
    }

    async fn get_inputs(&self, unspent_outputs: &UtxoSelection) -> WalletResult<Vec<MarshalOutputPair>> {
        let mut result = vec![];
        for utxo in &unspent_outputs.utxos {
            let wallet_output = self.output_converter.convert_to_wallet_output(utxo.clone()).await?;
            let input = self.build_marshal_output_pair(wallet_output, None).await?;
            result.push(input);
        }
        Ok(result)
    }

    async fn lock_outputs(&self, unspent_outputs: &UtxoSelection) -> WalletResult<()> {
        let output_ids: Vec<u32> = unspent_outputs.utxos.iter().filter_map(|o| o.id).collect();
        self.database.mark_outputs_locked(&output_ids).await?;
        Ok(())
    }

    pub async fn prepare(
        &self,
        dest_address: TariAddress,
        amount: MicroMinotari,
        fee_per_gram: MicroMinotari,
        payment_id: MemoField,
    ) -> WalletResult<PrepareOneSidedTransactionForSigningResult> {
        let recipient = PaymentRecipient {
            amount,
            output_features: OutputFeatures::default(),
            address: dest_address.clone(),
        };
        let sender_address = self
            .wallet
            .get_dual_address(TariAddressFeatures::create_one_sided_only(), None)
            .await?;

        let payment_id = self.get_payment_id(&sender_address, &dest_address, fee_per_gram, payment_id);
        let tx_id = TxId::new_random();

        let input_selector = InputSelector::new(self.wallet_id, self.database.clone());
        let unspent_outputs = input_selector.fetch_unspent_outputs(amount, fee_per_gram).await?;

        let inputs = self.get_inputs(&unspent_outputs).await?;

        let change_output = self
            .build_change_output(&unspent_outputs, &sender_address, &payment_id, &recipient)
            .await?;
        self.lock_outputs(&unspent_outputs).await?;

        let metadata = TransactionMetadata::new(unspent_outputs.fee(), 0);

        let info = OneSidedTransactionInfo {
            payment_id,
            recipient,
            change_output,
            inputs,
            outputs: vec![],
            metadata,
            sender_address,
        };

        Ok(PrepareOneSidedTransactionForSigningResult {
            version: get_supported_version(),
            tx_id,
            info,
        })
    }

    fn get_payment_id(
        &self,
        sender_address: &TariAddress,
        dest_address: &TariAddress,
        fee_per_gram: MicroMinotari,
        payment_id: MemoField,
    ) -> MemoField {
        let mut payment_id = payment_id.clone();
        if dest_address.features().contains(TariAddressFeatures::PAYMENT_ID) {
            payment_id = MemoField::open(dest_address.get_memo_field_payment_id_bytes(), TxType::PaymentToOther);
        }
        payment_id
            .clone()
            .add_sender_address(
                sender_address.clone(),
                true,
                fee_per_gram,
                if dest_address == sender_address {
                    Some(TxType::PaymentToSelf)
                } else {
                    Some(TxType::PaymentToOther)
                },
            )
            .unwrap_or(payment_id)
    }
}
