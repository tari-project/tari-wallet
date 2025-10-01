//! Wallet functionality for Tari wallets
//!
//! This module provides the core wallet struct and operations for managing
//! master keys, seed phrases, and wallet metadata.

use std::{collections::HashMap, sync::Arc};

use tari_common::configuration::Network;
use tari_common_types::{
    seeds::{cipher_seed::CipherSeed, mnemonic::Mnemonic, seed_words::SeedWords},
    tari_address::{TariAddress, TariAddressFeatures},
    wallet_types::WalletType,
};
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{
        error::KeyManagerServiceError,
        TransactionKeyManagerBackend,
        TransactionKeyManagerInterface,
        TransactionKeyManagerWrapper,
    },
};
use tari_utilities::SafePassword;

/// Core wallet struct containing master key, birthday, and metadata
#[derive(Clone)]
pub struct Wallet<KMBackend> {
    /// Wallet metadata for additional configuration and state
    metadata: WalletMetadata,
    // Key manager used by the wallet
    key_manager: TransactionKeyManagerWrapper<KMBackend>,
    // network
    network: Network,
}

/// Wallet metadata containing additional configuration and state information
#[derive(Debug, Clone, Default)]
pub struct WalletMetadata {
    /// Optional wallet label/name
    pub label: Option<String>,
    /// Additional custom properties
    pub properties: HashMap<String, String>,
}

impl<KMBackend> Wallet<KMBackend>
where KMBackend: TransactionKeyManagerBackend + 'static
{
    /// Create a new wallet with the given master key and birthday
    pub async fn new(
        master_seed: Option<CipherSeed>,
        crypto_factories: CryptoFactories,
        wallet_type: Arc<WalletType>,
        network: Network,
    ) -> Self {
        let key_manager = TransactionKeyManagerWrapper::new(master_seed, crypto_factories, wallet_type)
            .await
            .expect("Failed to create key manager");
        Self {
            key_manager,
            metadata: WalletMetadata::default(),
            network,
        }
    }

    pub fn key_manager(&self) -> &TransactionKeyManagerWrapper<KMBackend> {
        &self.key_manager
    }

    /// Create a new wallet from a seed phrase and optional passphrase
    pub async fn new_from_seed_phrase(
        seed_words: &SeedWords,
        passphrase: Option<SafePassword>,
        crypto_factories: CryptoFactories,
        wallet_type: Arc<WalletType>,
        network: Network,
    ) -> Result<Self, String> {
        // Convert seed phrase to master key
        let master_key = match CipherSeed::from_mnemonic(seed_words, passphrase) {
            Ok(seed) => seed,
            Err(e) => return Err(format!("Failed to create CipherSeed from mnemonic: {}", e)),
        };

        Ok(Wallet::new(Some(master_key), crypto_factories, wallet_type, network).await)
    }

    /// Generate a new wallet with random entropy
    ///
    /// Creates a wallet with completely random 32-byte master key entropy.
    /// Note: The passphrase parameter is included for API consistency but is not
    /// currently used since we generate random entropy directly rather than
    /// deriving from a mnemonic phrase.
    pub async fn generate_random(
        crypto_factories: CryptoFactories,
        wallet_type: Arc<WalletType>,
        network: Network,
    ) -> Self {
        let master_key = CipherSeed::random();
        Wallet::new(Some(master_key), crypto_factories, wallet_type, network).await
    }

    /// Get the wallet birthday (creation timestamp)
    pub async fn birthday(&self) -> u16 {
        self.key_manager.get_birthday().await.unwrap_or_default()
    }

    /// Get a reference to the wallet metadata
    pub fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }

    /// Get a mutable reference to the wallet metadata
    pub fn metadata_mut(&mut self) -> &mut WalletMetadata {
        &mut self.metadata
    }

    /// Set the wallet label
    pub fn set_label(&mut self, label: Option<String>) {
        self.metadata.label = label;
    }

    /// Get the wallet label
    pub fn label(&self) -> Option<&String> {
        self.metadata.label.as_ref()
    }

    /// Add a custom property to the wallet metadata
    pub fn set_property(&mut self, key: String, value: String) {
        self.metadata.properties.insert(key, value);
    }

    /// Get a custom property from the wallet metadata
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.metadata.properties.get(key)
    }

    /// Remove a custom property from the wallet metadata
    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        self.metadata.properties.remove(key)
    }

    /// Export the original seed phrase if available
    ///
    /// Returns the original seed phrase that was used to create this wallet.
    /// Returns an error if the wallet was created using `generate_new()` or other
    /// methods that don't use a seed phrase.
    pub fn export_seed_phrase(&self) -> Result<String, String> {
        Err("Export this from the key manager".to_string())
    }

    /// Generate a dual address with view and spend keys
    ///
    /// Creates a dual Tari address using derived view and spend keys from the master key.
    /// This allows for stealth payments and other advanced functionality.
    pub async fn get_dual_address(
        &self,
        features: TariAddressFeatures,
        payment_id: Option<Vec<u8>>,
    ) -> Result<TariAddress, KeyManagerServiceError> {
        let view_key = self.key_manager.get_view_key().await?;
        let spend_key = self.key_manager.get_spend_key().await?;
        Ok(TariAddress::new_dual_address(
            view_key.pub_key,
            spend_key.pub_key,
            self.network,
            features,
            payment_id,
        )?)
    }
}
