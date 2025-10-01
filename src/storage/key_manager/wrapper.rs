use std::ops::{Deref, DerefMut};

use tari_common_types::{seeds::cipher_seed::CipherSeed, wallet_types::WalletType};
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{TransactionKeyManagerInterface, TransactionKeyManagerWrapper},
};

use crate::{key_manager::TransactionKeyManagerWalletStorage, EncryptionError, WalletResult};

#[derive(Clone)]
pub struct TransactionKeyManager(TransactionKeyManagerWrapper<TransactionKeyManagerWalletStorage>);

impl TransactionKeyManager {
    pub async fn build(master_seed: CipherSeed, wallet_type: WalletType) -> WalletResult<Self> {
        let seed = tari_common_types::seeds::cipher_seed::CipherSeed::from_enciphered_bytes(
            &master_seed.encipher(None)?,
            None,
        )
        .map_err(|err| EncryptionError::DecryptionFailed(err.to_string()))?;
        let wrapper =
            TransactionKeyManagerWrapper::new(Some(seed), CryptoFactories::default(), wallet_type.into()).await?;
        Ok(Self(wrapper))
    }

    pub fn as_interface(&self) -> impl TransactionKeyManagerInterface + 'static {
        self.0.clone()
    }
}

impl Deref for TransactionKeyManager {
    type Target = TransactionKeyManagerWrapper<TransactionKeyManagerWalletStorage>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TransactionKeyManager {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
