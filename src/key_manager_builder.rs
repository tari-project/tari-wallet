use std::{any, sync::Arc};

use tari_common_types::{
    types::CompressedPublicKey,
    wallet_types::{ProvidedKeysWallet, WalletType},
};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{memory_key_manager::MemoryKeyManagerBackend, TransactionKeyManagerWrapper},
};

#[derive(Debug, Clone, Default)]
pub struct KeyManagerBuilder {
    wallet_type: Option<Arc<WalletType>>,
}

impl KeyManagerBuilder {
    #[must_use]
    pub fn with_view_key_and_spend_key(
        mut self,
        view_key: RistrettoSecretKey,
        spend_key: CompressedPublicKey,
        birthday: u16,
    ) -> Self {
        self.wallet_type = Some(Arc::new(WalletType::ProvidedKeys(ProvidedKeysWallet {
            view_key,
            birthday: Some(birthday),
            public_spend_key: spend_key,
            private_spend_key: None,
            private_comms_key: None,
        })));
        self
    }

    pub async fn try_build(self) -> Result<TransactionKeyManagerWrapper<MemoryKeyManagerBackend>, anyhow::Error> {
        if let Some(wallet_type) = self.wallet_type {
            match wallet_type.as_ref() {
                &WalletType::ProvidedKeys(_) => {
                    Ok(TransactionKeyManagerWrapper::new(None, CryptoFactories::default(), wallet_type).await?)
                },
                _ => {
                    todo!("Not implemented yet")
                },
            }
        } else {
            Err(anyhow::anyhow!("Missing field `{}`", any::type_name::<WalletType>()))
        }
    }
}
