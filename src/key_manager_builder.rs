use std::{any, sync::Arc};

use tari_common_types::{seeds::cipher_seed::CipherSeed, wallet_types::WalletType};
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{memory_key_manager::MemoryKeyManagerBackend, TransactionKeyManagerWrapper},
};

#[derive(Debug, Clone, Default)]
pub struct KeyManagerBuilder {}

impl KeyManagerBuilder {
    pub async fn try_build(self) -> Result<TransactionKeyManagerWrapper<MemoryKeyManagerBackend>, anyhow::Error> {
        Ok(TransactionKeyManagerWrapper::new(
            CipherSeed::new(),
            MemoryKeyManagerBackend::new(),
            CryptoFactories::default(),
            Arc::new(WalletType::DerivedKeys),
        )
        .await?)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_key_manager_builder() {
        let key_manager = KeyManagerBuilder::default().build();
    }
}
