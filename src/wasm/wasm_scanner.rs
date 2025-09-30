use std::{str::FromStr, sync::Arc};

use tari_common_types::{
    seeds::{cipher_seed::CipherSeed, mnemonic::Mnemonic, seed_words::SeedWords},
    types::{CompressedPublicKey, PrivateKey},
    wallet_types::{ProvidedKeysWallet, WalletType},
};
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{
        memory_key_manager::{create_memory_key_manager_from_seed, MemoryKeyManagerBackend},
        MemoryKeyManager,
        TransactionKeyManagerWrapper,
    },
};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

#[cfg(feature = "http")]
use crate::wasm::types::JsBlockScanResult;
use crate::{
    scanning::{http_scanner::HttpBlockchainScanner, BlockchainScanner},
    wasm::{key_manager::JsKeyManager, types::JsTipInfo},
};

const RANGEPROOF_SIZE: usize = 64;

#[wasm_bindgen(js_name = WasmScanner)]
pub struct WasmScanner {
    #[cfg(feature = "http")]
    http_scanner: HttpBlockchainScanner<TransactionKeyManagerWrapper<MemoryKeyManagerBackend>>,
    key_manager: MemoryKeyManager,
}

#[wasm_bindgen(js_class = WasmScanner)]
impl WasmScanner {
    #[wasm_bindgen(js_name = "fromSeedWords")]
    pub async fn from_seed_words(base_url: &str, seed_phrase: &str) -> Result<Self, String> {
        let seed_words = SeedWords::from_str(&seed_phrase).map_err(|e| e.to_string())?;
        let master_key = CipherSeed::from_mnemonic(&seed_words, None).map_err(|e| e.to_string())?;
        let key_manager = create_memory_key_manager_from_seed(master_key, RANGEPROOF_SIZE)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Self {
            #[cfg(feature = "http")]
            http_scanner: Self::build_http_scanner(base_url, &key_manager).await?,
            key_manager,
        })
    }

    #[wasm_bindgen(js_name = "fromKeys")]
    pub async fn from_keys(base_url: &str, view_key: &str, public_spend_key: &str) -> Result<Self, String> {
        let cipher = CipherSeed::new();
        let factory = CryptoFactories::new(RANGEPROOF_SIZE);
        let backend = MemoryKeyManagerBackend::new();
        let view_key = PrivateKey::from_hex(view_key).map_err(|e| format!("Invalid format of view key: {e}"))?;
        let public_spend_key = CompressedPublicKey::from_hex(public_spend_key)
            .map_err(|e| format!("Invalid format of public spend key: {e}"))?;
        let provided_keys = ProvidedKeysWallet {
            view_key,
            public_spend_key,
            private_spend_key: None,
            private_comms_key: None,
            birthday: None,
        };
        let wallet_type = WalletType::ProvidedKeys(provided_keys);
        let key_manager = TransactionKeyManagerWrapper::new(cipher, backend, factory, Arc::new(wallet_type))
            .await
            .map_err(|e| e.to_string())?;

        Ok(Self {
            #[cfg(feature = "http")]
            http_scanner: Self::build_http_scanner(base_url, &key_manager).await?,
            key_manager,
        })
    }

    async fn build_http_scanner(
        base_url: &str,
        key_manager: &TransactionKeyManagerWrapper<MemoryKeyManagerBackend>,
    ) -> Result<HttpBlockchainScanner<TransactionKeyManagerWrapper<MemoryKeyManagerBackend>>, String> {
        HttpBlockchainScanner::new(base_url.to_string(), key_manager.clone())
            .await
            .map_err(|e| format!("Failed to initialize HTTP scanner: {}", e))
    }

    #[wasm_bindgen(js_name = "getTipInfo")]
    pub async fn get_tip_info(&mut self) -> Result<JsTipInfo, String> {
        self.http_scanner
            .get_tip_info()
            .await
            .map_err(|e| format!("Failed to get tip info: {}", e))
            .map(|ti| (&ti).into())
    }

    #[cfg(feature = "http")]
    #[wasm_bindgen(js_name = "scanBlocks")]
    pub async fn scan_blocks(&mut self, start_height: u64, end_height: u64) -> Result<Vec<JsBlockScanResult>, String> {
        let scan_config = self
            .http_scanner
            .create_scan_config_with_wallet_keys(start_height, Some(end_height))
            .map_err(|e| e.to_string())?;

        let blocks = self
            .http_scanner
            .scan_blocks(scan_config)
            .await
            .map_err(|e| e.to_string())?;

        let mut scan_results = vec![];
        for block in &blocks {
            let result = JsBlockScanResult::from_block_scan_result(&self.key_manager, &block).await?;
            scan_results.push(result);
        }

        Ok(scan_results)
    }

    #[wasm_bindgen(js_name = "getKeyManager")]
    pub fn get_key_manager(&self) -> JsKeyManager {
        self.key_manager.clone().into()
    }
}
