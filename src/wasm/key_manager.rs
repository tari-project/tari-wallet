use tari_transaction_components::key_manager::{MemoryKeyManager, TariKeyAndId, TransactionKeyManagerInterface};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = KeyManager)]
pub struct JsKeyManager {
    key_manager: MemoryKeyManager,
}

impl JsKeyManager {
    pub fn new(key_manager: MemoryKeyManager) -> Self {
        Self { key_manager }
    }
}

#[wasm_bindgen(js_class = KeyManager)]
impl JsKeyManager {
    #[wasm_bindgen(js_name = "walletType", getter)]
    pub async fn wallet_type(&self) -> String {
        self.key_manager.get_wallet_type().await.to_string()
    }

    #[wasm_bindgen(getter)]
    pub async fn birthday(&self) -> u16 {
        self.key_manager.get_birthday().await
    }

    #[wasm_bindgen(js_name = "getViewKey")]
    pub async fn get_view_key(&self) -> Result<JsTariKeyAndId, String> {
        self.key_manager
            .get_view_key()
            .await
            .map_err(|e| e.to_string())
            .map(|k| k.into())
    }
}

impl From<MemoryKeyManager> for JsKeyManager {
    fn from(key_manager: MemoryKeyManager) -> Self {
        JsKeyManager::new(key_manager)
    }
}

#[derive(Debug)]
#[wasm_bindgen(js_name = TariKeyAndId)]
pub struct JsTariKeyAndId {
    key_and_id: TariKeyAndId,
}

impl JsTariKeyAndId {
    pub fn new(key_and_id: TariKeyAndId) -> Self {
        Self { key_and_id }
    }
}

#[wasm_bindgen(js_class = KeyManager)]
impl JsTariKeyAndId {
    #[wasm_bindgen(js_name = "keyId", getter)]
    pub async fn key_id(&self) -> String {
        self.key_and_id.key_id.to_string()
    }

    #[wasm_bindgen(js_name = "pubKey", getter)]
    pub async fn pub_key(&self) -> String {
        self.key_and_id.pub_key.to_string()
    }
}

impl From<TariKeyAndId> for JsTariKeyAndId {
    fn from(key_and_id: TariKeyAndId) -> Self {
        JsTariKeyAndId::new(key_and_id)
    }
}
