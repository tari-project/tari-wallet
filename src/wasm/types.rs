use borsh::BorshSerialize;
use tari_transaction_components::transaction_components::WalletOutput;
use tari_utilities::ByteArray;
use wasm_bindgen::prelude::*;

use crate::{BlockScanResult, TipInfo};

#[wasm_bindgen(js_name = TipInfo)]
#[derive(Debug, Clone)]
/// Chain tip information
pub struct JsTipInfo {
    /// Current best block height
    #[wasm_bindgen(js_name = "bestBlockHeight", readonly)]
    pub best_block_height: u64,
    /// Current best block hash
    #[wasm_bindgen(js_name = "bestBlockHash", getter_with_clone, readonly)]
    pub best_block_hash: Vec<u8>,
    /// Accumulated difficulty
    #[wasm_bindgen(js_name = "accumulatedDifficulty", getter_with_clone, readonly)]
    pub accumulated_difficulty: String,
    /// Pruned height (minimum height this node can provide complete blocks for)
    #[wasm_bindgen(js_name = "prunedHeight", readonly)]
    pub pruned_height: u64,
    /// Timestamp
    #[wasm_bindgen(js_name = "timestamp", getter_with_clone, readonly)]
    pub timestamp: js_sys::Date,
}

impl From<&TipInfo> for JsTipInfo {
    fn from(t: &TipInfo) -> Self {
        JsTipInfo {
            best_block_height: t.best_block_height,
            best_block_hash: t.best_block_hash.clone(),
            accumulated_difficulty: t.accumulated_difficulty.clone(),
            pruned_height: t.pruned_height,
            timestamp: timestamp_to_date(t.timestamp),
        }
    }
}

/// A wallet output is one where the value and spending key (blinding factor) are known. This can be used to
/// build both inputs and outputs (every input comes from an output)
#[wasm_bindgen(js_name = WalletOutput)]
#[derive(Debug, Clone)]
pub struct JsWalletOutput {
    #[wasm_bindgen(readonly)]
    pub version: u8,
    #[wasm_bindgen(readonly)]
    pub value: u64,
    #[wasm_bindgen(js_name = "commitmentMaskKeyId", getter_with_clone, readonly)]
    pub commitment_mask_key_id: String,
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub features: String,
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub script: Vec<u8>,
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub covenant: Vec<u8>,
    #[wasm_bindgen(js_name = "inputData", getter_with_clone, readonly)]
    pub input_data: Vec<u8>,
    #[wasm_bindgen(js_name = "scriptKeyId", getter_with_clone, readonly)]
    pub script_key_id: String,
    #[wasm_bindgen(js_name = "senderOffsetPublicKey", getter_with_clone, readonly)]
    pub sender_offset_public_key: String,
    #[wasm_bindgen(js_name = "metadataSignature", getter_with_clone, readonly)]
    pub metadata_signature: String,
    #[wasm_bindgen(js_name = "scriptLockHeight", readonly)]
    pub script_lock_height: u64,
    #[wasm_bindgen(js_name = "encryptedData", getter_with_clone, readonly)]
    pub encrypted_data: Vec<u8>,
    #[wasm_bindgen(js_name = "minimumValuePromise", readonly)]
    pub minimum_value_promise: u64,
    #[wasm_bindgen(js_name = "rangeProof", getter_with_clone, readonly)]
    pub range_proof: Option<Vec<u8>>,
    #[wasm_bindgen(js_name = "paymentId", getter_with_clone, readonly)]
    pub payment_id: Vec<u8>,
}

impl From<&WalletOutput> for JsWalletOutput {
    fn from(o: &WalletOutput) -> Self {
        let mut covenant = Vec::new();
        BorshSerialize::serialize(&o.covenant, &mut covenant).unwrap();

        JsWalletOutput {
            version: o.version.as_u8(),
            value: o.value.as_u64(),
            commitment_mask_key_id: o.commitment_mask_key_id.to_string(),
            features: serde_json::to_string(&o.features).expect("features"),
            script: o.script.to_bytes(),
            covenant,
            input_data: o.input_data.to_bytes(),
            script_key_id: o.script_key_id.to_string(),
            sender_offset_public_key: o.sender_offset_public_key.to_string(),
            metadata_signature: serde_json::to_string(&o.metadata_signature).expect("metadata_signature"),
            script_lock_height: o.script_lock_height,
            encrypted_data: o.encrypted_data.to_byte_vec(),
            minimum_value_promise: o.minimum_value_promise.0,
            range_proof: o.range_proof.as_ref().map(|rp| rp.to_vec()),
            payment_id: o.payment_id.to_bytes(),
        }
    }
}

/// Result of a block scan operation
#[wasm_bindgen(js_name = BlockScanResult)]
#[derive(Debug, Clone)]
pub struct JsBlockScanResult {
    /// Block height
    #[wasm_bindgen(readonly)]
    pub height: u64,
    /// Block hash
    #[wasm_bindgen(js_name = "blockHash", getter_with_clone, readonly)]
    pub block_hash: Vec<u8>,
    /// Wallet outputs extracted from transaction outputs
    #[wasm_bindgen(js_name = "walletOutputs", getter_with_clone, readonly)]
    pub wallet_outputs: Vec<JsWalletOutput>,
    /// Timestamp when block was mined
    #[wasm_bindgen(js_name = "minedTimestamp", getter_with_clone, readonly)]
    pub mined_timestamp: js_sys::Date,
}

impl From<&BlockScanResult> for JsBlockScanResult {
    fn from(r: &BlockScanResult) -> Self {
        JsBlockScanResult {
            height: r.height,
            block_hash: r.block_hash.clone(),
            wallet_outputs: r.wallet_outputs.iter().map(|o| o.into()).collect(),
            mined_timestamp: timestamp_to_date(r.mined_timestamp),
        }
    }
}

fn timestamp_to_date(timestamp: u64) -> js_sys::Date {
    let timestamp_in_ms = (timestamp as f64) * 1000.0;
    js_sys::Date::new(&JsValue::from_f64(timestamp_in_ms))
}
