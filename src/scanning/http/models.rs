


use serde::{Deserialize, Serialize};
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use serde_wasm_bindgen;
use tari_transaction_components::{
    transaction_components::TransactionOutput,
};
/// HTTP API tip info response - matches the actual API structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTipInfoResponse {
    pub metadata: HttpChainMetadata,
}

/// HTTP API chain metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpChainMetadata {
    pub best_block_height: u64,
    pub best_block_hash: Vec<u8>,
    pub accumulated_difficulty: String,
    pub pruned_height: u64,
    pub timestamp: u64,
}

/// HTTP API block header response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaderResponse {
    pub hash: Vec<u8>,
    pub height: u64,
    pub timestamp: u64,
}

/// HTTP API single block response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleBlockResponse {
    pub block: HttpBlock,
}

/// HTTP API block structure  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlock {
    pub header: HttpBlockHeader,
    pub body: HttpBlockBody,
}

/// HTTP API block header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockHeader {
    pub height: u64,
    pub hash: Vec<u8>,
    pub timestamp: u64,
}

/// HTTP API block body structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockBody {
    pub outputs: Vec<TransactionOutput>,
}
