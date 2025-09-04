//! HTTP-based blockchain scanner implementation
//!
//! This module provides an HTTP implementation of the BlockchainScanner trait
//! that connects to a Tari base node via HTTP API to scan for wallet outputs.
//!
//! ## Wallet Key Integration
//!
//! The HTTP scanner supports wallet key integration for identifying outputs that belong
//! to a specific wallet. To use wallet functionality:
//!
//! ```rust,no_run
//! use lightweight_wallet_libs::{
//!     scanning::{BlockchainScanner, HttpBlockchainScanner, ScanConfig},
//!     wallet::Wallet,
//! };
//!
//! async fn scan_with_wallet() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut scanner = HttpBlockchainScanner::new("http://127.0.0.1:18142".to_string()).await?;
//!     let wallet = Wallet::generate_new_with_seed_phrase(None)?;
//!
//!     // Create scan config with wallet keys
//!     let config = scanner.create_scan_config_with_wallet_keys(&wallet, 0, None)?;
//!
//!     // Scan for blocks with wallet key integration
//!     let results = scanner.scan_blocks(config).await?;
//!     println!("Found {} blocks with wallet outputs", results.len());
//!
//!     Ok(())
//! }
//! ```
// Native targets use reqwest
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use std::time::Duration;
// WASM targets use web-sys
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use std::time::Duration;

#[cfg(feature = "http")]
use async_trait::async_trait;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use reqwest::Client;
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use serde_wasm_bindgen;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    rpc::models::{BlockUtxoInfo, GetUtxosByBlockResponse, SyncUtxosByBlockResponse},
    transaction_components::{one_sided::shared_secret_to_output_encryption_key, TransactionError, TransactionOutput},
};
use tari_utilities::hex::Hex;
#[cfg(all(feature = "http", feature = "tracing"))]
use tracing::debug;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen::prelude::*;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen_futures::JsFuture;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use web_sys::{window, Request, RequestInit, RequestMode, Response};

use crate::{
    data_structures::incompleted_scanned_output::{IncompleteScannedOutput, ScanningOutputStruct},
    errors::{WalletError, WalletResult},
    extraction::ExtractionConfig,
    scanning::{BlockInfo, BlockScanResult, BlockchainScanner, ScanConfig, TipInfo},
    UtxoScanResult,
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
    pub accumulated_difficulty: Vec<u8>,
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
    pub hash: String,
    pub timestamp: u64,
}

/// HTTP API block body structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockBody {
    pub outputs: Vec<TransactionOutput>,
}

/// HTTP client for connecting to Tari base node
#[cfg(feature = "http")]
pub struct HttpBlockchainScanner<KM> {
    /// HTTP client for making requests (native targets)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    client: Client,
    /// Base URL for the HTTP API
    base_url: String,
    /// Request timeout (native targets only)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    timeout: Duration,
    key_manager: KM,
}

impl<KM> HttpBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    /// Create a new HTTP scanner with the given base URL
    pub async fn new(base_url: String, key_manager: KM) -> WalletResult<Self> {
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let timeout = Duration::from_secs(30);
            let client = Client::builder().timeout(timeout).build().map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to create HTTP client: {e}"
                )))
            })?;

            // Test the connection
            let test_url = format!("{base_url}/get_tip_info");
            let response = client.get(&test_url).send().await;
            if response.is_err() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to connect to {base_url}"
                    )),
                ));
            }
            Ok(Self {
                client,
                base_url,
                timeout,
                key_manager,
            })
        }

        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            // For WASM, we don't need to create a persistent client
            // web-sys creates requests on-demand

            // Test the connection with a simple GET request
            let test_url = format!("{}/get_tip_info", base_url);

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&test_url, &opts)?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "No window object available",
                ))
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to connect to {}",
                    base_url
                )))
            })?;

            let _resp: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Invalid response type",
                ))
            })?;

            Ok(Self { base_url, key_manager })
        }
    }

    /// Create a new HTTP scanner with custom timeout (native only)
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub async fn with_timeout(base_url: String, timeout: Duration, key_manager: KM) -> WalletResult<Self> {
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to create HTTP client: {e}"
            )))
        })?;

        // Test the connection
        let test_url = format!("{base_url}/get_tip_info");
        let response = client.get(&test_url).send().await;
        if response.is_err() {
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to connect to {base_url}")),
            ));
        }

        Ok(Self {
            client,
            base_url,
            timeout,
            key_manager,
        })
    }

    /// Create a new HTTP scanner with custom timeout (WASM - timeout ignored)
    #[cfg(all(feature = "http", target_arch = "wasm32"))]
    pub async fn with_timeout(base_url: String, _timeout: Duration, key_manager: KM) -> WalletResult<Self> {
        // WASM doesn't support timeouts in the same way, so we ignore the timeout parameter
        Self::new(base_url, key_manager).await
    }

    /// Get header by height - matches WASM example usage
    async fn get_header_by_height(&self, height: u64) -> WalletResult<HttpHeaderResponse> {
        let url = format!("{}/get_header_by_height", self.base_url);

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .get(&url)
                .query(&[("height", height)])
                .send()
                .await
                .map_err(|e| {
                    WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP request failed: {e}"
                    )))
                })?;

            if !response.status().is_success() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let header_response: HttpHeaderResponse = response.json().await.map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to parse response: {e}"
                )))
            })?;

            Ok(header_response)
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let url_with_params = format!("{}?height={}", url, height);

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&url_with_params, &opts)?;
            request.headers().set("Accept", "application/json")?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "No window object available",
                ))
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "HTTP request failed",
                ))
            })?;

            let response: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Invalid response type",
                ))
            })?;

            if !response.ok() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to get JSON response",
                ))
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to parse JSON response",
                ))
            })?;

            let header_response: HttpHeaderResponse = serde_wasm_bindgen::from_value(json_value).map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to deserialize response: {}",
                    e
                )))
            })?;

            Ok(header_response)
        }
    }

    /// Sync UTXOs by block - matches WASM example usage
    async fn sync_utxos_by_block(&self, start_header_hash: &str) -> WalletResult<SyncUtxosByBlockResponse> {
        let url = format!("{}/sync_utxos_by_block", self.base_url);
        let limit = 10u64;
        let page = 0u64;

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .get(&url)
                .query(&[
                    ("start_header_hash", start_header_hash),
                    ("limit", &limit.to_string()),
                    ("page", &page.to_string()),
                ])
                .send()
                .await
                .map_err(|e| {
                    WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP request failed: {e}"
                    )))
                })?;

            if !response.status().is_success() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let sync_response: SyncUtxosByBlockResponse = response.json().await.map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to parse response: {e}"
                )))
            })?;

            Ok(sync_response)
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let url_with_params = format!(
                "{}?start_header_hash={}&limit={}&page={}",
                url, start_header_hash, limit, page
            );

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&url_with_params, &opts)?;
            request.headers().set("Accept", "application/json")?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "No window object available",
                ))
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "HTTP request failed",
                ))
            })?;

            let response: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Invalid response type",
                ))
            })?;

            if !response.ok() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to get JSON response",
                ))
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to parse JSON response",
                ))
            })?;

            let sync_response: SyncUtxosByBlockResponse = serde_wasm_bindgen::from_value(json_value).map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to deserialize response: {}",
                    e
                )))
            })?;

            Ok(sync_response)
        }
    }

    async fn get_utxos_by_block(&self, current_header_hash: &str) -> WalletResult<GetUtxosByBlockResponse> {
        let url = format!("{}/get_utxos_by_block", self.base_url);

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self
                .client
                .get(&url)
                .query(&[("header_hash", current_header_hash)])
                .send()
                .await
                .map_err(|e| {
                    WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP request failed: {e}"
                    )))
                })?;

            if !response.status().is_success() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let sync_response: GetUtxosByBlockResponse = response.json().await.map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to parse response: {e}"
                )))
            })?;

            Ok(sync_response)
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let url_with_params = format!("{}?header_hash={}", url, current_header_hash);

            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&url_with_params, &opts)?;
            request.headers().set("Accept", "application/json")?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "No window object available",
                ))
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "HTTP request failed",
                ))
            })?;

            let response: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Invalid response type",
                ))
            })?;

            if !response.ok() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to get JSON response",
                ))
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to parse JSON response",
                ))
            })?;

            let sync_response: GetUtxosByBlockResponse = serde_wasm_bindgen::from_value(json_value).map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to deserialize response: {}",
                    e
                )))
            })?;

            Ok(sync_response)
        }
    }

    /// Convert bytes to hex string
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Create a scan config with wallet keys for block scanning
    pub fn create_scan_config_with_wallet_keys(
        &self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> WalletResult<ScanConfig> {
        let extraction_config = ExtractionConfig::default();

        Ok(ScanConfig {
            start_height,
            end_height,
            batch_size: 100,
            #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
            request_timeout: self.timeout,
            #[cfg(all(feature = "http", target_arch = "wasm32"))]
            request_timeout: std::time::Duration::from_secs(30), // Default for WASM
            extraction_config,
        })
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    async fn scan_for_recoverable_output(
        &self,
        output: &ScanningOutputStruct,
    ) -> WalletResult<Option<IncompleteScannedOutput>> {
        let (commitment_mask, value, memo) = match self
            .key_manager
            .try_output_key_recovery(&output.commitment, &output.encrypted_data, None)
            .await
        {
            Ok(value) => value,
            // Key manager errors here are actual errors and should not be suppressed.
            Err(TransactionError::KeyManagerError(e)) => return Err(TransactionError::KeyManagerError(e).into()),
            Err(_) => return Ok(None),
        };

        let output = IncompleteScannedOutput::new(output, value, commitment_mask, memo)?;
        Ok(Some(output))
    }

    /// Scan for one-sided payments
    async fn scan_for_one_sided_payment(
        &self,
        output: &ScanningOutputStruct,
    ) -> WalletResult<Option<IncompleteScannedOutput>> {
        let view_key = self.key_manager.get_view_key().await?;

        let shared_secret = self
            .key_manager
            .get_diffie_hellman_shared_secret(&view_key.key_id, &output.sender_offset_public_key)
            .await?;
        let recovery_key = shared_secret_to_output_encryption_key(&shared_secret)
            .map_err(|e| WalletError::ConversionError(e.to_string()))?;

        let (commitment_mask, value, memo) = match self
            .key_manager
            .try_output_key_recovery(&output.commitment, &output.encrypted_data, Some(recovery_key))
            .await
        {
            Ok(value) => value,
            // Key manager errors here are actual errors and should not be suppressed.
            Err(TransactionError::KeyManagerError(e)) => return Err(TransactionError::KeyManagerError(e).into()),
            Err(_) => return Ok(None),
        };

        let output = IncompleteScannedOutput::new(output, value, commitment_mask, memo)?;
        Ok(Some(output))
    }

    /// Fetch block range using the sync_utxos_by_block endpoint
    async fn fetch_block_range(&self, start_height: u64, end_height: u64) -> WalletResult<Vec<BlockUtxoInfo>> {
        // Get the starting header hash
        let start_header = self.get_header_by_height(start_height).await?;
        let mut current_header_hash = Self::bytes_to_hex(&start_header.hash);

        let mut all_blocks = Vec::new();
        let mut blocks_collected = 0;
        let max_blocks = (end_height - start_height + 1) as usize;

        #[cfg(feature = "tracing")]
        debug!(
            "Starting fetch_block_range from height {} to {} (max {} blocks)",
            start_height, end_height, max_blocks
        );

        while blocks_collected < max_blocks {
            // Use sync_utxos_by_block to get batch of blocks
            let sync_response = self.sync_utxos_by_block(&current_header_hash).await?;

            if sync_response.blocks.is_empty() {
                #[cfg(feature = "tracing")]
                debug!("No more blocks available from base node");
                break;
            }

            // Add all blocks from this response (we can't filter by height since it's not provided)
            for block in sync_response.blocks {
                all_blocks.push(block);
                blocks_collected += 1;

                // Stop if we've collected enough blocks
                if blocks_collected >= max_blocks {
                    break;
                }
            }

            // Check if we have a next header to continue with and haven't reached our limit
            if blocks_collected < max_blocks {
                if sync_response.next_header_to_scan.is_empty() {
                    #[cfg(feature = "tracing")]
                    debug!("No more headers to scan, reached end of available data");
                    break;
                } else {
                    current_header_hash = Self::bytes_to_hex(&sync_response.next_header_to_scan);
                    #[cfg(feature = "tracing")]
                    debug!(
                        "Continuing with next header: {} (collected {}/{} blocks)",
                        &current_header_hash[..16],
                        blocks_collected,
                        max_blocks
                    );
                }
            }
        }

        #[cfg(feature = "tracing")]
        debug!(
            "Fetched {} blocks for range {} to {}",
            all_blocks.len(),
            start_height,
            end_height
        );

        Ok(all_blocks)
    }
}

#[cfg(feature = "http")]
#[async_trait(?Send)]
impl<KM> BlockchainScanner for HttpBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    async fn scan_blocks(&mut self, config: ScanConfig) -> WalletResult<Vec<BlockScanResult>> {
        #[cfg(feature = "tracing")]
        debug!(
            "Starting HTTP block scan from height {} to {:?}",
            config.start_height, config.end_height
        );

        // Get tip info to determine end height
        let tip_info = self.get_tip_info().await?;
        let end_height = config.end_height.unwrap_or(tip_info.best_block_height);

        if config.start_height > end_height {
            return Ok(Vec::new());
        }

        // Fetch blocks using the new API
        let http_blocks = self.fetch_block_range(config.start_height, end_height).await?;

        let mut utxos = Vec::new();

        for http_block in http_blocks {
            let mut wallet_outputs = Vec::new();

            for output in &http_block.outputs {
                let scanned_output = output.clone().try_into()?;

                // Strategy 1: Regular recoverable outputs
                if let Some(wallet_output) = self.scan_for_recoverable_output(&scanned_output).await? {
                    wallet_outputs.push(wallet_output);
                    continue;
                }

                // Strategy 2: One-sided payments
                if let Some(wallet_output) = self.scan_for_one_sided_payment(&scanned_output).await? {
                    wallet_outputs.push(wallet_output);
                }
            }

            utxos.push(UtxoScanResult {
                height: http_block.height,
                block_hash: http_block.header_hash,
                wallet_outputs,
                mined_timestamp: http_block.mined_timestamp,
            });
        }
        let mut results = Vec::new();
        for block in utxos {
            let mut wallet_outputs = Vec::new();
            for output in block.wallet_outputs {
                let block_response = self.get_utxos_by_block(&block.block_hash.to_hex()).await?;
                if let Some(index) = block_response
                    .outputs
                    .iter()
                    .position(|o| *o.encrypted_data() == output.encrypted_data)
                {
                    if let Some(wallet_output) = output
                        .to_wallet_output(block_response.outputs[index].clone(), &self.key_manager)
                        .await?
                    {
                        wallet_outputs.push(wallet_output);
                    }
                }
            }
            results.push(BlockScanResult {
                height: block.height,
                block_hash: block.block_hash,
                wallet_outputs,
                mined_timestamp: block.mined_timestamp,
            });
        }

        #[cfg(feature = "tracing")]
        debug!(
            "HTTP scan completed, found {} blocks with wallet outputs",
            results.len()
        );
        Ok(results)
    }

    async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
        let url = format!("{}/get_tip_info", self.base_url);

        // Native implementation using reqwest
        #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
        {
            let response = self.client.get(&url).send().await.map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "HTTP request failed: {e}"
                )))
            })?;

            if !response.status().is_success() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            let tip_response: HttpTipInfoResponse = response.json().await.map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to parse response: {e}"
                )))
            })?;

            Ok(TipInfo {
                best_block_height: tip_response.metadata.best_block_height,
                best_block_hash: tip_response.metadata.best_block_hash,
                accumulated_difficulty: tip_response.metadata.accumulated_difficulty,
                pruned_height: tip_response.metadata.pruned_height,
                timestamp: tip_response.metadata.timestamp,
            })
        }

        // WASM implementation using web-sys
        #[cfg(all(feature = "http", target_arch = "wasm32"))]
        {
            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            let request = Request::new_with_str_and_init(&url, &opts)?;
            request.headers().set("Accept", "application/json")?;

            let window = window().ok_or_else(|| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "No window object available",
                ))
            })?;

            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "HTTP request failed",
                ))
            })?;

            let response: Response = resp_value.dyn_into().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Invalid response type",
                ))
            })?;

            if !response.ok() {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "HTTP error: {}",
                        response.status()
                    )),
                ));
            }

            // Get JSON response
            let json_promise = response.json().map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to get JSON response",
                ))
            })?;

            let json_value = JsFuture::from(json_promise).await.map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Failed to parse JSON response",
                ))
            })?;

            let tip_response: HttpTipInfoResponse = serde_wasm_bindgen::from_value(json_value).map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Failed to deserialize response: {}",
                    e
                )))
            })?;

            Ok(TipInfo {
                best_block_height: tip_response.metadata.best_block_height,
                best_block_hash: tip_response.metadata.best_block_hash,
                accumulated_difficulty: tip_response.metadata.accumulated_difficulty,
                pruned_height: tip_response.metadata.pruned_height,
                timestamp: tip_response.metadata.timestamp,
            })
        }
    }

    async fn search_utxos(&mut self, _commitments: Vec<Vec<u8>>) -> WalletResult<Vec<BlockScanResult>> {
        // This endpoint is not implemented in the current HTTP API
        // It would require a different endpoint that searches for specific commitments
        Err(WalletError::ScanningError(
            crate::errors::ScanningError::blockchain_connection_failed("search_utxos not implemented for HTTP scanner"),
        ))
    }

    async fn fetch_utxos(&mut self, _hashes: Vec<Vec<u8>>) -> WalletResult<Vec<TransactionOutput>> {
        // This endpoint is not implemented in the current HTTP API
        // It would require a different endpoint that fetches specific UTXOs by hash
        Err(WalletError::ScanningError(
            crate::errors::ScanningError::blockchain_connection_failed("fetch_utxos not implemented for HTTP scanner"),
        ))
    }

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<BlockInfo>> {
        let mut blocks = Vec::new();

        for height in heights {
            if let Some(block) = self.get_block_by_height(height).await? {
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<BlockInfo>> {
        let url = format!("{}/base_node/blocks/{}", self.base_url, height);

        let response = self.client.get(&url).timeout(self.timeout).send().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to fetch block {height}: {e}"
            )))
        })?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Ok(None);
            }
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "HTTP {} error fetching block {height}",
                    response.status()
                )),
            ));
        }

        let block_response: SingleBlockResponse = response.json().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse block response for height {height}: {e}"
            )))
        })?;

        let block = block_response.block;
        Ok(Some(BlockInfo {
            height: block.header.height,
            hash: hex::decode(&block.header.hash).map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Invalid block hash format",
                ))
            })?,
            outputs: block.body.outputs,
            inputs: Vec::new(),  // HTTP API doesn't provide input details
            kernels: Vec::new(), // HTTP API doesn't provide kernel details
            timestamp: block.header.timestamp,
        }))
    }

    #[cfg(all(feature = "http", target_arch = "wasm32"))]
    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<BlockInfo>> {
        let url = format!("{}/base_node/blocks/{}", self.base_url, height);

        let opts = RequestInit::new();
        opts.set_method("GET");
        opts.set_mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(&url, &opts)?;
        request.headers().set("Accept", "application/json")?;

        let window = window().ok_or_else(|| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                "No window object available",
            ))
        })?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.map_err(|_| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to fetch block {height}"
            )))
        })?;

        let response: Response = resp_value.dyn_into().map_err(|_| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                "Invalid response type",
            ))
        })?;

        if !response.ok() {
            if response.status() == 404 {
                return Ok(None);
            }
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "HTTP {} error fetching block {height}",
                    response.status()
                )),
            ));
        }

        // Get JSON response
        let json_promise = response.json().map_err(|_| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                "Failed to get JSON response",
            ))
        })?;

        let json_value = JsFuture::from(json_promise).await.map_err(|_| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                "Failed to parse JSON response",
            ))
        })?;

        let block_response: SingleBlockResponse = serde_wasm_bindgen::from_value(json_value).map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to deserialize block response for height {height}: {e}"
            )))
        })?;

        let block = block_response.block;
        Ok(Some(BlockInfo {
            height: block.header.height,
            hash: hex::decode(&block.header.hash).map_err(|_| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                    "Invalid block hash format",
                ))
            })?,
            outputs: block.body.outputs,
            inputs: Vec::new(),  // HTTP API doesn't provide input details
            kernels: Vec::new(), // HTTP API doesn't provide kernel details
            timestamp: block.header.timestamp,
        }))
    }
}

// #[cfg(test)]
// mod tests {
// use serde::Deserialize;
//
// use super::*;
// use crate::{data_structures::types::PrivateKey, extraction::ExtractionConfig, scanning::BlockScanResult};
//
// #[derive(Deserialize)]
// struct TestBlockHeader {
// name: String,
// height: u64,
// hash: Vec<u8>,
// }
//
// const TEST_PRIVATE_KEY: &str = "ab5ab1fdc94094ca1fc0ee46dc86ad5098b8ebf8e54c2a77eeb5b26334b8fa0d";
//
// Load real block data from JSON files
// const BLOCK_32038_DATA: &str = include_str!("test_fixtures/block_32038.json");
// const BLOCK_34926_DATA: &str = include_str!("test_fixtures/block_34926.json");
// const BLOCK_37928_DATA: &str = include_str!("test_fixtures/block_37928.json");
// const BLOCK_39949_DATA: &str = include_str!("test_fixtures/block_39949.json");
//
// Load block headers from JSON file
// const BLOCK_HEADERS_JSON: &str = include_str!("test_fixtures/block_headers.json");
//
// fn create_test_private_key() -> PrivateKey {
// let mut key_bytes = [0u8; 32];
// hex::decode_to_slice(TEST_PRIVATE_KEY, &mut key_bytes).expect("Valid hex");
// PrivateKey::new(key_bytes)
// }
//
// fn parse_test_block_data() -> SyncUtxosByBlockResponse {
// serde_json::from_str(BLOCK_32038_DATA).expect("Valid JSON")
// }
//
// fn load_all_test_block_data() -> Vec<SyncUtxosByBlockResponse> {
// vec![
// serde_json::from_str(BLOCK_32038_DATA).expect("Valid JSON for block 32038"),
// serde_json::from_str(BLOCK_34926_DATA).expect("Valid JSON for block 34926"),
// serde_json::from_str(BLOCK_37928_DATA).expect("Valid JSON for block 37928"),
// serde_json::from_str(BLOCK_39949_DATA).expect("Valid JSON for block 39949"),
// ]
// }
//
// fn load_test_block_headers() -> Vec<TestBlockHeader> {
// serde_json::from_str(BLOCK_HEADERS_JSON).expect("Valid block headers JSON")
// }
//
// #[test]
// fn test_block_header_data_consistency() {
// Verify our test block header data is consistent
// let headers = load_test_block_headers();
// for header in &headers {
// assert_eq!(header.hash.len(), 32, "Block {} hash should be 32 bytes", header.name);
// assert!(header.height > 0, "Block {} height should be positive", header.name);
// }
// }
//
// #[test]
// fn test_private_key_creation() {
// let private_key = create_test_private_key();
//
// Verify the private key was created correctly
// let key_bytes = private_key.as_bytes();
// assert_eq!(key_bytes.len(), 32);
//
// Verify it matches our expected test key
// let expected_bytes = hex::decode(TEST_PRIVATE_KEY).expect("Valid hex");
// assert_eq!(key_bytes, &expected_bytes[..]);
// }
//
// #[test]
// fn test_real_block_data_parsing() {
// let sync_response = parse_test_block_data();
//
// Verify the structure of the real block data
// assert_eq!(sync_response.blocks.len(), 1);
// assert!(sync_response.has_next_page);
// assert!(sync_response.next_header_to_scan.is_some());
//
// let block = &sync_response.blocks[0];
// assert_eq!(block.mined_timestamp, 1750340139);
// assert!(!block.outputs.is_empty());
// assert!(!block.inputs.is_empty());
//
// Verify output structure
// let output = &block.outputs[0];
// assert_eq!(output.output_hash.len(), 32);
// assert_eq!(output.commitment.len(), 32);
// assert_eq!(output.sender_offset_public_key.len(), 32);
// assert!(!output.encrypted_data.is_empty());
// }
//
// #[test]
// fn test_http_output_conversion() {
// let sync_response = parse_test_block_data();
// let http_output = &sync_response.blocks[0].outputs[0];
//
// Test converting HTTP output to TransactionOutput
// let result = HttpBlockchainScanner::convert_http_output_to_lightweight(http_output);
//
// match result {
// Ok(tx_output) => {
// Verify the conversion worked
// assert_eq!(tx_output.commitment().as_bytes(), &http_output.commitment[..]);
// assert_eq!(
// tx_output.sender_offset_public_key().as_bytes(),
// &http_output.sender_offset_public_key[..]
// );
// assert_eq!(tx_output.encrypted_data().as_bytes(), &http_output.encrypted_data[..]);
// },
// Err(e) => panic!("Failed to convert HTTP output: {e}"),
// }
// }
//
// #[test]
// fn test_http_input_conversion() {
// let sync_response = parse_test_block_data();
// let input_hash = &sync_response.blocks[0].inputs[0];
//
// Test converting HTTP input to TransactionInput
// let result = HttpBlockchainScanner::convert_http_input_to_lightweight(input_hash);
//
// match result {
// Ok(tx_input) => {
// Verify the conversion worked - check that output hash matches
// let output_hash = &tx_input.output_hash;
// assert_eq!(output_hash.as_slice(), input_hash.as_slice());
// },
// Err(e) => panic!("Failed to convert HTTP input: {e}"),
// }
// }
//
// #[test]
// fn test_block_conversion() {
// let sync_response = parse_test_block_data();
// let http_block = &sync_response.blocks[0];
//
// Test converting HTTP block to BlockInfo
// let result = HttpBlockchainScanner::convert_http_block_to_block_info(http_block);
//
// match result {
// Ok(block_info) => {
// assert_eq!(block_info.timestamp, http_block.mined_timestamp);
// assert_eq!(block_info.outputs.len(), http_block.outputs.len());
// assert_eq!(block_info.inputs.len(), http_block.inputs.len());
// },
// Err(e) => panic!("Failed to convert HTTP block: {e}"),
// }
// }
//
// #[test]
// fn test_utxo_extraction_with_test_key() {
// let sync_response = parse_test_block_data();
// let http_block = &sync_response.blocks[0];
// let private_key = create_test_private_key();
//
// Convert HTTP block to BlockInfo
// let block_info =
// HttpBlockchainScanner::convert_http_block_to_block_info(http_block).expect("Block conversion should work");
//
// Create extraction config with our test private key
// let extraction_config = ExtractionConfig::with_private_key(private_key);
//
// Try to extract wallet outputs from each output in the block
// let mut wallet_outputs = Vec::new();
// for output in &block_info.outputs {
// Test recoverable output scanning
// if let Some(wallet_output) = HttpBlockchainScanner::scan_for_recoverable_output(output, &extraction_config)
// .expect("Scan should not error")
// {
// wallet_outputs.push(wallet_output);
// }
//
// Test one-sided payment scanning
// if let Some(wallet_output) = HttpBlockchainScanner::scan_for_one_sided_payment(output, &extraction_config)
// .expect("Scan should not error")
// {
// wallet_outputs.push(wallet_output);
// }
//
// Test coinbase output scanning (will be None for payment outputs)
// if let Some(wallet_output) =
// HttpBlockchainScanner::scan_for_coinbase_output(output).expect("Scan should not error")
// {
// wallet_outputs.push(wallet_output);
// }
// }
//
// Verify the expected number of wallet outputs found
// assert_eq!(
// wallet_outputs.len(),
// 2,
// "Expected 2 wallet outputs with test private key"
// );
// }
//
// #[test]
// fn test_all_blocks_data_loading() {
// let all_blocks = load_all_test_block_data();
// let headers = load_test_block_headers();
//
// Verify we have 4 blocks
// assert_eq!(all_blocks.len(), 4);
// assert_eq!(headers.len(), 4);
//
// Verify each block has expected structure
// for (i, sync_response) in all_blocks.iter().enumerate() {
// let header = &headers[i];
//
// for block in &sync_response.blocks {
// Basic validation
// assert!(!block.outputs.is_empty(), "Block {} should have outputs", header.name);
//
// Validate output structure for each output
// for (j, output) in block.outputs.iter().enumerate() {
// assert_eq!(
// output.output_hash.len(),
// 32,
// "Block {} output {} hash should be 32 bytes",
// header.name,
// j
// );
// assert_eq!(
// output.commitment.len(),
// 32,
// "Block {} output {} commitment should be 32 bytes",
// header.name,
// j
// );
// assert_eq!(
// output.sender_offset_public_key.len(),
// 32,
// "Block {} output {} sender key should be 32 bytes",
// header.name,
// j
// );
// assert!(
// !output.encrypted_data.is_empty(),
// "Block {} output {} should have encrypted data",
// header.name,
// j
// );
//
// Test conversion works for each output
// let conversion_result = HttpBlockchainScanner::convert_http_output_to_lightweight(output);
// assert!(
// conversion_result.is_ok(),
// "Block {} output {} should convert successfully",
// header.name,
// j
// );
// }
// }
// }
// }
//
// #[test]
// fn test_debug_output_5_block_32038() {
// Load the test data
// let sync_response: SyncUtxosByBlockResponse =
// serde_json::from_str(BLOCK_32038_DATA).expect("Failed to parse block 32038 JSON");
//
// Create the extraction config with the correct wallet key from database (wallet_id 2 "small")
// let view_key_hex = "ab5ab1fdc94094ca1fc0ee46dc86ad5098b8ebf8e54c2a77eeb5b26334b8fa0d";
// let view_key_bytes = hex::decode(view_key_hex).expect("Valid hex");
// let mut view_key_array = [0u8; 32];
// view_key_array.copy_from_slice(&view_key_bytes);
// let view_private_key = PrivateKey::new(view_key_array);
// let extraction_config = ExtractionConfig::with_private_key(view_private_key);
//
// let http_block = &sync_response.blocks[0];
// let block_info =
// HttpBlockchainScanner::convert_http_block_to_block_info(http_block).expect("Block conversion should work");
//
// Verify block has expected number of outputs
// assert_eq!(block_info.outputs.len(), 199, "Block 32038 should have 199 outputs");
//
// Focus on output 92 (the one with the correct commitment)
// if block_info.outputs.len() > 92 {
// let output_5 = &block_info.outputs[92];
//
// Verify output properties
// assert_eq!(
// hex::encode(output_5.commitment().as_bytes()),
// "080e9955f7b1cfaf04b879b98126269c92a7ee3a3387e1a1bdd92e6b1db54604",
// "Expected specific commitment for output 92"
// );
// assert_eq!(
// output_5.encrypted_data().as_bytes().len(),
// 161,
// "Expected encrypted data length of 161 bytes"
// );
//
// Test direct decryption mechanisms
//
// Test direct change output decryption - should fail for this test case
// let test_private_key = create_test_private_key();
// assert!(
// crate::data_structures::encrypted_data::EncryptedData::decrypt_data(
// &test_private_key,
// output_5.commitment(),
// output_5.encrypted_data(),
// )
// .is_err(),
// "Direct change output decryption should fail for this output"
// );
//
// Test direct one-sided payment decryption - should succeed
// let (value, _mask, _payment_id) =
// crate::data_structures::encrypted_data::EncryptedData::decrypt_one_sided_data(
// &test_private_key,
// output_5.commitment(),
// output_5.sender_offset_public_key(),
// output_5.encrypted_data(),
// )
// .expect("Direct one-sided payment decryption should succeed");
//
// assert_eq!(value.as_u64(), 4011796, "Expected value 4011796 µT");
//
// Test wallet output extraction
// let wallet_output = crate::extraction::extract_wallet_output(output_5, &extraction_config)
// .expect("Wallet output extraction should succeed");
//
// assert_eq!(
// wallet_output.value().as_u64(),
// 4011796,
// "Expected wallet output value 4011796 µT"
// );
//
// Test scan_for_recoverable_output
// let scanned_wallet_output =
// HttpBlockchainScanner::scan_for_recoverable_output(output_5, &extraction_config)
// .expect("scan_for_recoverable_output should not error")
// .expect("scan_for_recoverable_output should return Some");
//
// assert_eq!(
// scanned_wallet_output.value().as_u64(),
// 4011796,
// "Expected scanned value 4011796 µT"
// );
// }
// }
//
// #[test]
// fn test_scanning_all_blocks_with_test_key() {
// let all_blocks = load_all_test_block_data();
// let _headers = load_test_block_headers();
// let private_key = create_test_private_key();
// let extraction_config = ExtractionConfig::with_private_key(private_key);
//
// let mut total_outputs_scanned = 0;
// let mut total_inputs_scanned = 0;
// let mut total_wallet_outputs_found = 0;
// let mut wallet_output_hashes = std::collections::HashSet::new();
//
// for sync_response in all_blocks.iter() {
// for http_block in &sync_response.blocks {
// Convert HTTP block to BlockInfo
// let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
// .expect("Block conversion should work");
//
// let mut wallet_outputs = Vec::new();
//
// Scan outputs for wallet ownership
// for (output_index, output) in block_info.outputs.iter().enumerate() {
// total_outputs_scanned += 1;
//
// if let Some(wallet_output) =
// HttpBlockchainScanner::scan_for_recoverable_output(output, &extraction_config)
// .expect("Scan should not error")
// {
// Track successful outputs for validation
//
// Store the output hash for later input matching (this is what inputs reference)
// let http_output = &http_block.outputs[output_index];
// let output_hash = http_output.output_hash.clone();
// wallet_output_hashes.insert(output_hash);
// wallet_outputs.push(wallet_output);
// }
// }
//
// total_wallet_outputs_found += wallet_outputs.len();
//
// Track wallet outputs found per block
// }
// }
//
// Now scan all blocks for spent inputs that match our wallet outputs
// let mut total_spent_wallet_inputs = 0;
//
// for sync_response in all_blocks.iter() {
// let http_block = &sync_response.blocks[0];
//
// Convert HTTP block to BlockInfo
// let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
// .expect("Block conversion should work");
//
// let mut spent_wallet_inputs = 0;
//
// Check each input to see if it spends one of our wallet outputs
// for input in &block_info.inputs {
// total_inputs_scanned += 1;
// let input_output_hash = &input.output_hash;
//
// Check if this input spends one of our wallet outputs
// if wallet_output_hashes.contains(input_output_hash.as_slice()) {
// spent_wallet_inputs += 1;
// }
// }
//
// total_spent_wallet_inputs += spent_wallet_inputs;
//
// Track spent wallet inputs per block
// }
//
// Assert the expected values from test output
// assert_eq!(total_wallet_outputs_found, 24, "Expected 24 wallet outputs found");
// assert_eq!(total_outputs_scanned, 495, "Expected 495 total outputs scanned");
// assert_eq!(total_spent_wallet_inputs, 3, "Expected 3 spent wallet inputs found");
// assert_eq!(total_inputs_scanned, 338, "Expected 338 total inputs scanned");
// assert_eq!(all_blocks.len(), 4, "Expected 4 blocks processed");
// }
//
// #[test]
// fn test_input_detection_and_spent_outputs() {
// let all_blocks = load_all_test_block_data();
// let headers = load_test_block_headers();
// let private_key = create_test_private_key();
// let extraction_config = ExtractionConfig::with_private_key(private_key);
//
// First pass: collect all wallet outputs and their identifiers
// let mut wallet_output_identifiers = std::collections::HashMap::new();
// let mut all_input_hashes = std::collections::HashSet::new();
//
// for (i, sync_response) in all_blocks.iter().enumerate() {
// let header = &headers[i];
// let http_block = &sync_response.blocks[0];
// let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
// .expect("Block conversion should work");
//
// Collect all input hashes to see what's being spent
// for input in &block_info.inputs {
// all_input_hashes.insert(input.output_hash);
// }
//
// Scan for wallet outputs and store their identifiers
// for output in &block_info.outputs {
// if let Some(_wallet_output) =
// HttpBlockchainScanner::scan_for_recoverable_output(output, &extraction_config)
// .expect("Scan should not error")
// {
// Store the output hash for later input matching (this is what inputs reference)
// let http_output =
// &http_block.outputs[block_info.outputs.iter().position(|o| std::ptr::eq(o, output)).unwrap()];
// let output_hash = http_output.output_hash.clone();
// let output_hash_key = format!("{}_{}", header.height, hex::encode(&output_hash[..8]));
// wallet_output_identifiers.insert(output_hash_key.clone(), (header.height, output_hash.clone()));
//
// Track wallet output found
// }
// }
// }
//
// Second pass: check for spent wallet outputs by matching input hashes
// let mut spent_outputs_detected = 0;
//
// for sync_response in all_blocks.iter() {
// let http_block = &sync_response.blocks[0];
// let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
// .expect("Block conversion should work");
//
// for input in &block_info.inputs {
// Check if this input hash matches any of our wallet output hashes
// for (_origin_height, output_hash) in wallet_output_identifiers.values() {
// Check if the input references one of our wallet outputs by hash
// if input.output_hash.as_slice() == output_hash.as_slice() {
// spent_outputs_detected += 1;
// Track spent wallet output
// }
//
// 2. Check if the input output_hash appears in our collected hashes
// if all_input_hashes.contains(&input.output_hash) {
// This input references an output that exists in our dataset
// Additional logic could be added here for more sophisticated matching
// }
// }
// }
// }
//
// Assert expected values from test output
// assert_eq!(wallet_output_identifiers.len(), 24, "Expected 24 wallet outputs found");
// assert_eq!(spent_outputs_detected, 3, "Expected 3 spent wallet outputs detected");
// assert_eq!(all_input_hashes.len(), 338, "Expected 338 unique input hashes");
//
// Additional analysis: check if any inputs reference the actual output hashes from HTTP data
// let mut cross_referenced_inputs = 0;
// for sync_response in all_blocks.iter() {
// let http_block = &sync_response.blocks[0];
//
// for input_hash in &http_block.inputs {
// Check if this input hash matches any output hash from the same or other blocks
// for other_sync_response in all_blocks.iter() {
// let other_http_block = &other_sync_response.blocks[0];
// for output in &other_http_block.outputs {
// if input_hash.as_slice() == output.output_hash.as_slice() {
// cross_referenced_inputs += 1;
// Track cross-referenced input
// }
// }
// }
// }
// }
//
// Assert expected cross-reference value
// assert_eq!(cross_referenced_inputs, 4, "Expected 4 cross-referenced inputs");
// }
//
// #[test]
// fn test_scan_config_creation() {
// let private_key = create_test_private_key();
// let private_key_bytes = private_key.as_bytes();
//
// let _start_height = 32038;
// let _end_height = Some(32040);
//
// Test the basic scan config structure that would be created
// let extraction_config = ExtractionConfig::with_private_key(private_key);
//
// Verify extraction config was created properly
// assert_eq!(
// extraction_config
// .private_key
// .expect("Private key should be set")
// .as_bytes(),
// private_key_bytes
// );
// }
//
// #[test]
// fn test_bytes_to_hex_conversion() {
// Test the utility function used in the scanner
// let test_bytes = &[0xde, 0xad, 0xbe, 0xef];
// let hex_result = HttpBlockchainScanner::bytes_to_hex(test_bytes);
// assert_eq!(hex_result, "deadbeef");
//
// Test with block header hash
// let headers = load_test_block_headers();
// let header_hash = &headers[0].hash;
// let hex_hash = HttpBlockchainScanner::bytes_to_hex(header_hash);
// assert_eq!(hex_hash.len(), 64); // 32 bytes = 64 hex chars
// assert!(hex_hash.chars().all(|c| c.is_ascii_hexdigit()));
// }
//
// #[test]
// fn test_error_handling_invalid_commitment() {
// Test error handling with invalid commitment length
// let mut invalid_output = MinimalUtxoSyncInfo {
// output_hash: vec![0u8; 32],
// commitment: vec![0u8; 31], // Invalid length
// encrypted_data: vec![0u8; 161],
// sender_offset_public_key: vec![0u8; 32],
// };
//
// let result = HttpBlockchainScanner::convert_http_output_to_lightweight(&invalid_output);
// assert!(result.is_err());
//
// Test with invalid sender offset public key length
// invalid_output.commitment = vec![0u8; 32];
// invalid_output.sender_offset_public_key = vec![0u8; 31]; // Invalid length
//
// let result = HttpBlockchainScanner::convert_http_output_to_lightweight(&invalid_output);
// assert!(result.is_err());
// }
//
// #[test]
// fn test_error_handling_invalid_input_hash() {
// Test error handling with invalid input hash length
// let invalid_hash = vec![0u8; 31]; // Invalid length
//
// let result = HttpBlockchainScanner::convert_http_input_to_lightweight(&invalid_hash);
// assert!(result.is_err());
// }
//
// Integration test that demonstrates the full scanning workflow
// Note: This test uses mock data and doesn't require network access
// #[test]
// fn test_scanning_workflow_integration() {
// let sync_response = parse_test_block_data();
// let private_key = create_test_private_key();
//
// Simulate the scanning workflow that would happen in scan_blocks
// let extraction_config = ExtractionConfig::with_private_key(private_key);
//
// let mut results = Vec::new();
//
// for http_block in &sync_response.blocks {
// let block_info = HttpBlockchainScanner::convert_http_block_to_block_info(http_block)
//     .expect("Block conversion should work");
//
// let mut wallet_outputs = Vec::new();
//
// for output in http_block.outputs.iter() {
// let mut found_output = false;
// let scanning_output = output.try_into()?;
// Strategy 1: Regular recoverable outputs
// if !found_output {
// if let Some(wallet_output) =
// HttpBlockchainScanner::scan_for_recoverable_output(scanning_output, &extraction_config)
// .expect("Scan should not error")
// {
// wallet_outputs.push(wallet_output);
// found_output = true;
// }
// }
//
// Strategy 2: One-sided payments
// if !found_output {
// if let Some(wallet_output) =
// HttpBlockchainScanner::scan_for_one_sided_payment(output, &extraction_config)
// .expect("Scan should not error")
// {
// wallet_outputs.push(wallet_output);
// found_output = true;
// }
// }
//
// Strategy 3: Coinbase outputs
// if !found_output {
// if let Some(wallet_output) =
// HttpBlockchainScanner::scan_for_coinbase_output(output).expect("Scan should not error")
// {
// wallet_outputs.push(wallet_output);
// }
// }
// }
//
// let scan_result = BlockScanResult {
// height: block_info.height,
// block_hash: block_info.hash,
// outputs: block_info.outputs,
// wallet_outputs,
// mined_timestamp: block_info.timestamp,
// };
//
// results.push(scan_result);
// }
//
// Verify the workflow produced expected results
// assert_eq!(results.len(), 1);
// let result = &results[0];
// assert_eq!(result.height, 0); // Block height not available in sync_utxos_by_block response
// assert_eq!(result.mined_timestamp, 1750340139);
// assert!(!result.outputs.is_empty(), "Block should have outputs");
//
// Verify the expected number of wallet outputs found
// assert_eq!(result.wallet_outputs.len(), 1, "Expected 1 wallet output found");
// }
// }
