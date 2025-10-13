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
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use serde_wasm_bindgen;
use tari_common_types::types::FixedHash;
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    rpc::models::{BlockUtxoInfo, GetUtxosByBlockResponse, SyncUtxosByBlockResponse},
    transaction_components::TransactionOutput,
};
use tari_utilities::hex::Hex;
use crate::scanning::http::models::HttpHeaderResponse;

#[cfg(all(feature = "http", feature = "tracing"))]
use tracing::debug;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen::prelude::*;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use wasm_bindgen_futures::JsFuture;
#[cfg(all(feature = "http", target_arch = "wasm32"))]
use web_sys::{window, Request, RequestInit, RequestMode, Response};

#[cfg(feature = "http")]
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use crate::BlockHeaderInfo;
use crate::{
    data_structures::incompleted_scanned_output::{IncompleteScannedOutput, ScanningOutputStruct},
    errors::{WalletError, WalletResult},
    extraction::ExtractionConfig,
    scanning::{BlockScanResult, BlockchainScanner, ScanConfig, TipInfo},
    UtxoScanResult,
};
use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};
use crate::http::models::{HttpBlockHeader, HttpTipInfoResponse};

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
    #[cfg(not(target_arch = "wasm32"))]
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

    /// Get header by height - matches WASM example usage
    #[cfg(not(target_arch = "wasm32"))]
    async fn get_header_by_height(&self, height: u64) -> WalletResult<HttpHeaderResponse> {
        let url = format!("{}/get_header_by_height", self.base_url);

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

    /// Get header by height - matches WASM example usage
    #[cfg(target_arch = "wasm32")]
    async fn get_header_by_height(&self, height: u64) -> WalletResult<HttpHeaderResponse> {
        let url = format!("{}/get_header_by_height", self.base_url);

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

    /// Sync UTXOs by block - matches WASM example usage
    async fn sync_utxos_by_block(&self, start_header_hash: &str, limit: u64) -> WalletResult<SyncUtxosByBlockResponse> {
        let url = format!("{}/sync_utxos_by_block", self.base_url);
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
            .try_output_key_recovery(
                &output.commitment,
                &output.encrypted_data,
                &output.sender_offset_public_key,
            )
            .await?
        {
            Some(value) => value,
            None => return Ok(None),
        };

        let output = IncompleteScannedOutput::new(output, value, commitment_mask, memo)?;
        Ok(Some(output))
    }

    /// Fetch block range using the sync_utxos_by_block endpoint
    async fn fetch_block_range(&self, start_height: u64, end_height: u64) -> WalletResult<Vec<BlockUtxoInfo>> {
        // Get the starting header hash
        let start_header = self.get_header_by_height(start_height).await?;
        let mut current_header_hash = start_header.hash.to_hex();

        let mut all_blocks = Vec::new();
        let mut blocks_collected = 0;
        let max_blocks = (end_height - start_height + 1) as usize;
        let mut is_first_batch = true;

        #[cfg(feature = "tracing")]
        debug!(
            "Starting fetch_block_range from height {} to {} (max {} blocks)",
            start_height, end_height, max_blocks
        );

        while blocks_collected < max_blocks {
            let remaining_blocks = max_blocks - blocks_collected;
            let limit = std::cmp::min(remaining_blocks as u64, 100);

            // Use sync_utxos_by_block to get batch of blocks
            let sync_response = self.sync_utxos_by_block(&current_header_hash, limit).await?;

            if sync_response.blocks.is_empty() {
                #[cfg(feature = "tracing")]
                debug!("No more blocks available from base node");
                break;
            }

            let mut blocks_to_process = sync_response.blocks.into_iter();

            // The API returns the `start_header_hash` block as the first block in the response.
            // For subsequent batches, we skip this first block as it was already processed in the previous iteration.
            if !is_first_batch {
                blocks_to_process.next();
            }

            // Add all blocks from this response
            for block in blocks_to_process {
                // Only add blocks if their height is within the requested range
                if block.height >= start_height && block.height <= end_height {
                    all_blocks.push(block);
                    blocks_collected += 1;
                }

                // Stop if we've collected enough blocks
                if blocks_collected >= max_blocks {
                    break;
                }
            }

            is_first_batch = false;

            // Check if we have a next header to continue with and haven't reached our limit
            if blocks_collected < max_blocks {
                if sync_response.next_header_to_scan.is_empty() {
                    #[cfg(feature = "tracing")]
                    debug!("No more headers to scan, reached end of available data");
                    break;
                } else {
                    let next_hash = sync_response.next_header_to_scan.to_hex();
                    // Safeguard against infinite loops if the server returns the same hash
                    if next_hash == current_header_hash {
                        #[cfg(feature = "tracing")]
                        debug!("Next header is the same as the current one, stopping to prevent infinite loop.");
                        break;
                    }
                    current_header_hash = next_hash;
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
    async fn scan_blocks(&mut self, config: ScanConfig) -> WalletResult<(Vec<BlockScanResult>, bool)> {

        #[cfg(feature = "tracing")]
        debug!(
            "Starting HTTP block scan from height {} to {:?}",
            config.start_height, config.end_height
        );

        let timer = Instant::now();
        let end_height = match config.end_height {
            Some(height) => height,
            None => {
                let tip_info = self.get_tip_info().await?;
                tip_info.best_block_height
            },
        };

        if config.start_height > end_height {
            return Ok((Vec::new(), false));
        }

        // Fetch blocks using the new API
        println!("Fetching blocks from {} to {}", config.start_height, end_height);
        let http_blocks = self.fetch_block_range(config.start_height, end_height).await?;
        // println!(
        //     "Fetched {} blocks. Time taken: {:?}",
        //     http_blocks.len(),
        //     timer.elapsed()
        // );

        let mut utxos = Vec::new();

        let mut blocks_with_utxos = HashSet::new();
        for http_block in http_blocks {
            let mut wallet_outputs = Vec::new();

            let header_hash = FixedHash::try_from(http_block.header_hash.clone()).unwrap_or_default();
            for output in &http_block.outputs {
                let scanned_output = output.clone().try_into()?;
                if let Some(wallet_output) = self.scan_for_recoverable_output(&scanned_output).await? {
                    wallet_outputs.push(wallet_output);
                    blocks_with_utxos.insert(header_hash.clone());
                    continue;
                }
            }
            let mined_timestamp = http_block.mined_timestamp;
            utxos.push(UtxoScanResult {
                height: http_block.height,
                block_hash: header_hash,
                wallet_outputs,
                inputs: http_block
                    .inputs
                    .into_iter()
                    .map(|i| FixedHash::try_from(i).unwrap_or_default())
                    .collect(),
                mined_timestamp,
            });
        }
        let mut results = Vec::new();
        // fetch all the unique blocks we need before processing
        let mut block_data = HashMap::new();
        for block_hash in blocks_with_utxos {
            let block_response = self.get_utxos_by_block(&block_hash.to_hex()).await?;
            block_data.insert(block_hash, block_response);
        }
        for block in utxos {
            let mut wallet_outputs = Vec::new();
            for output in block.wallet_outputs {
                // Block should always be present as we fetched them above
                let block_response = block_data.get(&block.block_hash).ok_or_else(|| {
                    WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                        "Block data missing for output",
                    ))
                })?;
                if let Some(index) = block_response
                    .outputs
                    .iter()
                    .position(|o| *o.encrypted_data() == output.encrypted_data)
                {
                    let tx_output = block_response.outputs[index].clone();
                    let output_hash = output.output_hash.clone();
                    // Attempt to convert to wallet output
                    if let Some(wallet_output) = output.to_wallet_output(tx_output, &self.key_manager).await? {
                        wallet_outputs.push((output_hash, wallet_output));
                    }
                }
            }
            results.push(BlockScanResult {
                height: block.height,
                block_hash: block.block_hash,
                wallet_outputs,
                inputs: block.inputs,
                mined_timestamp: block.mined_timestamp,
            });
        }

        #[cfg(feature = "tracing")]
        debug!(
            "HTTP scan completed, found {} blocks with wallet outputs",
            results.len()
        );
        Ok((results, false))
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
                best_block_hash: FixedHash::try_from(tip_response.metadata.best_block_hash).unwrap_or_default(),
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

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        let mut blocks = Vec::new();

        for height in heights {
            if let Some(block) = self.get_block_by_height(height).await? {
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    async fn get_block_by_height(&mut self, _height: u64) -> WalletResult<Option<Block>> {
        // method does not exit
        Ok(None)
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

    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    async fn get_header_by_height(&mut self, height: u64) -> WalletResult<Option<BlockHeaderInfo>> {
        use tari_utilities::epoch_time::EpochTime;

        let url = format!("{}/get_header_by_height?height={}", self.base_url, height);

        let response = self.client.get(&url).send().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "HTTP request failed: {e}"
            )))
        })?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Ok(None);
            }
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "HTTP error: {}",
                    response.status()
                )),
            ));
        }

        let body = response.text().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to read response body: {e}"
            )))
        })?;
        dbg!(&body);

        let header_response: HttpBlockHeader = serde_json::from_str(&body).map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse response: {e}"
            )))
        })?;

        Ok(Some(BlockHeaderInfo {
            height: header_response.height,
            hash: FixedHash::try_from(header_response.hash).unwrap_or_default(),
            timestamp: EpochTime::from(header_response.timestamp),
        }))
    }
}
