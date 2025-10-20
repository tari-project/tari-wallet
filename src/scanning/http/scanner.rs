//! HTTP-based blockchain scanner implementation
//!
//! This module provides an HTTP implementation of the `BlockchainScanner` trait
//! that connects to a Tari base node via HTTP API to scan for wallet outputs.

// Native targets use reqwest
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use reqwest::Client;
use tari_common_types::types::FixedHash;
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    rpc::models::{BlockUtxoInfo, GetUtxosByBlockResponse, SyncUtxosByBlockResponse},
    transaction_components::TransactionOutput,
};
use tari_utilities::hex::Hex;
use tracing::debug;

use crate::{
    errors::{WalletError, WalletResult},
    http::models::{HttpBlockHeader, HttpTipInfoResponse, IncompleteScannedOutput, ScanningOutputStruct},
    scanning::{interface::BlockchainScanner, BlockScanResult, InProgressScan, ScanConfig, TipInfo},
    BlockHeaderInfo,
    UtxoScanResult,
};

const SYNC_UTXOS_BY_BLOCK_PAGE_LIMIT: u64 = 10;

/// HTTP client for connecting to Tari base node
pub struct HttpBlockchainScanner<KM> {
    /// HTTP client for making requests (native targets)
    client: Client,
    /// Base URL for the HTTP API
    base_url: String,
    /// Request timeout (native targets only)
    timeout: Duration,
    key_manager: KM,
    current_in_progress: InProgressScan,
}

impl<KM> HttpBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    /// Create a new HTTP scanner with the given base URL
    pub async fn new(base_url: String, key_manager: KM) -> WalletResult<Self> {
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
                crate::errors::ScanningError::blockchain_connection_failed(&format!("Failed to connect to {base_url}")),
            ));
        }
        Ok(Self {
            client,
            base_url,
            timeout,
            key_manager,
            current_in_progress: InProgressScan::new_empty(),
        })
    }

    /// Create a new HTTP scanner with custom timeout (native only)
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
            current_in_progress: InProgressScan::new_empty(),
        })
    }

    /// Sync UTXOs by block - matches WASM example usage
    async fn sync_utxos_by_block(
        &self,
        start_header_hash: &str,
        limit: u64,
        page: u64,
    ) -> WalletResult<SyncUtxosByBlockResponse> {
        let url = format!("{}/sync_utxos_by_block", self.base_url);

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

    async fn get_utxos_by_block(&self, current_header_hash: &str) -> WalletResult<GetUtxosByBlockResponse> {
        let url = format!("{}/get_utxos_by_block", self.base_url);

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

    /// Create a scan config with wallet keys for block scanning
    pub const fn create_scan_config_with_wallet_keys(
        &self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> WalletResult<ScanConfig> {
        Ok(ScanConfig {
            start_height,
            end_height,
            batch_size: Some(100),
            request_timeout: self.timeout,
        })
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    async fn scan_for_recoverable_output(
        &self,
        output: &ScanningOutputStruct,
    ) -> WalletResult<Option<IncompleteScannedOutput>> {
        let Some((commitment_mask, value, memo)) = self
            .key_manager
            .try_output_key_recovery(
                &output.commitment,
                &output.encrypted_data,
                &output.sender_offset_public_key,
            )
            .await?
        else {
            return Ok(None);
        };

        let output = IncompleteScannedOutput::new(output, value, commitment_mask, memo)?;
        Ok(Some(output))
    }

    /// Fetch block range using the `sync_utxos_by_block` endpoint
    #[allow(clippy::cognitive_complexity)]
    async fn fetch_block_range(&mut self) -> WalletResult<(Vec<BlockUtxoInfo>, bool)> {
        let start_height = self.current_in_progress.get_config().map_or(0, |c| c.start_height);

        // Get the starting header hash
        let mut more_blocks = true;
        let current_header_hash = if let Some(h) = self.current_in_progress.get_header() {
            h.clone()
        } else {
            let Some(start_header) = self.get_header_by_height(start_height).await? else {
                return Err(WalletError::ScanningError(
                    crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "Failed to get header at height {start_height}"
                    )),
                ));
            };
            let current_header_hash = start_header.hash.to_hex();
            self.current_in_progress.set_next_request(current_header_hash.clone());
            current_header_hash
        };

        let mut all_blocks = Vec::new();

        debug!("Starting fetch_block_range from height {} ", start_height);
        let limit = self
            .current_in_progress
            .get_config()
            .and_then(|c| c.batch_size)
            .unwrap_or(SYNC_UTXOS_BY_BLOCK_PAGE_LIMIT);
        let page = self.current_in_progress.page();
        let sync_response = self.sync_utxos_by_block(&current_header_hash, limit, page).await?;
        if sync_response.blocks.is_empty() {
            debug!("No more blocks available from base node");
            return Ok((Vec::new(), false));
        }
        let mut has_next_page = sync_response.has_next_page;
        let next_header_to_scan = sync_response.next_header_to_scan.clone();
        let blocks_to_process = sync_response.blocks.into_iter();

        // Add all blocks from this response
        for block in blocks_to_process {
            if let Some(end_height) = self.current_in_progress.get_config().and_then(|c| c.end_height) {
                if block.height > end_height {
                    debug!("Reached end height {}, stopping fetch", end_height);
                    self.current_in_progress.clear();
                    more_blocks = false;
                    has_next_page = false;
                }
            }
            all_blocks.push(block);
        }
        self.current_in_progress.increment_page();

        if !has_next_page && self.current_in_progress.is_active() {
            // we are done scanning this batch of blocks, we need to request the next header, and we have not
            // reached some end goal
            if next_header_to_scan.is_empty() {
                debug!("No next header to scan, ending fetch");
                more_blocks = false;
                self.current_in_progress.clear();
            } else {
                let next_header_to_scan_hex = next_header_to_scan.to_hex();
                debug!("Setting next header to scan: {}", next_header_to_scan_hex);
                // Safeguard against infinite loops if the server returns the same hash
                if next_header_to_scan_hex == self.current_in_progress.get_header().cloned().unwrap_or_default() {
                    debug!("Next header is the same as the current one, stopping to prevent infinite loop.");
                    more_blocks = false;
                    self.current_in_progress.clear();
                } else {
                    self.current_in_progress.set_next_request(next_header_to_scan_hex);
                }
            }
        }

        debug!("Fetched {} blocks for range {}", all_blocks.len(), start_height,);

        Ok((all_blocks, more_blocks))
    }

    pub async fn update_scan_config(&mut self, config: &ScanConfig) -> WalletResult<()> {
        debug!(
            "String new scan, scanning from: {} to  {:?}",
            config.start_height, config.end_height
        );
        self.current_in_progress = InProgressScan::new(config.clone());
        Ok(())
    }

    pub fn clear_in_progress_scan(&mut self) {
        self.current_in_progress.clear();
    }
}

#[async_trait(?Send)]
impl<KM> BlockchainScanner for HttpBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    async fn scan_blocks(&mut self, config: &ScanConfig) -> WalletResult<(Vec<BlockScanResult>, bool)> {
        if let Some(end_height) = config.end_height {
            if config.start_height > end_height {
                return Err(WalletError::OperationNotSupported(
                    "start_height cannot be greater than end_height".to_string(),
                ));
            }
        }

        match &self.current_in_progress.get_config() {
            Some(existing_scan) => {
                if *existing_scan == config {
                    debug!(
                        "Resuming existing HTTP block scan from height {} to {:?}",
                        existing_scan.start_height, existing_scan.end_height
                    );
                } else {
                    self.update_scan_config(config).await?;
                }
            },
            _ => {
                self.update_scan_config(config).await?;
            },
        }

        let timer = Instant::now();
        let (http_blocks, more_blocks) = self.fetch_block_range().await?;

        let mut utxos = Vec::new();

        let mut blocks_with_utxos = HashSet::new();
        for http_block in http_blocks {
            let mut wallet_outputs = Vec::new();

            let header_hash = FixedHash::try_from(http_block.header_hash.clone())
                .map_err(|e| WalletError::ConversionError(e.to_string()))?;
            for output in &http_block.outputs {
                let scanned_output = output.clone().try_into()?;
                if let Some(wallet_output) = self.scan_for_recoverable_output(&scanned_output).await? {
                    wallet_outputs.push(wallet_output);
                    blocks_with_utxos.insert(header_hash);
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

            // Block should always be present as we fetched them above
            if !block.wallet_outputs.is_empty() {
                let block_response = block_data.get(&block.block_hash).ok_or_else(|| {
                    WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                        "Block data missing for output",
                    ))
                })?;
                for output in block.wallet_outputs {
                    if let Some(index) = block_response
                        .outputs
                        .iter()
                        .position(|o| *o.encrypted_data() == output.encrypted_data)
                    {
                        let tx_output = block_response.outputs.get(index).expect("should exist").clone();
                        let output_hash = output.output_hash;
                        // Attempt to convert to wallet output
                        if let Some(wallet_output) = output.to_wallet_output(tx_output, &self.key_manager).await? {
                            wallet_outputs.push((output_hash, wallet_output));
                        }
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

        debug!(
            "HTTP scan completed, found {} blocks with wallet outputs in {}s",
            results.len(),
            timer.elapsed().as_secs()
        );
        Ok((results, more_blocks))
    }

    async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
        let url = format!("{}/get_tip_info", self.base_url);

        // Native implementation using reqwest
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
            best_block_hash: FixedHash::try_from(tip_response.metadata.best_block_hash)
                .map_err(|e| WalletError::ConversionError(e.to_string()))?,
            accumulated_difficulty: tip_response.metadata.accumulated_difficulty,
            pruned_height: tip_response.metadata.pruned_height,
            timestamp: tip_response.metadata.timestamp,
        })
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

    async fn get_block_by_height(&mut self, _height: u64) -> WalletResult<Option<Block>> {
        // method does not exit
        Ok(None)
    }

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

        let header_response: HttpBlockHeader = serde_json::from_str(&body).map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse response: {e}"
            )))
        })?;

        Ok(Some(BlockHeaderInfo {
            height: header_response.height,
            hash: FixedHash::try_from(header_response.hash).map_err(|e| WalletError::ConversionError(e.to_string()))?,
            timestamp: EpochTime::from(header_response.timestamp),
        }))
    }
}
