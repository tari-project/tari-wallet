//! HTTP-based blockchain scanner implementation
//!
//! This module provides an HTTP implementation of the `BlockchainScanner` trait
//! that connects to a Tari base node via HTTP API to scan for wallet outputs.

// Native targets use reqwest
use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use reqwest::Client;
use tari_common_types::types::{CompressedCommitment, FixedHash};
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    rpc::models::{BlockUtxoInfo, GetUtxosByBlockResponse, SyncUtxosByBlockResponse},
    transaction_components::{MemoField, TransactionOutput},
    MicroMinotari,
};
use tari_utilities::{hex::Hex, ByteArray};
use tracing::debug;

use crate::{
    errors::{WalletError, WalletResult},
    http::models::{
        HttpBlockHeader,
        HttpMempoolResponse,
        HttpTipInfoResponse,
        IncompleteScannedOutput,
        ScanningOutputStruct,
    },
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
    number_processing_threads: usize,
}

impl<KM> HttpBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    /// Create a new HTTP scanner with the given base URL
    pub async fn new(base_url: String, key_manager: KM, number_processing_threads: usize) -> WalletResult<Self> {
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
            number_processing_threads,
        })
    }

    /// Create a new HTTP scanner with custom timeout (native only)
    pub async fn with_timeout(
        base_url: String,
        timeout: Duration,
        key_manager: KM,
        number_processing_threads: usize,
    ) -> WalletResult<Self> {
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
            number_processing_threads,
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
    fn scan_for_recoverable_output(
        &self,
        output: &ScanningOutputStruct,
    ) -> WalletResult<Option<IncompleteScannedOutput>> {
        let Some((commitment_mask, value, memo)) = self.key_manager.try_output_key_recovery(
            &output.commitment,
            &output.encrypted_data,
            &output.sender_offset_public_key,
        )?
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

        let utxos = RwLock::new(Vec::new());
        let blocks_with_utxos = RwLock::new(HashSet::new());
        let errors = RwLock::new(Vec::new());
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.number_processing_threads)
            .build()
            .map_err(|e| WalletError::ConfigurationError(format!("Failed to build thread pool: {}", e)))?;
        pool.install(|| {
            http_blocks.into_par_iter().for_each(|http_block| {
                let mut wallet_outputs = Vec::new();

                let header_hash = match FixedHash::try_from(http_block.header_hash.clone()) {
                    Ok(h) => h,
                    Err(e) => {
                        errors
                            .write()
                            .expect("write lock should not be poisoned")
                            .push(WalletError::ConversionError(e.to_string()));
                        return;
                    },
                };
                for output in &http_block.outputs {
                    let scanned_output = match output.clone().try_into() {
                        Ok(o) => o,
                        Err(e) => {
                            errors.write().expect("write lock should not be poisoned").push(e);
                            continue;
                        },
                    };
                    match self.scan_for_recoverable_output(&scanned_output) {
                        Ok(Some(wallet_output)) => {
                            wallet_outputs.push(wallet_output);
                            blocks_with_utxos
                                .write()
                                .expect("write lock should not be poisoned")
                                .insert(header_hash);
                        },
                        Ok(None) => {},
                        Err(e) => {
                            errors.write().expect("write lock should not be poisoned").push(e);
                        },
                    }
                }
                let mined_timestamp = http_block.mined_timestamp;
                utxos
                    .write()
                    .expect("write lock should not be poisoned")
                    .push(UtxoScanResult {
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
            });
        });
        if let Some(e) = errors.read().expect("read lock should not be poisoned").first() {
            return Err(e.clone());
        }
        let results = RwLock::new(Vec::new());
        // fetch all the unique blocks we need before processing
        let mut block_data = HashMap::new();
        for block_hash in blocks_with_utxos.into_inner().expect("lock should not be poisoned") {
            let block_response = self.get_utxos_by_block(&block_hash.to_hex()).await?;
            block_data.insert(block_hash, block_response);
        }
        let utxos = utxos.into_inner().expect("lock should not be poisoned");
        pool.install(|| {
            utxos.par_iter().for_each(|block| {
                let mut wallet_outputs = Vec::new();

                if !block.wallet_outputs.is_empty() {
                    // Block should always be present as we fetched them above
                    let block_response = match block_data.get(&block.block_hash) {
                        Some(b) => b,
                        None => {
                            errors.write().expect("write lock should not be poisoned").push(
                                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(
                                    "Block data missing for output",
                                )),
                            );
                            return;
                        },
                    };
                    for output in &block.wallet_outputs {
                        if let Some(index) = block_response
                            .outputs
                            .iter()
                            .position(|o| *o.encrypted_data() == output.encrypted_data)
                        {
                            let tx_output = block_response.outputs.get(index).expect("should exist").clone();
                            let output_hash = output.output_hash;
                            // Attempt to convert to wallet output
                            match output.to_wallet_output(tx_output, &self.key_manager) {
                                Ok(Some(wallet_output)) => {
                                    wallet_outputs.push((output_hash, wallet_output));
                                },
                                Ok(None) => {},
                                Err(e) => {
                                    errors.write().expect("Write lock should not be poisoned").push(e);
                                },
                            }
                        }
                    }
                }
                results
                    .write()
                    .expect("lock should not be poisoned")
                    .push(BlockScanResult {
                        height: block.height,
                        block_hash: block.block_hash,
                        wallet_outputs,
                        inputs: block.inputs.clone(),
                        mined_timestamp: block.mined_timestamp,
                    });
            });
        });
        if let Some(e) = errors.read().expect("read lock should not be poisoned").first() {
            return Err(e.clone());
        }
        let results = results.into_inner().expect("Lock should not be poisoned");
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

    /// Scan the mempool for wallet outputs
    /// Returns a tuple of (wallet outputs, spent input hashes)
    async fn scan_mempool(
        &mut self,
    ) -> WalletResult<(Vec<(TransactionOutput, MicroMinotari, MemoField)>, Vec<FixedHash>)> {
        let url = format!("{}/get_mempool_transactions", self.base_url);

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

        let response_text = response.text().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to read response body: {e}"
            )))
        })?;
        let mempool_response: HttpMempoolResponse = serde_json::from_str(&response_text).map_err(|e| {
            // dbg!(&response_text);
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Failed to parse mempool response: {e}"
            )))
        })?;

        let wallet_outputs = RwLock::new(Vec::new());
        let errors = RwLock::new(Vec::new());

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.number_processing_threads)
            .build()
            .map_err(|e| WalletError::ConfigurationError(format!("Failed to build thread pool: {}", e)))?;

        // For now just include all the spent inputs from all transactions
        let spent_inputs: Vec<FixedHash> = mempool_response
            .transactions
            .iter()
            .flat_map(|tx| tx.input_hashes.iter())
            .map(|input| FixedHash::from_hex(input))
            .collect::<Result<_, _>>()
            .map_err(|e| WalletError::ConversionError(e.to_string()))?;

        pool.install(|| {
            mempool_response.transactions.into_par_iter().for_each(|tx| {
                for output in &tx.outputs {
                    let output_hash = output.hash();
                    let commitment = output.commitment.clone();
                    let encrypted_data = output.encrypted_data.clone();

                    let sender_offset_public_key = output.sender_offset_public_key.clone();
                    match self.scan_for_recoverable_output(&ScanningOutputStruct {
                        min_info: tari_transaction_components::rpc::models::MinimalUtxoSyncInfo {
                            output_hash: output_hash.to_vec(),
                            commitment: commitment.to_vec(),
                            encrypted_data: encrypted_data.to_byte_vec(),
                            sender_offset_public_key: sender_offset_public_key.to_vec(),
                        },
                        commitment: commitment.clone(),
                        encrypted_data: encrypted_data.clone(),
                        sender_offset_public_key: sender_offset_public_key.clone(),
                    }) {
                        Ok(Some(incomplete_output)) => {
                            let value = incomplete_output.value;
                            let memo = incomplete_output.memo.clone();

                            wallet_outputs
                                .write()
                                .expect("write lock should not be poisoned")
                                .push((output.clone(), value, memo));
                        },
                        Ok(None) => {},
                        Err(e) => {
                            errors.write().expect("write lock should not be poisoned").push(e);
                        },
                    }
                }
            });
        });

        if let Some(e) = errors.read().expect("read lock should not be poisoned").first() {
            return Err(e.clone());
        }

        // for tx in &mempool_response.transactions {
        // for spent_input in &tx.spent_inputs {
        // Check if there are any outputs with those hashes
        // debug!("Mempool spent input: {}", spent_input.to_hex());
        // }
        // }

        Ok((
            wallet_outputs.into_inner().expect("lock should not be poisoned"),
            spent_inputs,
        ))
    }
}
