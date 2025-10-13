//! GRPC-based blockchain scanner implementation
//!
//! This module provides a GRPC implementation of the BlockchainScanner trait
//! that connects to a Tari base node via GRPC to scan for wallet outputs.
//!
//! ## Wallet Key Integration
//!
//! The GRPC scanner supports wallet key integration for identifying outputs that belong
//! to a specific wallet.

use std::time::Duration;

use async_trait::async_trait;
use minotari_app_grpc::tari_rpc;
use primitive_types::U512;
use tari_common_types::types::FixedHash;
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    transaction_components::{Transaction, TransactionInput, TransactionKernel, TransactionOutput, WalletOutput},
};
use tonic::{transport::Channel, Request};

use crate::{
    errors::{WalletError, WalletResult},
    scanning::{BlockScanResult, BlockchainScanner, ScanConfig, TipInfo, TransactionBroadcaster},
    BlockHeaderInfo,
    ExtractionConfig,
};

/// GRPC client for connecting to Tari base node

pub struct GrpcBlockchainScanner<KM> {
    /// GRPC channel to the base node
    client: tari_rpc::base_node_client::BaseNodeClient<Channel>,
    /// Connection timeout
    timeout: Duration,
    /// Base URL for the GRPC connection
    base_url: String,
    /// key manager used for the keys
    pub key_manager: KM,
}

impl<KM> GrpcBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    /// Create a new GRPC scanner with the given base URL
    pub async fn new(base_url: String, key_manager: KM) -> WalletResult<Self> {
        let timeout = Duration::from_secs(30);
        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Invalid URL: {e}"
                )))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Connection failed: {e}"
                )))
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            base_url,
            key_manager,
        })
    }

    /// Create a new GRPC scanner with custom timeout
    pub async fn with_timeout(base_url: String, timeout: Duration, key_manager: KM) -> WalletResult<Self> {
        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Invalid URL: {e}"
                )))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Connection failed: {e}"
                )))
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            base_url,
            key_manager,
        })
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
            request_timeout: self.timeout,
            extraction_config,
        })
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    pub async fn scan_for_recoverable_output(&self, output: &TransactionOutput) -> WalletResult<Option<WalletOutput>> {
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
        match WalletOutput::new_imported(value, commitment_mask, memo, output.clone(), &self.key_manager).await {
            Ok(wallet_output) => Ok(Some(wallet_output)),
            Err(_) => Ok(None),
        }
    }

    /// Get all outputs from a specific block
    pub async fn get_outputs_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionOutput>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                return Ok(tari_block.dissolve().2);
            }
        }

        Ok(Vec::new())
    }

    /// Get all inputs from a specific block
    pub async fn get_inputs_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionInput>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                return Ok(tari_block.dissolve().1);
            }
        }

        Ok(Vec::new())
    }

    /// Get all kernels from a specific block
    pub async fn get_kernels_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionKernel>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                return Ok(tari_block.dissolve().3);
            }
        }

        Ok(Vec::new())
    }

    /// Get complete block data including outputs, inputs, and kernels
    pub async fn get_complete_block_data(&mut self, block_height: u64) -> WalletResult<Option<Block>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                return Ok(Some(tari_block));
            }
        }

        Ok(None)
    }

    /// Scan a single block for wallet outputs using the provided entropy
    pub async fn scan_block(&mut self, block_height: u64) -> WalletResult<Vec<WalletOutput>> {
        let mut wallet_outputs = Vec::new();

        // Get all outputs from the block
        let outputs = self.get_outputs_from_block(block_height).await?;

        if outputs.is_empty() {
            return Ok(wallet_outputs);
        }

        // Process each output
        for output in &outputs {
            if let Some(wallet_output) = self.scan_for_recoverable_output(output).await? {
                wallet_outputs.push(wallet_output);
                continue;
            }
        }

        Ok(wallet_outputs)
    }

    /// Get blocks by their heights in a batch
    pub async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                blocks.push(tari_block);
            }
        }

        Ok(blocks)
    }

    /// Convert GRPC tip info to lightweight tip info
    fn convert_tip_info(grpc_tip: &tari_rpc::TipInfoResponse) -> TipInfo {
        let metadata = grpc_tip.metadata.as_ref();

        TipInfo {
            best_block_height: metadata.map(|m| m.best_block_height).unwrap_or(0),
            best_block_hash: FixedHash::try_from(metadata.map(|m| m.best_block_hash.clone()).unwrap_or_default())
                .unwrap_or_default(),
            accumulated_difficulty: metadata
                .map(|m| U512::from_big_endian(&m.accumulated_difficulty).to_string())
                .unwrap_or_default(),
            pruned_height: metadata.map(|m| m.pruned_height).unwrap_or(0),
            timestamp: metadata.map(|m| m.timestamp).unwrap_or(0),
        }
    }
}

#[async_trait(?Send)]
impl<KM> BlockchainScanner for GrpcBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    async fn scan_blocks(&mut self, config: &ScanConfig) -> WalletResult<Vec<BlockScanResult>> {
        // Get tip info to determine end height
        let tip_info = self.get_tip_info().await?;
        let end_height = config.end_height.unwrap_or(tip_info.best_block_height);

        if config.start_height > end_height {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut current_height = config.start_height;

        while current_height <= end_height {
            let batch_end = std::cmp::min(current_height + config.batch_size - 1, end_height);
            let heights: Vec<u64> = (current_height..=batch_end).collect();
            // Get blocks for this batch
            let request = tari_rpc::GetBlocksRequest { heights };

            let mut stream = self
                .client
                .clone()
                .get_blocks(Request::new(request))
                .await
                .map_err(|e| {
                    WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                        "GRPC error: {e}"
                    )))
                })?
                .into_inner();

            let mut batch_results = Vec::new();
            while let Some(grpc_block) = stream.message().await.map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Stream error: {e}"
                )))
            })? {
                if let Some(block) = grpc_block.block {
                    let tari_block: Block = block.try_into()?;
                    let mut wallet_outputs = Vec::new();

                    // Process outputs without debug output - let caller decide what to log
                    for output in tari_block.body.outputs() {
                        if let Some(wallet_output) = self.scan_for_recoverable_output(output).await? {
                            wallet_outputs.push((output.hash(), wallet_output));
                            continue;
                        }
                    }
                    let inputs = tari_block.body.inputs().iter().map(|i| i.output_hash()).collect();

                    batch_results.push(BlockScanResult {
                        height: tari_block.header.height,
                        block_hash: tari_block.hash(),
                        wallet_outputs,
                        inputs,
                        mined_timestamp: tari_block.header.timestamp.as_u64(),
                    });
                }
            }

            results.extend(batch_results);
            current_height = batch_end + 1;
        }

        Ok(results)
    }

    async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
        let request = Request::new(tari_rpc::Empty {});

        let response = self.client.clone().get_tip_info(request).await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC error: {e}"
            )))
        })?;

        let tip_info = response.into_inner();
        Ok(Self::convert_tip_info(&tip_info))
    }

    async fn search_utxos(&mut self, _commitments: Vec<Vec<u8>>) -> WalletResult<Vec<BlockScanResult>> {
        Ok(Vec::new())
    }

    async fn fetch_utxos(&mut self, _hashes: Vec<Vec<u8>>) -> WalletResult<Vec<TransactionOutput>> {
        Ok(Vec::new())
    }

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                blocks.push(tari_block);
            }
        }

        Ok(blocks)
    }

    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<Block>> {
        let blocks = self.get_blocks_by_heights(vec![height]).await?;
        Ok(blocks.into_iter().next())
    }

    async fn get_header_by_height(&mut self, height: u64) -> WalletResult<Option<BlockHeaderInfo>> {
        let block = self.get_block_by_height(height).await?;
        if let Some(b) = block {
            Ok(Some(BlockHeaderInfo {
                height: b.header.height,
                hash: b.hash(),
                timestamp: b.header.timestamp,
            }))
        } else {
            Ok(None)
        }
    }
}

#[async_trait(?Send)]
impl<KM> TransactionBroadcaster for GrpcBlockchainScanner<KM>
where KM: TransactionKeyManagerInterface
{
    async fn submit_transaction(&mut self, transaction: Transaction) -> WalletResult<i32> {
        let request: tari_rpc::SubmitTransactionRequest = tari_rpc::SubmitTransactionRequest {
            transaction: Some(
                tari_rpc::Transaction::try_from(transaction.clone())
                    .map_err(|e| WalletError::GrpcError(e.to_string()))?,
            ),
        };
        let response = self
            .client
            .clone()
            .submit_transaction(request)
            .await
            .map_err(|e| WalletError::GrpcError(e.to_string()))?
            .into_inner();

        Ok(response.result)
    }
}

impl<KM> std::fmt::Debug for GrpcBlockchainScanner<KM> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcBlockchainScanner")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish()
    }
}



/// Builder for creating GRPC blockchain scanners

pub struct GrpcScannerBuilder<KM> {
    base_url: Option<String>,
    timeout: Option<Duration>,
    key_manager: Option<KM>,
}

impl<KM> GrpcScannerBuilder<KM>
where KM: TransactionKeyManagerInterface
{
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            base_url: None,
            timeout: None,
            key_manager: None,
        }
    }

    /// Set the base URL for the GRPC connection
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Set the timeout for GRPC operations
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the key manager for wallet key integration
    pub fn with_key_manager(mut self, key_manager: KM) -> Self {
        self.key_manager = Some(key_manager);
        self
    }

    /// Build the GRPC scanner
    pub async fn build(self) -> WalletResult<GrpcBlockchainScanner<KM>> {
        let base_url = self
            .base_url
            .ok_or_else(|| WalletError::ConfigurationError("Base URL not specified".to_string()))?;

        let key_manager = self
            .key_manager
            .ok_or_else(|| WalletError::ConfigurationError("Key manager not specified".to_string()))?;

        match self.timeout {
            Some(timeout) => GrpcBlockchainScanner::with_timeout(base_url, timeout, key_manager).await,
            None => GrpcBlockchainScanner::new(base_url, key_manager).await,
        }
    }
}

