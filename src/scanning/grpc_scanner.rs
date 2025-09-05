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
use minotari_app_grpc::{tari_rpc, tari_rpc::HistoricalBlock};
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    transaction_components::{
        one_sided::shared_secret_to_output_encryption_key,
        Transaction,
        TransactionError,
        TransactionInput,
        TransactionKernel,
        TransactionOutput,
        WalletOutput,
    },
};
use tari_utilities::ByteArray;
use tonic::{transport::Channel, Request};

use crate::{
    data_structures::incompleted_scanned_output::{IncompleteScannedOutput, ScanningOutputStruct},
    errors::{DataStructureError, WalletError, WalletResult},
    scanning::{
        BlockInfo,
        BlockScanResult,
        BlockchainScanner,
        LegacyProgressCallback,
        ScanConfig,
        TipInfo,
        TransactionBroadcaster,
        WalletScanConfig,
        WalletScanResult,
        WalletScanner,
    },
    wallet::Wallet,
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
            .try_output_key_recovery(&output.commitment, &output.encrypted_data, None)
            .await
        {
            Ok(value) => value,
            // Key manager errors here are actual errors and should not be suppressed.
            Err(TransactionError::KeyManagerError(e)) => return Err(TransactionError::KeyManagerError(e).into()),
            Err(_) => return Ok(None),
        };
        Ok(WalletOutput::new_imported(
            value,
            commitment_mask,
            memo,
            output.clone(),
            &self.key_manager,
        ))
    }

    /// Scan for one-sided payments
    pub async fn scan_for_one_sided_payment(&self, output: &TransactionOutput) -> WalletResult<Option<WalletOutput>> {
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

        Ok(WalletOutput::new_imported(
            value,
            commitment_mask,
            memo,
            output.clone(),
            &self.key_manager,
        ))
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
            if let Some(historic_block) = &grpc_block? {
                return Ok(historic_block.outputs);
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
            if let Some(historic_block) = &grpc_block? {
                return Ok(historic_block.inputs);
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
            if let Some(historic_block) = &grpc_block? {
                return Ok(historic_block.kernels);
            }
        }

        Ok(Vec::new())
    }

    /// Get complete block data including outputs, inputs, and kernels
    pub async fn get_complete_block_data(&mut self, block_height: u64) -> WalletResult<Option<HistoricalBlock>> {
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
            return Some(grpc_block);
        }

        Ok(None)
    }

    /// Scan a single block for wallet outputs using the provided entropy
    pub async fn scan_block(&mut self, block_height: u64, entropy: &[u8; 16]) -> WalletResult<Vec<WalletOutput>> {
        let mut wallet_outputs = Vec::new();

        // Get all outputs from the block
        let outputs = self.get_outputs_from_block(block_height).await?;

        if outputs.is_empty() {
            return Ok(wallet_outputs);
        }

        // Create scanning logic with entropy
        let scanning_logic = DefaultScanningLogic::new(*entropy);

        // Process each output
        for output in outputs {
            // Try to extract wallet output using reference-compatible approach
            if let Some(wallet_output) = scanning_logic.extract_wallet_output(&output)? {
                wallet_outputs.push(wallet_output);
            }
        }

        Ok(wallet_outputs)
    }

    /// Get blocks by their heights in a batch
    pub async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<HistoricalBlock>> {
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
            blocks.push(grpc_block);
        }

        Ok(blocks)
    }
}

#[async_trait(?Send)]
impl BlockchainScanner for GrpcBlockchainScanner {
    async fn scan_blocks(&mut self, config: ScanConfig) -> WalletResult<Vec<BlockScanResult>> {
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
                if let Some(block_info) = Self::convert_block(&grpc_block)? {
                    let mut wallet_outputs = Vec::new();

                    // Process outputs without debug output - let caller decide what to log
                    for output in &block_info.outputs {
                        // Use enhanced multi-strategy scanning instead of basic extraction
                        let mut found_output = false;

                        // Strategy 1: Regular recoverable outputs (encrypted data decryption)
                        if !found_output {
                            if let Some(wallet_output) =
                                Self::scan_for_recoverable_output_grpc(output, &config.extraction_config)?
                            {
                                wallet_outputs.push(wallet_output);
                                found_output = true;
                            }
                        }

                        // Strategy 2: One-sided payments (different detection logic)
                        if !found_output {
                            if let Some(wallet_output) =
                                Self::scan_for_one_sided_payment_grpc(output, &config.extraction_config)?
                            {
                                wallet_outputs.push(wallet_output);
                                found_output = true;
                            }
                        }

                        // Strategy 3: Coinbase outputs (special handling)
                        if !found_output {
                            if let Some(wallet_output) = Self::scan_for_coinbase_output_grpc(output)? {
                                wallet_outputs.push(wallet_output);
                                // found_output = true;
                            }
                        }
                    }

                    batch_results.push(BlockScanResult {
                        height: block_info.height,
                        block_hash: block_info.hash,
                        outputs: block_info.outputs,
                        wallet_outputs,
                        mined_timestamp: block_info.timestamp,
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

    async fn search_utxos(&mut self, commitments: Vec<Vec<u8>>) -> WalletResult<Vec<BlockScanResult>> {
        let request = tari_rpc::SearchUtxosRequest { commitments };

        let mut stream = self
            .client
            .clone()
            .search_utxos(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut results = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? {
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                let mut wallet_outputs = Vec::new();
                for output in &block_info.outputs {
                    // Use default extraction config with no keys for commitment search
                    // This method is typically used for searching specific commitments
                    // where wallet ownership is already known
                    match extract_wallet_output(output, &ExtractionConfig::default()) {
                        Ok(wallet_output) => wallet_outputs.push(wallet_output),
                        Err(e) => {
                            println!("Failed to extract wallet output during commitment search: {e}");
                        },
                    }
                }
                results.push(BlockScanResult {
                    height: block_info.height,
                    block_hash: block_info.hash,
                    outputs: block_info.outputs,
                    wallet_outputs,
                    mined_timestamp: block_info.timestamp,
                });
            }
        }

        Ok(results)
    }

    async fn fetch_utxos(&mut self, hashes: Vec<Vec<u8>>) -> WalletResult<Vec<TransactionOutput>> {
        let request = tari_rpc::FetchMatchingUtxosRequest { hashes };

        let mut stream = self
            .client
            .clone()
            .fetch_matching_utxos(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut results = Vec::new();
        while let Some(response) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? {
            if let Some(output) = response.output {
                results.push(Self::convert_transaction_output(&output)?);
            }
        }

        Ok(results)
    }

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<BlockInfo>> {
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
            if let Some(block_info) = Self::convert_block(&grpc_block)? {
                blocks.push(block_info);
            }
        }

        Ok(blocks)
    }

    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<BlockInfo>> {
        let blocks = self.get_blocks_by_heights(vec![height]).await?;
        Ok(blocks.into_iter().next())
    }
}

#[async_trait(?Send)]
impl TransactionBroadcaster for GrpcBlockchainScanner {
    async fn submit_transaction(&mut self, transaction: Transaction) -> WalletResult<i32> {
        let request: tari_rpc::SubmitTransactionRequest = tari_rpc::SubmitTransactionRequest {
            transaction: Some(convert_transaction(transaction)),
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

impl std::fmt::Debug for GrpcBlockchainScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcBlockchainScanner")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Clone for GrpcBlockchainScanner {
    fn clone(&self) -> Self {
        // Note: This creates a new connection, which is expensive
        // In practice, you might want to use connection pooling
        panic!("GrpcBlockchainScanner cannot be cloned - create a new instance instead");
    }
}

/// Builder for creating GRPC blockchain scanners

pub struct GrpcScannerBuilder {
    base_url: Option<String>,
    timeout: Option<Duration>,
}

impl GrpcScannerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            base_url: None,
            timeout: None,
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

    /// Build the GRPC scanner
    pub async fn build(self) -> WalletResult<GrpcBlockchainScanner> {
        let base_url = self
            .base_url
            .ok_or_else(|| WalletError::ConfigurationError("Base URL not specified".to_string()))?;

        match self.timeout {
            Some(timeout) => GrpcBlockchainScanner::with_timeout(base_url, timeout).await,
            None => GrpcBlockchainScanner::new(base_url).await,
        }
    }
}

impl Default for GrpcScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Empty module when GRPC feature is not enabled
#[cfg(not(feature = "grpc"))]
pub struct GrpcBlockchainScanner;

#[cfg(not(feature = "grpc"))]
impl GrpcBlockchainScanner {
    pub async fn new(_base_url: String) -> crate::errors::WalletResult<Self> {
        Err(crate::errors::WalletError::OperationNotSupported(
            "GRPC feature not enabled".to_string(),
        ))
    }
}

#[cfg(not(feature = "grpc"))]
pub struct GrpcScannerBuilder;

#[cfg(not(feature = "grpc"))]
impl GrpcScannerBuilder {
    pub fn new() -> Self {
        Self
    }

    pub async fn build(self) -> crate::errors::WalletResult<GrpcBlockchainScanner> {
        Err(crate::errors::WalletError::OperationNotSupported(
            "GRPC feature not enabled".to_string(),
        ))
    }
}

#[async_trait(?Send)]
impl WalletScanner for GrpcBlockchainScanner {
    async fn scan_wallet(&mut self, config: WalletScanConfig) -> WalletResult<WalletScanResult> {
        self.scan_wallet_with_progress(config, None).await
    }

    async fn scan_wallet_with_progress(
        &mut self,
        config: WalletScanConfig,
        progress_callback: Option<&LegacyProgressCallback>,
    ) -> WalletResult<WalletScanResult> {
        // Validate that we have key management set up
        if config.key_manager.is_none() && config.key_store.is_none() {
            return Err(WalletError::ConfigurationError(
                "No key manager or key store provided for wallet scanning".to_string(),
            ));
        }

        // Use the default scanning logic with proper wallet key integration
        DefaultScanningLogic::scan_wallet_with_progress(self, config, progress_callback).await
    }

    fn blockchain_scanner(&mut self) -> &mut dyn BlockchainScanner {
        self
    }
}

#[cfg(test)]
#[cfg(not(feature = "grpc"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_grpc_feature_disabled() {
        let result = GrpcBlockchainScanner::new("http://127.0.0.1:18142".to_string()).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::errors::WalletError::OperationNotSupported(_)
        ));
    }

    #[tokio::test]
    async fn test_grpc_builder_feature_disabled() {
        let builder = GrpcScannerBuilder::new();
        let result = builder.build().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::errors::WalletError::OperationNotSupported(_)
        ));
    }
}
