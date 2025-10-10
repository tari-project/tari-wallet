//! UTXO scanning module for lightweight wallet libraries
//!
//! This module provides a lightweight interface for scanning the Tari blockchain
//! for wallet outputs. It uses a trait-based approach that allows different
//! backend implementations (gRPC, HTTP, etc.) to be plugged in.
//!
//! ## Scanner Refactoring Components
//!
//! The following modules support the refactored scanner.rs binary:
//! - `scan_config`: Configuration structures for scanner binary operations
//! - `storage_manager`: Storage abstraction for scanner binary
//! - `background_writer`: Async database operations for scanner binary
//! - `wallet_scanner`: Main scanning implementation for scanner binary
//! - `progress`: Progress tracking utilities for scanner binary

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tari_common_types::types::FixedHash;
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    transaction_components::{Transaction, TransactionOutput, WalletOutput},
};
use tari_utilities::epoch_time::EpochTime;

use crate::{
    errors::{WalletError, WalletResult},
    extraction::ExtractionConfig,
};

// Include GRPC scanner when the feature is enabled
#[cfg(feature = "grpc")]
pub mod grpc_scanner;

// Include HTTP scanner
#[cfg(feature = "http")]
pub mod http;
pub use http::scanner as http_scanner;

// Scanner refactoring modules (for binary refactoring)
pub mod scan_config;



pub mod wallet_scanner;

#[cfg(all(feature = "storage", feature = "http"))]
pub mod new_wallet_scanner;


#[cfg(feature = "grpc")]
pub use grpc_scanner::{GrpcBlockchainScanner, GrpcScannerBuilder};
// Re-export HTTP scanner types
#[cfg(feature = "http")]
pub use http_scanner::HttpBlockchainScanner;
// Re-export progress tracking types for scanner binary operations
pub use progress::{ProgressCallback, ProgressConfig, ProgressInfo, ProgressTracker};
// Re-export configuration types for scanner binary operations
pub use scan_config::{BinaryScanConfig, OutputFormat};
// Re-export storage manager types for scanner binary operations
#[cfg(feature = "storage")]
pub use storage_manager::ScannerStorage;
pub use wallet_scanner::{
    RetryConfig,
    ScanMetadata,
    ScanResult,
    ScannerBuilder,
    ScannerConfigError,
    WalletScanner as WalletScannerStruct,
    WalletScannerConfig,
};

// Event emitter module for scanner integration with event system
pub mod event_emitter;
mod interface;

// Re-export event emitter types
#[cfg(feature = "storage")]
pub use event_emitter::create_database_event_emitter;
pub use event_emitter::{
    create_address_info_from_transaction,
    create_block_info_from_block,
    create_default_event_emitter,
    ScanEventEmitter,
};

use crate::data_structures::incompleted_scanned_output::IncompleteScannedOutput;

/// Legacy progress callback for scanning operations (for compatibility)
pub type LegacyProgressCallback = Box<dyn Fn(ScanProgress) + Send + Sync>;

/// Scanning progress information
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Current block height being scanned
    pub current_height: u64,
    /// Target block height to scan to
    pub target_height: u64,
    /// Number of outputs found so far
    pub outputs_found: u64,
    /// Total value of outputs found so far (in MicroMinotari)
    pub total_value: u64,
    /// Time elapsed since scan started
    pub elapsed: Duration,
}

/// Configuration for blockchain scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Starting block height (wallet birthday)
    pub start_height: u64,
    /// Ending block height (optional, if None scans to tip)
    pub end_height: Option<u64>,
    /// Maximum number of blocks to scan in one request
    pub batch_size: u64,
    /// Timeout for requests
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
    /// Extraction configuration (excluded from serialization for security)
    #[serde(skip)]
    pub extraction_config: ExtractionConfig,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            start_height: 0,
            end_height: None,
            batch_size: 100,
            request_timeout: Duration::from_secs(30),
            extraction_config: ExtractionConfig::default(),
        }
    }
}

impl ScanConfig {
    pub fn with_start_height(mut self, start_height: u64) -> Self {
        self.start_height = start_height;
        self
    }

    pub fn with_end_height(mut self, end_height: u64) -> Self {
        self.end_height = Some(end_height);
        self
    }

    pub fn with_start_end_heights(mut self, start_height: u64, end_height: u64) -> Self {
        self.start_height = start_height;
        self.end_height = Some(end_height);
        self
    }
}

// Helper module for Duration serialization
mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where D: Deserializer<'de> {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

impl ScanConfig {
    /// Create a new scan config with a progress callback
    pub fn with_progress_callback(self, callback: LegacyProgressCallback) -> ScanConfigWithCallback {
        ScanConfigWithCallback {
            config: self,
            progress_callback: Some(callback),
        }
    }
}

/// Scan config with progress callback (not Debug/Clone)
pub struct ScanConfigWithCallback {
    pub config: ScanConfig,
    pub progress_callback: Option<LegacyProgressCallback>,
}

/// Configuration for wallet-specific scanning
pub struct WalletScanConfig<KM> {
    /// Base scan configuration
    pub scan_config: ScanConfig,
    /// Key manager for wallet key derivation
    pub key_manager: KM,
    /// Maximum number of addresses to scan per account
    pub max_addresses_per_account: u32,
}

impl<KM> WalletScanConfig<KM>
where KM: TransactionKeyManagerInterface
{
    /// Create a new wallet scan config
    pub fn new(start_height: u64, key_manager: KM) -> Self {
        Self {
            scan_config: ScanConfig {
                start_height,
                end_height: None,
                batch_size: 100,
                request_timeout: Duration::from_secs(30),
                extraction_config: ExtractionConfig::default(),
            },
            key_manager,
            max_addresses_per_account: 1000,
        }
    }

    /// Set maximum addresses per account
    pub fn with_max_addresses_per_account(mut self, max: u32) -> Self {
        self.max_addresses_per_account = max;
        self
    }

    /// Set the end height
    pub fn with_end_height(mut self, end_height: u64) -> Self {
        self.scan_config.end_height = Some(end_height);
        self
    }

    /// Set the batch size
    pub fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.scan_config.batch_size = batch_size;
        self
    }

    /// Set the request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.scan_config.request_timeout = timeout;
        self
    }
}

/// Result of a wallet scan operation
#[derive(Debug, Clone)]
pub struct WalletScanResult {
    /// Block scan results
    pub block_results: Vec<BlockScanResult>,
    /// Total wallet outputs found
    pub total_wallet_outputs: u64,
    /// Total value found (in MicroMinotari)
    pub total_value: u64,
    /// Number of addresses scanned
    pub addresses_scanned: u64,
    /// Number of accounts scanned
    pub accounts_scanned: u64,
    /// Scan duration
    pub scan_duration: Duration,
}

/// Chain tip information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipInfo {
    /// Current best block height
    pub best_block_height: u64,
    /// Current best block hash
    pub best_block_hash: FixedHash,
    /// Accumulated difficulty
    pub accumulated_difficulty: String,
    /// Pruned height (minimum height this node can provide complete blocks for)
    pub pruned_height: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Result of a block scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoScanResult {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: FixedHash,
    /// Wallet outputs extracted from transaction outputs
    pub wallet_outputs: Vec<IncompleteScannedOutput>,
    /// Input hashes
    pub inputs: Vec<FixedHash>,
    /// Timestamp when block was mined
    pub mined_timestamp: u64,
}

/// Result of a block scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockScanResult {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: FixedHash,
    /// Wallet outputs extracted from transaction outputs (hash, output)
    pub wallet_outputs: Vec<(FixedHash, WalletOutput)>,
    /// Input hashes
    pub inputs: Vec<FixedHash>,
    /// Timestamp when block was mined
    pub mined_timestamp: u64,
}

/// Block header information
#[derive(Debug, Clone)]
pub struct BlockHeaderInfo {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: FixedHash,
    /// Timestamp
    pub timestamp: EpochTime,
}


/// Builder for creating blockchain scanners

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub retry_attempts: u32,
}

impl<KM> BlockchainScannerBuilder<KM>
where KM: TransactionKeyManagerInterface
{
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            scanner_type: None,
            config: None,
        }
    }

    /// Set the scanner type
    pub fn with_type(mut self, scanner_type: ScannerType<KM>) -> Self {
        self.scanner_type = Some(scanner_type);
        self
    }

    /// Set the scanner configuration
    pub fn with_config(mut self, config: ScannerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Build the scanner
    pub async fn build(self) -> WalletResult<Box<dyn BlockchainScanner>> {
        match self.scanner_type {
            Some(ScannerType::Mock) => Ok(Box::new(MockBlockchainScanner::new())),

            #[cfg(feature = "grpc")]
            Some(ScannerType::Grpc { url, key_manager }) => {
                {
                    let scanner = GrpcBlockchainScanner::new(url, key_manager).await?;
                    Ok(Box::new(scanner))
                }
            },
            #[cfg(feature = "http")]
            Some(ScannerType::Http { .. }) => {
                unimplemented!()
            },
            None => Err(WalletError::ConfigurationError(
                "Scanner type not specified".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_arch = "wasm32"))]
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert_eq!(config.start_height, 0);
        assert_eq!(config.end_height, None);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert!(config.extraction_config.enable_key_derivation);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_scan_progress() {
        let progress = ScanProgress {
            current_height: 1000,
            target_height: 2000,
            outputs_found: 5,
            total_value: 1000000,
            elapsed: Duration::from_secs(10),
        };

        assert_eq!(progress.current_height, 1000);
        assert_eq!(progress.target_height, 2000);
        assert_eq!(progress.outputs_found, 5);
        assert_eq!(progress.total_value, 1000000);
        assert_eq!(progress.elapsed, Duration::from_secs(10));
    }


    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_tip_info() {
        let tip_info = TipInfo {
            best_block_height: 1000,
            best_block_hash: FixedHash::new([1u8; 32]),
            accumulated_difficulty: "5678".to_string(),
            pruned_height: 500,
            timestamp: 1234567890,
        };

        assert_eq!(tip_info.best_block_height, 1000);
        assert_eq!(tip_info.best_block_hash, vec![1, 2, 3, 4]);
        assert_eq!(tip_info.accumulated_difficulty, "5678");
        assert_eq!(tip_info.pruned_height, 500);
        assert_eq!(tip_info.timestamp, 1234567890);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_mock_scanner() {
        let mut scanner = MockBlockchainScanner::new();
        let tip_info = scanner.get_tip_info().await.unwrap();
        assert_eq!(tip_info.best_block_height, 1000);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_scanner_builder() {
        let builder = BlockchainScannerBuilder::new().with_type(ScannerType::Mock);

        let mut scanner = builder.build().await.unwrap();
        let tip_info = scanner.get_tip_info().await.unwrap();
        assert_eq!(tip_info.best_block_height, 1000);
    }
}
