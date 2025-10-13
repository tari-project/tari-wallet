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

use serde::{Deserialize, Serialize};
use tari_common_types::types::FixedHash;
use tari_transaction_components::{
    transaction_components::{WalletOutput},
};
use tari_utilities::epoch_time::EpochTime;


// Include GRPC scanner when the feature is enabled
#[cfg(feature = "grpc")]
pub mod grpc_scanner;

// Include HTTP scanner
#[cfg(feature = "http")]
pub mod http;
pub use http::scanner as http_scanner;






#[cfg(feature = "grpc")]
pub use scanner::{GrpcBlockchainScanner, GrpcScannerBuilder};
// Re-export HTTP scanner types
#[cfg(feature = "http")]
pub use http_scanner::HttpBlockchainScanner;
use crate::http::models::IncompleteScannedOutput;

mod interface;


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
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            start_height: 0,
            end_height: None,
            batch_size: 100,
            request_timeout: Duration::from_secs(30),
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
