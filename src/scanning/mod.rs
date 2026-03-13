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
use tari_transaction_components::transaction_components::WalletOutput;
use tari_utilities::epoch_time::EpochTime;

/// Default number of blocks before the chain tip used as the safety buffer during fast sync.
/// Blocks within this distance from the tip are scanned in full.
pub const DEFAULT_FAST_SYNC_SAFETY_BUFFER: u64 = 720;

// Include GRPC scanner when the feature is enabled
#[cfg(feature = "grpc")]
pub mod grpc;

// Include HTTP scanner
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "grpc")]
pub use grpc::scanner::{GrpcBlockchainScanner, GrpcScannerBuilder};
pub use http::scanner as http_scanner;
// Re-export HTTP scanner types
#[cfg(feature = "http")]
pub use http_scanner::HttpBlockchainScanner;

use crate::http::models::IncompleteScannedOutput;

mod interface;
pub use interface::BlockchainScanner;

/// Configuration for blockchain scanning
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanConfig {
    /// Starting block height (wallet birthday)
    pub start_height: u64,
    /// Ending block height (optional, if None scans to tip)
    pub end_height: Option<u64>,
    /// Maximum number of blocks to scan in one request, default 10
    pub batch_size: Option<u64>,
    /// Timeout for requests
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            start_height: 0,
            end_height: None,
            batch_size: Some(100),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl ScanConfig {
    #[must_use]
    pub const fn with_start_height(mut self, start_height: u64) -> Self {
        self.start_height = start_height;
        self
    }

    #[must_use]
    pub const fn with_end_height(mut self, end_height: u64) -> Self {
        self.end_height = Some(end_height);
        self
    }

    #[must_use]
    pub const fn with_start_end_heights(mut self, start_height: u64, end_height: u64) -> Self {
        self.start_height = start_height;
        self.end_height = Some(end_height);
        self
    }

    #[must_use]
    pub const fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.batch_size = Some(batch_size);
        self
    }
}

/// Configuration for the three-phase fast sync scanning method
///
/// The fast sync method improves initial wallet recovery time by combining:
/// 1. A fast phase that queries only the unspent UTXO set at `fast_sync_target_height`
///    (avoids scanning every block from birthday to target height individually).
/// 2. A full block-by-block scan of the recent blocks from `fast_sync_target_height` to tip
///    to catch the latest transactions.
/// 3. A full historical scan from birthday to tip (run separately by the caller) to
///    reconstruct the complete wallet history.
///
/// The `fast_sync_target_height` is computed as `tip_height - fast_sync_safety_buffer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FastSyncConfig {
    /// Starting block height (wallet birthday)
    pub birthday: u64,
    /// Number of blocks before the chain tip that form the boundary between the
    /// fast-scan phase and the full-scan phase.  Defaults to
    /// [`DEFAULT_FAST_SYNC_SAFETY_BUFFER`] (720 blocks).
    pub fast_sync_safety_buffer: u64,
    /// Maximum number of blocks to scan per request during the full-scan phases
    pub batch_size: Option<u64>,
    /// Timeout for individual requests
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
}

impl Default for FastSyncConfig {
    fn default() -> Self {
        Self {
            birthday: 0,
            fast_sync_safety_buffer: DEFAULT_FAST_SYNC_SAFETY_BUFFER,
            batch_size: Some(100),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl FastSyncConfig {
    /// Create a new `FastSyncConfig` with the given wallet birthday and all other
    /// fields set to their defaults.
    #[must_use]
    pub fn new(birthday: u64) -> Self {
        Self {
            birthday,
            ..Default::default()
        }
    }

    /// Override the safety buffer (number of blocks before tip scanned in full).
    #[must_use]
    pub const fn with_safety_buffer(mut self, buffer: u64) -> Self {
        self.fast_sync_safety_buffer = buffer;
        self
    }

    /// Override the per-request batch size.
    #[must_use]
    pub const fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.batch_size = Some(batch_size);
        self
    }
}

/// Result returned by the three-phase fast sync operation.
#[derive(Debug, Clone)]
pub struct FastSyncResult {
    /// Phase 1 results: outputs recovered from the unspent UTXO set at
    /// `fast_sync_target_height` (birthday → `fast_sync_target_height`).
    pub phase1_results: Vec<BlockScanResult>,
    /// Phase 2 results: full block-by-block scan results for the recent range
    /// (`fast_sync_target_height` → tip).
    pub phase2_results: Vec<BlockScanResult>,
    /// The computed `fast_sync_target_height` (`tip_height - fast_sync_safety_buffer`).
    pub fast_sync_target_height: u64,
    /// The chain tip height at the time the fast sync was initiated.
    pub tip_height: u64,
    /// A [`ScanConfig`] pre-populated with `start_height = birthday` and
    /// `end_height = tip_height` that the caller can use to run the background
    /// full-history scan (Phase 3) at a convenient time.
    pub full_history_scan_config: ScanConfig,
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
    pub wallet_outputs: Vec<(FixedHash, WalletOutput, usize)>,
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

#[derive(Debug, Clone)]
struct InProgressScan {
    config: Option<ScanConfig>,
    header: Option<String>,
    current_page: u64,
}

impl InProgressScan {
    pub const fn new(config: ScanConfig) -> Self {
        Self {
            config: Some(config),
            header: None,
            current_page: 0,
        }
    }

    pub const fn new_empty() -> Self {
        Self {
            config: None,
            header: None,
            current_page: 0,
        }
    }

    pub fn clear(&mut self) {
        self.config = None;
        self.header = None;
        self.current_page = 0;
    }

    pub const fn page(&self) -> u64 {
        self.current_page
    }

    pub const fn is_active(&self) -> bool {
        self.config.is_some()
    }

    pub const fn increment_page(&mut self) {
        self.current_page += 1;
    }

    pub fn set_next_request(&mut self, header: String) {
        self.header = Some(header);
        self.current_page = 0;
    }

    pub const fn get_header(&self) -> Option<&String> {
        self.header.as_ref()
    }

    pub const fn get_config(&self) -> Option<&ScanConfig> {
        self.config.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_trait::async_trait;
    use tari_common_types::types::FixedHash;
    use tari_node_components::blocks::Block;
    use tari_transaction_components::transaction_components::TransactionOutput;

    use super::*;
    use crate::{BlockHeaderInfo, BlockScanResult, TipInfo, WalletResult};

    // ── Minimal mock scanner for testing fast_sync orchestration ─────────────

    struct MockScanner {
        tip_height: u64,
        scan_calls: Vec<ScanConfig>,
    }

    impl MockScanner {
        fn new(tip_height: u64) -> Self {
            Self {
                tip_height,
                scan_calls: Vec::new(),
            }
        }
    }

    #[async_trait]
    impl BlockchainScanner for MockScanner {
        async fn scan_blocks(&mut self, config: &ScanConfig) -> WalletResult<(Vec<BlockScanResult>, bool)> {
            self.scan_calls.push(config.clone());
            Ok((Vec::new(), false))
        }

        async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
            Ok(TipInfo {
                best_block_height: self.tip_height,
                best_block_hash: FixedHash::default(),
                accumulated_difficulty: "0".to_string(),
                pruned_height: 0,
                timestamp: 0,
            })
        }

        async fn search_utxos(&mut self, _commitments: Vec<Vec<u8>>) -> WalletResult<Vec<BlockScanResult>> {
            Ok(Vec::new())
        }

        async fn fetch_utxos(&mut self, _hashes: Vec<Vec<u8>>) -> WalletResult<Vec<TransactionOutput>> {
            Ok(Vec::new())
        }

        async fn get_blocks_by_heights(&mut self, _heights: Vec<u64>) -> WalletResult<Vec<Block>> {
            Ok(Vec::new())
        }

        async fn get_block_by_height(&mut self, _height: u64) -> WalletResult<Option<Block>> {
            Ok(None)
        }

        async fn get_header_by_height(&mut self, _height: u64) -> WalletResult<Option<BlockHeaderInfo>> {
            Ok(None)
        }
    }

    // ── fast_sync orchestration tests ─────────────────────────────────────────

    #[tokio::test]
    async fn test_fast_sync_phases_are_correct() {
        let mut scanner = MockScanner::new(1000);
        // birthday=100, safety_buffer=200 → fast_sync_target_height = 1000-200 = 800
        let config = FastSyncConfig::new(100).with_safety_buffer(200);
        let result = scanner.fast_sync(&config).await.expect("fast_sync failed");

        assert_eq!(result.tip_height, 1000);
        assert_eq!(result.fast_sync_target_height, 800);
        // Full-history config must cover birthday→tip
        assert_eq!(result.full_history_scan_config.start_height, 100);
        assert_eq!(result.full_history_scan_config.end_height, Some(1000));

        // Phase 1 and Phase 2 each produce one scan_blocks call (mock returns more_blocks=false)
        assert_eq!(scanner.scan_calls.len(), 2);
        // Phase 1: birthday → fast_sync_target_height
        assert_eq!(scanner.scan_calls[0].start_height, 100);
        assert_eq!(scanner.scan_calls[0].end_height, Some(800));
        // Phase 2: fast_sync_target_height → tip
        assert_eq!(scanner.scan_calls[1].start_height, 800);
        assert_eq!(scanner.scan_calls[1].end_height, Some(1000));
    }

    #[tokio::test]
    async fn test_fast_sync_skips_phase1_when_birthday_at_target() {
        // birthday == fast_sync_target_height → phase 1 should be skipped
        let mut scanner = MockScanner::new(1000);
        let config = FastSyncConfig::new(800).with_safety_buffer(200); // target = 800
        let result = scanner.fast_sync(&config).await.expect("fast_sync failed");

        assert_eq!(result.fast_sync_target_height, 800);
        // Only phase 2 scan_blocks call should have been made
        assert_eq!(scanner.scan_calls.len(), 1);
        assert_eq!(scanner.scan_calls[0].start_height, 800);
    }

    #[tokio::test]
    async fn test_fast_sync_skips_phase2_when_target_at_tip() {
        // safety_buffer=0 → fast_sync_target_height == tip → phase 2 should be skipped
        let mut scanner = MockScanner::new(1000);
        let config = FastSyncConfig::new(0).with_safety_buffer(0);
        let result = scanner.fast_sync(&config).await.expect("fast_sync failed");

        assert_eq!(result.fast_sync_target_height, 1000);
        // Only phase 1 scan_blocks call should have been made
        assert_eq!(scanner.scan_calls.len(), 1);
        assert_eq!(scanner.scan_calls[0].start_height, 0);
        assert_eq!(scanner.scan_calls[0].end_height, Some(1000));
    }

    #[tokio::test]
    async fn test_fast_sync_saturating_sub_prevents_underflow() {
        // tip_height < safety_buffer → saturating_sub → target_height = 0
        let mut scanner = MockScanner::new(100);
        let config = FastSyncConfig::new(0).with_safety_buffer(720); // 100 - 720 saturates to 0
        let result = scanner.fast_sync(&config).await.expect("fast_sync failed");

        assert_eq!(result.fast_sync_target_height, 0);
        // birthday(0) is NOT < target(0), so phase 1 skipped.
        // target(0) IS < tip(100), so phase 2 runs.
        assert_eq!(scanner.scan_calls.len(), 1);
        assert_eq!(scanner.scan_calls[0].start_height, 0);
        assert_eq!(scanner.scan_calls[0].end_height, Some(100));
    }

    // ── FastSyncConfig ────────────────────────────────────────────────────────

    #[test]
    fn test_fast_sync_config_default() {
        let config = FastSyncConfig::default();
        assert_eq!(config.birthday, 0);
        assert_eq!(config.fast_sync_safety_buffer, DEFAULT_FAST_SYNC_SAFETY_BUFFER);
        assert_eq!(config.batch_size, Some(100));
        assert_eq!(config.request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_fast_sync_config_new() {
        let config = FastSyncConfig::new(1000);
        assert_eq!(config.birthday, 1000);
        assert_eq!(config.fast_sync_safety_buffer, DEFAULT_FAST_SYNC_SAFETY_BUFFER);
    }

    #[test]
    fn test_fast_sync_config_builder() {
        let config = FastSyncConfig::new(500)
            .with_safety_buffer(360)
            .with_batch_size(50);
        assert_eq!(config.birthday, 500);
        assert_eq!(config.fast_sync_safety_buffer, 360);
        assert_eq!(config.batch_size, Some(50));
    }

    #[test]
    fn test_fast_sync_config_serialization() {
        let config = FastSyncConfig::new(1234).with_safety_buffer(100).with_batch_size(20);
        let json = serde_json::to_string(&config).expect("serialization failed");
        let deserialized: FastSyncConfig = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(config, deserialized);
    }

    // ── DEFAULT_FAST_SYNC_SAFETY_BUFFER ───────────────────────────────────────

    #[test]
    fn test_default_fast_sync_safety_buffer_value() {
        assert_eq!(DEFAULT_FAST_SYNC_SAFETY_BUFFER, 720);
    }

    // ── ScanConfig helpers ────────────────────────────────────────────────────

    #[test]
    fn test_scan_config_default() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.start_height, 0);
        assert_eq!(cfg.end_height, None);
        assert_eq!(cfg.batch_size, Some(100));
    }

    #[test]
    fn test_scan_config_builders() {
        let cfg = ScanConfig::default()
            .with_start_height(100)
            .with_end_height(200)
            .with_batch_size(10);
        assert_eq!(cfg.start_height, 100);
        assert_eq!(cfg.end_height, Some(200));
        assert_eq!(cfg.batch_size, Some(10));
    }

    #[test]
    fn test_scan_config_with_start_end_heights() {
        let cfg = ScanConfig::default().with_start_end_heights(50, 150);
        assert_eq!(cfg.start_height, 50);
        assert_eq!(cfg.end_height, Some(150));
    }
}
