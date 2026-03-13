use async_trait::async_trait;
use tari_node_components::blocks::Block;
use tari_transaction_components::transaction_components::TransactionOutput;

use crate::{BlockHeaderInfo, BlockScanResult, FastSyncConfig, FastSyncResult, ScanConfig, TipInfo, WalletResult};

/// Blockchain scanner trait for scanning UTXOs
///
/// This trait provides a lightweight interface that can be implemented by
/// different backend providers (gRPC, HTTP, etc.) without requiring heavy
/// dependencies in the core library.
#[async_trait]
pub trait BlockchainScanner: Send + Sync {
    /// Scan for wallet outputs in the specified block range
    async fn scan_blocks(&mut self, config: &ScanConfig) -> WalletResult<(Vec<BlockScanResult>, bool)>;
    /// Get the current chain tip information
    async fn get_tip_info(&mut self) -> WalletResult<TipInfo>;

    /// Search for specific UTXOs by commitment
    async fn search_utxos(&mut self, commitments: Vec<Vec<u8>>) -> WalletResult<Vec<BlockScanResult>>;

    /// Fetch specific UTXOs by hash
    async fn fetch_utxos(&mut self, hashes: Vec<Vec<u8>>) -> WalletResult<Vec<TransactionOutput>>;

    /// Get blocks by height range
    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>>;

    /// Get a single block by height
    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<Block>>;

    async fn get_header_by_height(&mut self, height: u64) -> WalletResult<Option<BlockHeaderInfo>>;

    /// Perform a three-phase fast sync to quickly recover wallet balance and history.
    ///
    /// ## Phases
    ///
    /// 1. **Fast phase** (`birthday` → `fast_sync_target_height`): queries the base node for
    ///    unspent UTXOs only at `fast_sync_target_height`, avoiding a full block-by-block scan
    ///    of the potentially large range from birthday to target height.
    ///
    /// 2. **Full phase** (`fast_sync_target_height` → `tip`): performs a complete block-by-block
    ///    scan of the recent blocks so that the latest transactions are not missed.
    ///
    /// 3. **History phase config** (returned, not executed): the caller receives a
    ///    [`ScanConfig`] covering `birthday` → `tip` which can be used to run a full
    ///    background scan that reconstructs complete wallet history.
    ///
    /// `fast_sync_target_height = tip_height - fast_sync_safety_buffer`
    /// (default safety buffer: [`crate::DEFAULT_FAST_SYNC_SAFETY_BUFFER`] = 720 blocks).
    async fn fast_sync(&mut self, config: &FastSyncConfig) -> WalletResult<FastSyncResult> {
        // ── Step 1: determine the current tip ───────────────────────────────
        let tip_info = self.get_tip_info().await?;
        let tip_height = tip_info.best_block_height;

        // ── Step 2: calculate the boundary between the two scan phases ───────
        let fast_sync_target_height = tip_height.saturating_sub(config.fast_sync_safety_buffer);

        // ── Phase 1: scan birthday → fast_sync_target_height ─────────────────
        // Asks the base node for unspent UTXOs at fast_sync_target_height so
        // we do not have to replay every block in that (potentially large) range.
        let mut phase1_results = Vec::new();
        if config.birthday < fast_sync_target_height {
            let phase1_config = ScanConfig {
                start_height: config.birthday,
                end_height: Some(fast_sync_target_height),
                batch_size: config.batch_size,
                request_timeout: config.request_timeout,
            };
            loop {
                let (results, more_blocks) = self.scan_blocks(&phase1_config).await?;
                phase1_results.extend(results);
                if !more_blocks {
                    break;
                }
            }
        }

        // ── Phase 2: full scan fast_sync_target_height → tip ─────────────────
        // The recent blocks are always scanned in full to capture the latest
        // outputs and inputs.
        let mut phase2_results = Vec::new();
        if fast_sync_target_height < tip_height {
            let phase2_config = ScanConfig {
                start_height: fast_sync_target_height,
                end_height: Some(tip_height),
                batch_size: config.batch_size,
                request_timeout: config.request_timeout,
            };
            loop {
                let (results, more_blocks) = self.scan_blocks(&phase2_config).await?;
                phase2_results.extend(results);
                if !more_blocks {
                    break;
                }
            }
        }

        // ── Phase 3 config: full historical scan birthday → tip ───────────────
        // The caller is responsible for running this scan in the background to
        // fill in the complete wallet history (including spent outputs).
        let full_history_scan_config = ScanConfig {
            start_height: config.birthday,
            end_height: Some(tip_height),
            batch_size: config.batch_size,
            request_timeout: config.request_timeout,
        };

        Ok(FastSyncResult {
            phase1_results,
            phase2_results,
            fast_sync_target_height,
            tip_height,
            full_history_scan_config,
        })
    }
}
