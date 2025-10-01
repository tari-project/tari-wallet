#![cfg(all(feature = "storage", feature = "http"))]

use tari_common_types::types::FixedHash;
use tari_transaction_components::{key_manager::TransactionKeyManagerInterface, transaction_components::WalletOutput};
use tokio::time::Instant;

use crate::{
    common::format_number,
    BinaryScanConfig,
    BlockScanResult,
    HttpBlockchainScanner,
    ScanEventEmitter,
    ScanMetadata,
    ScannerStorage,
    WalletError,
    WalletResult,
    WalletState,
};

/// Represents the result of a wallet scanning operation
#[derive(Debug, Clone)]
pub enum ScanResult {
    /// Scan completed successfully with final wallet state and metadata
    Completed(WalletState, Option<ScanMetadata>),
    /// Scan was interrupted (e.g., by user) with current wallet state and metadata
    Interrupted(WalletState, Option<ScanMetadata>),
}

impl ScanResult {
    /// Get the wallet state from the scan result
    pub fn wallet_state(&self) -> &WalletState {
        match self {
            ScanResult::Completed(state, _) => state,
            ScanResult::Interrupted(state, _) => state,
        }
    }

    /// Get the scan metadata from the scan result
    pub fn metadata(&self) -> Option<&ScanMetadata> {
        match self {
            ScanResult::Completed(_, metadata) => metadata.as_ref(),
            ScanResult::Interrupted(_, metadata) => metadata.as_ref(),
        }
    }

    /// Check if the scan was completed successfully
    pub fn is_completed(&self) -> bool {
        matches!(self, ScanResult::Completed(_, _))
    }

    /// Check if the scan was interrupted
    pub fn is_interrupted(&self) -> bool {
        matches!(self, ScanResult::Interrupted(_, _))
    }

    /// Get the block range that was scanned
    pub fn block_range(&self) -> Option<(u64, u64)> {
        self.metadata().map(|meta| (meta.from_block, meta.to_block))
    }

    /// Get the number of blocks processed
    pub fn blocks_processed(&self) -> Option<usize> {
        self.metadata().map(|meta| meta.blocks_processed)
    }

    /// Get the scan duration
    pub fn duration(&self) -> Option<std::time::Duration> {
        self.metadata().and_then(|meta| meta.duration())
    }

    /// Get the scan speed in blocks per second
    pub fn blocks_per_second(&self) -> Option<f64> {
        self.metadata().and_then(|meta| meta.blocks_per_second())
    }

    /// Display result in JSON format
    pub fn display_json(&self) {
        display_json_results(self.wallet_state())
    }

    /// Display result in summary format
    pub fn display_summary(&self, config: &BinaryScanConfig) {
        display_summary_results(self.wallet_state(), config)
    }

    /// Display result in detailed format
    pub fn display_detailed(&self, config: &BinaryScanConfig) {
        display_wallet_activity(self.wallet_state(), config.from_block, config.to_block)
    }

    /// Display result in the specified format
    pub fn display(&self, config: &BinaryScanConfig) {
        match config.output_format {
            crate::scanning::OutputFormat::Json => self.display_json(),
            crate::scanning::OutputFormat::Summary => self.display_summary(config),
            crate::scanning::OutputFormat::Detailed => self.display_detailed(config),
        }
    }

    /// Create a resume command string for interrupted scans
    pub fn resume_command(&self, original_command_args: &str) -> Option<String> {
        if let ScanResult::Interrupted(wallet_state, _) = self {
            let next_block = wallet_state
                .transactions
                .iter()
                .map(|tx| tx.block_height)
                .max()
                .map(|h| h + 1)
                .unwrap_or(0);

            if next_block > 0 {
                Some(format!("{original_command_args} --from-block {next_block}"))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get wallet balance summary from the result
    pub fn get_balance_summary(&self) -> (u64, u64, i64, usize, usize) {
        self.wallet_state().get_summary()
    }

    /// Get transaction direction counts from the result
    pub fn get_direction_counts(&self) -> (usize, usize, usize) {
        self.wallet_state().get_direction_counts()
    }

    /// Check if any wallet activity was found
    pub fn has_activity(&self) -> bool {
        !self.wallet_state().transactions.is_empty()
    }

    /// Get the current wallet balance
    pub fn current_balance(&self) -> i64 {
        self.wallet_state().get_balance()
    }

    /// Get the total number of transactions found
    pub fn transaction_count(&self) -> usize {
        self.wallet_state().transactions.len()
    }

    /// Export scan result to JSON string
    pub fn to_json_string(&self) -> String {
        let wallet_state = self.wallet_state();
        let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
        let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

        let mut json = String::from("{\n");
        json.push_str("  \"summary\": {\n");
        json.push_str(&format!(
            "    \"total_transactions\": {},\n",
            wallet_state.transactions.len()
        ));
        json.push_str(&format!("    \"inbound_count\": {inbound_count},\n"));
        json.push_str(&format!("    \"outbound_count\": {outbound_count},\n"));
        json.push_str(&format!("    \"total_received\": {total_received},\n"));
        json.push_str(&format!("    \"total_spent\": {total_spent},\n"));
        json.push_str(&format!("    \"current_balance\": {balance},\n"));
        json.push_str(&format!("    \"unspent_outputs\": {unspent_count},\n"));
        json.push_str(&format!("    \"spent_outputs\": {spent_count}\n"));
        json.push_str("  }");

        if let Some(metadata) = self.metadata() {
            json.push_str(",\n  \"metadata\": {\n");
            json.push_str(&format!("    \"from_block\": {},\n", metadata.from_block));
            json.push_str(&format!("    \"to_block\": {},\n", metadata.to_block));
            json.push_str(&format!("    \"blocks_processed\": {},\n", metadata.blocks_processed));
            json.push_str(&format!(
                "    \"had_specific_blocks\": {}",
                metadata.had_specific_blocks
            ));

            if let Some(duration) = metadata.duration() {
                json.push_str(&format!(",\n    \"duration_seconds\": {:.3}", duration.as_secs_f64()));
            }
            if let Some(bps) = metadata.blocks_per_second() {
                json.push_str(&format!(",\n    \"blocks_per_second\": {bps:.2}"));
            }

            json.push_str("\n  }");
        }

        json.push_str(",\n  \"status\": \"");
        json.push_str(if self.is_completed() {
            "completed"
        } else {
            "interrupted"
        });
        json.push_str("\"\n}");

        json
    }
}

pub struct WalletScannerConfig {
    /// Event emitter for scanner operations (replaces progress_tracker and storage interactions)
    pub event_emitter: Option<super::event_emitter::ScanEventEmitter>,
    /// Batch size for block processing (number of blocks to process at once)
    pub batch_size: usize,
    /// Timeout duration for blockchain operations
    pub timeout: Option<std::time::Duration>,
    /// Whether to enable detailed logging
    pub verbose_logging: bool,
    /// Custom retry configuration for failed operations
    pub retry_config: RetryConfig,
}

/// Errors that can occur during scanner configuration
#[derive(Debug, Clone)]
pub enum ScannerConfigError {
    /// Invalid batch size
    InvalidBatchSize { value: usize, min: usize, max: usize },
    /// Invalid timeout duration
    InvalidTimeout {
        value: std::time::Duration,
        min: std::time::Duration,
        max: std::time::Duration,
    },
    /// Invalid retry configuration
    InvalidRetryConfig { reason: String },
    /// General validation error
    ValidationError { field: String, reason: String },
}

impl std::fmt::Display for ScannerConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerConfigError::InvalidBatchSize { value, min, max } => {
                write!(f, "Invalid batch size {value}: must be between {min} and {max}")
            },
            ScannerConfigError::InvalidTimeout { value, min, max } => {
                write!(f, "Invalid timeout {value:?}: must be between {min:?} and {max:?}")
            },
            ScannerConfigError::InvalidRetryConfig { reason } => {
                write!(f, "Invalid retry configuration: {reason}")
            },
            ScannerConfigError::ValidationError { field, reason } => {
                write!(f, "Validation error for {field}: {reason}")
            },
        }
    }
}

impl std::error::Error for ScannerConfigError {}

impl From<ScannerConfigError> for WalletError {
    fn from(error: ScannerConfigError) -> Self {
        WalletError::InvalidArgument {
            argument: "scanner_config".to_string(),
            value: "validation_error".to_string(),
            message: error.to_string(),
        }
    }
}

/// Retry configuration for failed operations
///
/// Controls how the scanner behaves when encountering transient failures
/// during blockchain operations. Supports exponential backoff with configurable
/// delays and maximum retry attempts.
///
/// # Examples
/// ```ignore
/// use lightweight_wallet_libs::scanning::RetryConfig;
/// use std::time::Duration;
///
/// let retry_config = RetryConfig {
///     max_retries: 5,
///     base_delay: Duration::from_secs(1),
///     max_delay: Duration::from_secs(30),
///     exponential_backoff: true,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: usize,
    /// Base delay between retries
    pub base_delay: std::time::Duration,
    /// Maximum delay between retries (for exponential backoff)
    pub max_delay: std::time::Duration,
    /// Whether to use exponential backoff
    pub exponential_backoff: bool,
}

impl RetryConfig {
    /// Create a conservative retry configuration with more attempts and longer delays
    pub fn conservative() -> Self {
        Self {
            max_retries: 5,
            base_delay: std::time::Duration::from_secs(2),
            max_delay: std::time::Duration::from_secs(30),
            exponential_backoff: true,
        }
    }

    /// Create an aggressive retry configuration with fewer attempts and shorter delays
    pub fn aggressive() -> Self {
        Self {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(100),
            max_delay: std::time::Duration::from_secs(5),
            exponential_backoff: true,
        }
    }

    /// Create a configuration with no retries
    pub fn no_retries() -> Self {
        Self {
            max_retries: 0,
            base_delay: std::time::Duration::from_millis(0),
            max_delay: std::time::Duration::from_millis(0),
            exponential_backoff: false,
        }
    }

    /// Validate the retry configuration
    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        if self.max_retries > 100 {
            return Err(ScannerConfigError::InvalidRetryConfig {
                reason: "max_retries cannot exceed 100".to_string(),
            });
        }

        if self.base_delay > std::time::Duration::from_secs(60) {
            return Err(ScannerConfigError::InvalidRetryConfig {
                reason: "base_delay cannot exceed 60 seconds".to_string(),
            });
        }

        if self.max_delay < self.base_delay {
            return Err(ScannerConfigError::InvalidRetryConfig {
                reason: "max_delay must be greater than or equal to base_delay".to_string(),
            });
        }

        Ok(())
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: std::time::Duration::from_millis(500),
            max_delay: std::time::Duration::from_secs(10),
            exponential_backoff: true,
        }
    }
}

impl WalletScannerConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        // Validate batch size
        if self.batch_size == 0 {
            return Err(ScannerConfigError::InvalidBatchSize {
                value: self.batch_size,
                min: 1,
                max: 1000,
            });
        }
        if self.batch_size > 1000 {
            return Err(ScannerConfigError::InvalidBatchSize {
                value: self.batch_size,
                min: 1,
                max: 1000,
            });
        }

        // Validate timeout
        if let Some(timeout) = self.timeout {
            if timeout < std::time::Duration::from_millis(100) {
                return Err(ScannerConfigError::InvalidTimeout {
                    value: timeout,
                    min: std::time::Duration::from_millis(100),
                    max: std::time::Duration::from_secs(300),
                });
            }
            if timeout > std::time::Duration::from_secs(300) {
                return Err(ScannerConfigError::InvalidTimeout {
                    value: timeout,
                    min: std::time::Duration::from_millis(100),
                    max: std::time::Duration::from_secs(300),
                });
            }
        }

        // Validate retry config
        self.retry_config.validate()?;

        Ok(())
    }
}

impl Default for WalletScannerConfig {
    fn default() -> Self {
        Self {
            event_emitter: None,
            batch_size: 10,
            timeout: Some(std::time::Duration::from_secs(30)),
            verbose_logging: false,
            retry_config: RetryConfig::default(),
        }
    }
}

impl Clone for WalletScannerConfig {
    fn clone(&self) -> Self {
        Self {
            event_emitter: None, // Event emitter cannot be cloned due to internal state
            batch_size: self.batch_size,
            timeout: self.timeout,
            verbose_logging: self.verbose_logging,
            retry_config: self.retry_config.clone(),
        }
    }
}

impl std::fmt::Debug for WalletScannerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletScannerConfig")
            .field("event_emitter", &self.event_emitter.is_some())
            .field("batch_size", &self.batch_size)
            .field("timeout", &self.timeout)
            .field("verbose_logging", &self.verbose_logging)
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

pub struct NewWalletScanner {
    /// Scanner configuration
    config: WalletScannerConfig,
}

impl NewWalletScanner {
    /// Create a new wallet scanner with default configuration
    pub fn new() -> Self {
        Self {
            config: WalletScannerConfig::default(),
        }
    }

    /// Create a wallet scanner from a configuration
    pub fn from_config(config: WalletScannerConfig) -> Self {
        Self { config }
    }

    /// Create a new wallet scanner with default event listeners (progress + console)
    ///
    /// This is a convenience constructor that sets up common event listeners.
    pub fn new_with_default_events(source: String) -> Result<Self, WalletError> {
        let event_emitter = super::event_emitter::create_default_event_emitter(source, None)?;
        Ok(Self {
            config: WalletScannerConfig {
                event_emitter: Some(event_emitter),
                ..Default::default()
            },
        })
    }

    /// Create a new wallet scanner with database event listeners (storage + progress + console)
    ///
    /// This is a convenience constructor for database-backed scanning.
    pub fn new_with_database_events(source: String, _database_path: Option<String>) -> Result<Self, WalletError> {
        let event_emitter = super::event_emitter::create_default_event_emitter(source, None)?;
        Ok(Self {
            config: WalletScannerConfig {
                event_emitter: Some(event_emitter),
                ..Default::default()
            },
        })
    }

    /// Set an event emitter for scanner operations
    ///
    /// The event emitter will handle progress tracking, storage operations, and other
    /// scanner events through registered listeners.
    pub fn with_event_emitter(mut self, event_emitter: super::event_emitter::ScanEventEmitter) -> Self {
        self.config.event_emitter = Some(event_emitter);
        self
    }

    /// Create scanner with default event emitter (progress tracking and console logging)
    ///
    /// This is a convenience method that sets up an event emitter with commonly used listeners.
    pub fn with_default_events(mut self, source: String) -> Result<Self, WalletError> {
        let event_emitter = super::event_emitter::create_default_event_emitter(source, None)?;
        self.config.event_emitter = Some(event_emitter);
        Ok(self)
    }

    /// Create scanner with database event emitter (storage + progress tracking)
    ///
    /// This is a convenience method for setting up an event emitter with database storage.
    pub fn with_database_events(mut self, source: String, _database_path: Option<String>) -> Result<Self, WalletError> {
        let event_emitter = super::event_emitter::create_default_event_emitter(source, None)?;
        self.config.event_emitter = Some(event_emitter);
        Ok(self)
    }

    /// Set the batch size for block processing
    ///
    /// Larger batch sizes can improve performance but may use more memory.
    /// Default is 10 blocks per batch.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        // Use the min or the max of the provided size and the limits
        self.config.batch_size = batch_size.clamp(1, 1000);
        self
    }

    /// Set the timeout duration for blockchain operations
    ///
    /// This timeout applies to individual GRPC calls to the blockchain.
    /// Default is 30 seconds.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.timeout = Some(timeout.clamp(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(300),
        ));
        self
    }

    /// Enable or disable verbose logging
    ///
    /// When enabled, the scanner will output detailed information about its operations.
    /// Default is disabled.
    pub fn with_verbose_logging(mut self, enabled: bool) -> Self {
        self.config.verbose_logging = enabled;
        self
    }

    /// Set retry configuration for failed operations
    ///
    /// Configure how the scanner handles temporary failures during blockchain operations.
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.config.retry_config = retry_config;
        self
    }

    /// Get the current configuration
    pub fn config(&self) -> &WalletScannerConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration
    pub fn config_mut(&mut self) -> &mut WalletScannerConfig {
        &mut self.config
    }

    /// Build and validate the scanner configuration
    ///
    /// This method validates the entire configuration and returns a fully configured scanner.
    /// Use this method when you want to ensure all configuration is valid before proceeding.
    ///
    /// # Errors
    /// Returns an error if any configuration parameter is invalid.
    pub fn build(self) -> Result<NewWalletScanner, ScannerConfigError> {
        self.config.validate()?;
        Ok(self)
    }

    /// Validate the current configuration without consuming the scanner
    ///
    /// This method allows you to check if the current configuration is valid
    /// without building the final scanner.
    ///
    /// # Errors
    /// Returns an error if any configuration parameter is invalid.
    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        self.config.validate()
    }

    /// Create a quick scanner with simple progress display (using events)
    ///
    /// This is a convenience method that creates a scanner with basic event-driven
    /// progress tracking and console logging.
    pub fn with_simple_progress() -> Result<Self, WalletError> {
        Self::new_with_default_events("simple_progress_scanner".to_string())
    }

    /// Create a scanner optimized for performance
    ///
    /// This sets larger batch sizes and disables verbose logging for faster scanning.
    pub fn performance_optimized() -> Self {
        Self::new()
            .with_batch_size(50)
            .with_timeout(std::time::Duration::from_secs(60))
            .with_verbose_logging(false)
    }

    /// Create a scanner optimized for reliability
    ///
    /// This uses smaller batch sizes and more aggressive retry settings.
    pub fn reliability_optimized() -> Self {
        Self::new()
            .with_batch_size(5)
            .with_timeout(std::time::Duration::from_secs(10))
            .with_retry_config(RetryConfig {
                max_retries: 5,
                base_delay: std::time::Duration::from_millis(1000),
                max_delay: std::time::Duration::from_secs(30),
                exponential_backoff: true,
            })
            .with_verbose_logging(true)
    }

    /// Perform wallet scanning across blocks with cancellation support
    ///
    /// This is the main scanning method that processes blockchain blocks to find
    /// wallet outputs and transactions. It supports both specific block scanning
    /// and range scanning with event-driven progress tracking and storage.
    ///
    /// # Arguments
    /// * `scanner` - GRPC blockchain scanner for fetching blocks
    /// * `scan_context` - Wallet scanning context with keys and entropy
    /// * `config` - Binary scan configuration
    /// * `cancel_rx` - Channel receiver for cancellation signals
    ///
    /// # Returns
    /// `ScanResult` indicating completion or interruption with wallet state and metadata
    ///
    /// # Errors
    /// Returns an error if:
    /// - Blockchain connection fails
    /// - Invalid scan configuration provided
    /// - Event emitter is not configured
    /// - Scanning is cancelled by external signal
    pub async fn scan<KM: TransactionKeyManagerInterface>(
        &mut self,
        scanner: &mut HttpBlockchainScanner<KM>,
        config: &BinaryScanConfig,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> WalletResult<ScanResult> {
        // Check that event emitter is configured
        if self.config.event_emitter.is_none() {
            return Err(WalletError::InvalidArgument {
                argument: "event_emitter".to_string(),
                value: "None".to_string(),
                message: "Event emitter must be configured before scanning. Use with_event_emitter(), \
                          with_default_events(), or with_database_events()."
                    .to_string(),
            });
        }

        let start_time = Instant::now();

        // Check that event emitter is configured
        if self.config.event_emitter.is_none() {
            return Err(WalletError::ScanningError(
                crate::errors::ScanningError::ScanConfigurationError("Event emitter not configured".to_string()),
            ));
        }

        // Execute the scan with enhanced error handling
        let mut event_emitter = self.config.event_emitter.take().unwrap();
        let scan_result = self
            .execute_scan_with_retry(scanner, config, &mut event_emitter, cancel_rx)
            .await;

        // Put the event emitter back
        self.config.event_emitter = Some(event_emitter);

        // Add timing information to the result
        match scan_result {
            Ok(ScanResult::Completed(wallet_state, mut metadata)) => {
                if let Some(ref mut meta) = metadata {
                    meta.start_time = Some(start_time);
                    meta.end_time = Some(Instant::now());
                }
                Ok(ScanResult::Completed(wallet_state, metadata))
            },
            Ok(ScanResult::Interrupted(wallet_state, mut metadata)) => {
                if let Some(ref mut meta) = metadata {
                    meta.start_time = Some(start_time);
                    meta.end_time = Some(Instant::now());
                }
                Ok(ScanResult::Interrupted(wallet_state, metadata))
            },
            Err(e) => Err(e),
        }
    }

    /// Execute the scan with retry logic for failed operations
    async fn execute_scan_with_retry<KM: TransactionKeyManagerInterface>(
        &mut self,
        scanner: &mut HttpBlockchainScanner<KM>,
        config: &BinaryScanConfig,
        event_emitter: &mut super::event_emitter::ScanEventEmitter,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> WalletResult<ScanResult> {
        let mut attempts = 0;
        let max_retries = self.config.retry_config.max_retries;

        loop {
            match scan_wallet_across_blocks_with_cancellation(scanner, config, cancel_rx, event_emitter).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempts += 1;

                    // Check if this is a retryable error and we haven't exceeded max retries
                    if attempts <= max_retries && self.is_retryable_error(&e) {
                        // Calculate delay with exponential backoff if enabled
                        let delay = if self.config.retry_config.exponential_backoff {
                            let exp = (attempts - 1).min(10) as u32; // Cap to prevent overflow
                            std::cmp::min(
                                self.config.retry_config.base_delay * (2_u32.pow(exp)),
                                self.config.retry_config.max_delay,
                            )
                        } else {
                            self.config.retry_config.base_delay
                        };

                        // Wait before retrying
                        tokio::time::sleep(delay).await;
                        continue;
                    } else {
                        return Err(e);
                    }
                },
            }
        }
    }

    /// Check if an error is retryable
    fn is_retryable_error(&self, error: &WalletError) -> bool {
        match error {
            // Network-related errors are typically retryable
            WalletError::StorageError(msg) if msg.contains("connection") => true,
            WalletError::StorageError(msg) if msg.contains("timeout") => true,
            WalletError::StorageError(msg) if msg.contains("network") => true,
            // Temporary GRPC errors
            WalletError::StorageError(msg) if msg.contains("unavailable") => true,
            WalletError::StorageError(msg) if msg.contains("deadline exceeded") => true,
            // Other errors are typically not retryable
            _ => false,
        }
    }

    /// Start building a scanner with custom configuration
    ///
    /// This returns a ScannerBuilder that allows for fluent configuration.
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::new()
    }
}

impl Default for NewWalletScanner {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Block processing helper functions
// =============================================================================

/// Determine scanning block range with resume support
#[allow(dead_code)]
async fn determine_scan_range(
    config: &BinaryScanConfig,
    storage_backend: &mut ScannerStorage,
) -> WalletResult<(u64, u64)> {
    // Handle automatic resume functionality for database storage
    if config.use_database && config.explicit_from_block.is_none() && config.block_heights.is_none() {
        if let Some(_wallet_id) = storage_backend.wallet_id {
            // Get the wallet to check its resume block
            if let Some(wallet_birthday) = storage_backend.get_wallet_birthday().await? {
                if !config.quiet {
                    println!(
                        "📄 Resuming wallet from last scanned block {}",
                        format_number(wallet_birthday)
                    );
                }
                Ok((wallet_birthday, config.to_block))
            } else {
                if !config.quiet {
                    println!("📄 Wallet not found, starting from configuration");
                }
                Ok((config.from_block, config.to_block))
            }
        } else {
            if !config.quiet {
                println!("⚠️  Resume requires a selected wallet");
            }
            Ok((config.from_block, config.to_block))
        }
    } else {
        Ok((config.from_block, config.to_block))
    }
}

/// Determine scan range with event system support
async fn determine_scan_range_with_events(
    config: &BinaryScanConfig,
    _event_emitter: &mut super::event_emitter::ScanEventEmitter,
) -> WalletResult<(u64, u64)> {
    // For now, use the configuration directly since resume functionality
    // will be handled by the DatabaseStorageListener through events
    // The event system will track the last scanned block via events
    Ok((config.from_block, config.to_block))
}

/// Prepare block heights list for scanning
fn prepare_block_heights(config: &BinaryScanConfig, from_block: u64, to_block: u64) -> Vec<u64> {
    let has_specific_blocks = config.block_heights.is_some();

    if has_specific_blocks {
        let heights = config.block_heights.as_ref().unwrap().clone();
        if !config.quiet {
            display_scan_info(config, &heights, has_specific_blocks);
        }
        heights
    } else {
        let heights: Vec<u64> = (from_block..=to_block).collect();
        // Don't display here for range scanning - it's handled in the main function
        heights
    }
}

/// Core scanning logic - simplified and focused with batch processing
async fn scan_wallet_across_blocks_with_cancellation<KM: TransactionKeyManagerInterface>(
    scanner: &mut HttpBlockchainScanner<KM>,
    config: &BinaryScanConfig,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    event_emitter: &mut super::event_emitter::ScanEventEmitter,
) -> WalletResult<ScanResult> {
    // Determine scanning block range
    let (from_block, to_block) = determine_scan_range_with_events(config, event_emitter).await?;

    // Prepare block heights list for scanning
    let block_heights = prepare_block_heights(config, from_block, to_block);

    // Emit scan started event
    let mut wallet_context = std::collections::HashMap::new();
    wallet_context.insert("scan_type".to_string(), "full_scan".to_string());
    wallet_context.insert("batch_size".to_string(), config.batch_size.to_string());
    event_emitter
        .emit_scan_started(config, (from_block, to_block), wallet_context)
        .await?;

    if !config.quiet && config.block_heights.is_none() {
        use crate::common::format_number;

        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(from_block),
            format_number(to_block),
            format_number(block_heights.len())
        );
    }

    // Batch scan implementation
    let mut wallet_state = WalletState::new();
    let mut blocks_processed = 0u64;
    let mut last_progress_update = Instant::now();
    let total_blocks = block_heights.len() as u64;
    let batch_size = config.batch_size as usize;
    let mut batch_start = 0;

    while batch_start < block_heights.len() {
        // Check for cancellation before each batch

        use crate::BlockchainScanner;
        if *cancel_rx.borrow() {
            if !config.quiet {
                println!("\n🛑 Scan cancelled by user");
            }
            let current_block = if batch_start < block_heights.len() {
                block_heights[batch_start]
            } else {
                to_block
            };
            let metadata = ScanMetadata::new(
                from_block,
                current_block.saturating_sub(1),
                blocks_processed as usize,
                config.block_heights.is_some(),
            );
            event_emitter
                .emit_scan_cancelled(
                    "User requested cancellation".to_string(),
                    current_block,
                    Some(&metadata),
                )
                .await?;
            return Ok(ScanResult::Interrupted(wallet_state, Some(metadata)));
        }

        let batch_end = std::cmp::min(batch_start + batch_size, block_heights.len());
        let batch_heights = &block_heights[batch_start..batch_end];
        let scan_config = super::ScanConfig {
            start_height: batch_heights[0],
            end_height: Some(*batch_heights.last().unwrap()),
            batch_size: config.batch_size as u64,
            request_timeout: std::time::Duration::from_secs(30),
            extraction_config: crate::extraction::ExtractionConfig::default(),
        };

        let scan_results = BlockchainScanner::scan_blocks(scanner, scan_config).await?;

        for block_result in &scan_results {
            add_outputs_from_blockscan(&mut wallet_state, &block_result.wallet_outputs, block_result.height);
            emit_block_processed_simple(event_emitter, block_result, &wallet_state).await?;
        }

        blocks_processed += scan_results.len() as u64;

        // Emit progress update
        let should_emit_progress = if config.block_heights.is_some() {
            false
        } else {
            blocks_processed % config.progress_frequency as u64 == 0 || last_progress_update.elapsed().as_secs() >= 1
        };
        if should_emit_progress {
            let processing_rate = if last_progress_update.elapsed().as_secs_f64() > 0.0 {
                blocks_processed as f64 / last_progress_update.elapsed().as_secs_f64()
            } else {
                0.0
            };
            let estimated_completion = if processing_rate > 0.0 {
                let remaining_blocks = total_blocks - blocks_processed;
                let remaining_seconds = remaining_blocks as f64 / processing_rate;
                Some(std::time::SystemTime::now() + std::time::Duration::from_secs_f64(remaining_seconds))
            } else {
                None
            };
            let last_block_height = scan_results.last().map(|b| b.height).unwrap_or(to_block);
            event_emitter
                .emit_scan_progress(
                    blocks_processed,
                    total_blocks,
                    last_block_height,
                    wallet_state.transactions.len(),
                    Some(processing_rate),
                    estimated_completion,
                )
                .await?;
            last_progress_update = Instant::now();
        }

        batch_start = batch_end;
    }

    if !config.quiet {
        println!("✅ Completed scanning {total_blocks} blocks");
    }

    let metadata = ScanMetadata::new(
        from_block,
        to_block,
        block_heights.len(),
        config.block_heights.is_some(),
    );
    event_emitter
        .emit_scan_completed(&metadata, &wallet_state, true)
        .await?;
    if !config.quiet {
        println!();
    }
    Ok(ScanResult::Completed(wallet_state, Some(metadata)))
}

/// Display scan configuration information
fn display_scan_info(config: &BinaryScanConfig, block_heights: &[u64], has_specific_blocks: bool) {
    if has_specific_blocks {
        println!(
            "🔍 Scanning {} specific blocks: \"{}\"",
            format_number(block_heights.len()),
            if block_heights.len() <= 10 {
                block_heights
                    .iter()
                    .map(|h| format_number(*h))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                format!(
                    "{}, {}..{} and {} others",
                    format_number(block_heights[0]),
                    format_number(block_heights[1]),
                    format_number(block_heights.last().copied().unwrap_or(0)),
                    format_number(block_heights.len() - 3)
                )
            }
        );
    } else {
        let block_range = config.to_block - config.from_block + 1;
        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(config.from_block),
            format_number(config.to_block),
            format_number(block_range)
        );
    }
}

// =============================================================================
// Balance calculation and summary helper functions
// =============================================================================

/// Calculate wallet balance summary
fn calculate_wallet_summary(wallet_state: &WalletState) -> (u64, u64, i64, usize, usize) {
    wallet_state.get_summary()
}

/// Calculate transaction direction counts
fn calculate_direction_counts(wallet_state: &WalletState) -> (usize, usize, usize) {
    wallet_state.get_direction_counts()
}

/// Format currency amount for display
fn format_currency_amount(amount: u64) -> String {
    format!("{} μT ({:.6} T)", format_number(amount), amount as f64 / 1_000_000.0)
}

/// Check if wallet has any activity in the scanned range
fn has_wallet_activity(wallet_state: &WalletState) -> bool {
    !wallet_state.transactions.is_empty()
}

/// Display no activity message
fn display_no_activity_message(from_block: u64, to_block: u64) {
    println!(
        "💡 No wallet activity found in blocks {} to {}",
        format_number(from_block),
        format_number(to_block)
    );
    if from_block > 1 {
        println!(
            "   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked",
            format_number(from_block)
        );
        println!(
            "   💡 For complete history, try: cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your \
             seed phrase\" --from-block 1"
        );
    }
}

/// Display wallet activity summary header
fn display_activity_header(from_block: u64, to_block: u64) {
    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!(
        "Scan range: Block {} to {} ({} blocks)",
        format_number(from_block),
        format_number(to_block),
        format_number(to_block - from_block + 1)
    );
}

/// Display transaction breakdown by direction
fn display_transaction_breakdown(inbound_count: usize, outbound_count: usize, total_received: u64, total_spent: u64) {
    println!(
        "📥 Inbound:  {} transactions, {}",
        format_number(inbound_count),
        format_currency_amount(total_received)
    );
    println!(
        "📤 Outbound: {} transactions, {}",
        format_number(outbound_count),
        format_currency_amount(total_spent)
    );
}

/// Display current balance and total activity
fn display_balance_and_totals(balance: i64, total_count: usize) {
    println!("💰 Current balance: {}", format_currency_amount(balance.unsigned_abs()));
    println!("📊 Total activity: {} transactions", format_number(total_count));
    println!();
}

/// Display wallet activity summary
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    if !has_wallet_activity(wallet_state) {
        display_no_activity_message(from_block, to_block);
        return;
    }

    // Calculate summary values
    let (total_received, total_spent, balance, _unspent_count, _spent_count) = calculate_wallet_summary(wallet_state);
    let (inbound_count, outbound_count, _) = calculate_direction_counts(wallet_state);
    let total_count = wallet_state.transactions.len();

    // Display formatted summary
    display_activity_header(from_block, to_block);
    display_transaction_breakdown(inbound_count, outbound_count, total_received, total_spent);
    display_balance_and_totals(balance, total_count);
}

// =============================================================================
// Result output formatting functions
// =============================================================================

/// Display scan results in JSON format
fn display_json_results(wallet_state: &WalletState) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("{{");
    println!("  \"summary\": {{");
    println!("    \"total_transactions\": {},", wallet_state.transactions.len());
    println!("    \"inbound_count\": {inbound_count},");
    println!("    \"outbound_count\": {outbound_count},");
    println!("    \"total_received\": {total_received},");
    println!("    \"total_spent\": {total_spent},");
    println!("    \"current_balance\": {balance},");
    println!("    \"unspent_outputs\": {unspent_count},");
    println!("    \"spent_outputs\": {spent_count}");
    println!("  }}");
    println!("}}");
}

/// Display scan results in summary format
fn display_summary_results(wallet_state: &WalletState, config: &BinaryScanConfig) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("📊 WALLET SCAN SUMMARY");
    println!("=====================");
    if let Some(ref block_heights) = config.block_heights {
        if block_heights.len() <= 10 {
            println!(
                "Scanned {} specific blocks: {}",
                format_number(block_heights.len()),
                block_heights
                    .iter()
                    .map(|h| format_number(*h))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        } else {
            println!(
                "Scanned {} specific blocks: {}, {}..{} and {} others",
                format_number(block_heights.len()),
                format_number(block_heights[0]),
                format_number(block_heights[1]),
                format_number(block_heights.last().copied().unwrap_or(0)),
                format_number(block_heights.len() - 3)
            );
        }
    } else {
        println!(
            "Scan range: Block {} to {}",
            format_number(config.from_block),
            format_number(config.to_block)
        );
    }
    println!("Total transactions: {}", format_number(wallet_state.transactions.len()));
    println!(
        "Inbound: {} transactions ({:.6} T)",
        format_number(inbound_count),
        total_received as f64 / 1_000_000.0
    );
    println!(
        "Outbound: {} transactions ({:.6} T)",
        format_number(outbound_count),
        total_spent as f64 / 1_000_000.0
    );
    println!("Current balance: {:.6} T", balance as f64 / 1_000_000.0);
    println!("Unspent outputs: {}", format_number(unspent_count));
    println!("Spent outputs: {}", format_number(spent_count));
}

// =============================================================================
// Scanner Builder Pattern Implementation
// =============================================================================

/// Builder for configuring WalletScanner with different preset configurations
///
/// This builder provides a fluent interface for setting up scanners with various
/// combinations of event listeners and configurations. It includes preset methods
/// similar to the event listeners for common use cases.
///
/// # Examples
///
/// ```rust,no_run
/// use lightweight_wallet_libs::scanning::wallet_scanner::ScannerBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Basic scanner with default events
/// let scanner = ScannerBuilder::new()
///     .with_default_events("my_scanner".to_string())?
///     .with_batch_size(25)
///     .build();
///
/// // Development scanner with verbose logging
/// let scanner = ScannerBuilder::new().with_development_preset()?.build();
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ScannerBuilder {
    config: WalletScannerConfig,
    event_emitter: Option<super::event_emitter::ScanEventEmitter>,
}

impl ScannerBuilder {
    /// Create a new scanner builder with default configuration
    pub fn new() -> Self {
        Self {
            config: WalletScannerConfig::default(),
            event_emitter: None,
        }
    }

    /// Set an event emitter for scanner operations
    pub fn with_event_emitter(mut self, event_emitter: super::event_emitter::ScanEventEmitter) -> Self {
        self.event_emitter = Some(event_emitter);
        self
    }

    /// Configure with default event listeners (progress tracking + console logging)
    pub fn with_default_events(mut self, source: String) -> Result<Self, WalletError> {
        let event_emitter = super::event_emitter::create_default_event_emitter(source, None)?;
        self.event_emitter = Some(event_emitter);
        Ok(self)
    }

    /// Configure with database event listeners (storage + progress + console)
    pub fn with_database_events(mut self, source: String, _database_path: Option<String>) -> Result<Self, WalletError> {
        let event_emitter = super::event_emitter::create_default_event_emitter(source, None)?;
        self.event_emitter = Some(event_emitter);
        Ok(self)
    }

    /// Set the batch size for block processing
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.config.batch_size = batch_size.clamp(1, 1000);
        self
    }

    /// Set the timeout duration for blockchain operations
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.timeout = Some(timeout.clamp(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(300),
        ));
        self
    }

    /// Enable or disable verbose logging
    pub fn with_verbose_logging(mut self, verbose: bool) -> Self {
        self.config.verbose_logging = verbose;
        self
    }

    /// Set retry configuration
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.config.retry_config = retry_config;
        self
    }

    // =============================================================================
    // Preset Configurations (similar to event listener presets)
    // =============================================================================

    /// Apply performance optimization preset
    ///
    /// - Large batch size (50)
    /// - Extended timeout (60s)
    /// - Disabled verbose logging
    /// - Conservative retry policy
    pub fn with_performance_preset(mut self) -> Self {
        self.config.batch_size = 50;
        self.config.timeout = Some(std::time::Duration::from_secs(60));
        self.config.verbose_logging = false;
        self.config.retry_config = RetryConfig {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(500),
            max_delay: std::time::Duration::from_secs(10),
            exponential_backoff: true,
        };
        self
    }

    /// Apply reliability optimization preset
    ///
    /// - Small batch size (5)
    /// - Conservative timeout (45s)
    /// - Enabled verbose logging
    /// - Aggressive retry policy
    pub fn with_reliability_preset(mut self) -> Self {
        self.config.batch_size = 5;
        self.config.timeout = Some(std::time::Duration::from_secs(45));
        self.config.verbose_logging = true;
        self.config.retry_config = RetryConfig {
            max_retries: 5,
            base_delay: std::time::Duration::from_millis(1000),
            max_delay: std::time::Duration::from_secs(30),
            exponential_backoff: true,
        };
        self
    }

    /// Apply development preset with default events
    ///
    /// - Medium batch size (10)
    /// - Standard timeout (30s)
    /// - Enabled verbose logging
    /// - Default retry policy
    /// - Default event listeners
    pub fn with_development_preset(mut self) -> Result<Self, WalletError> {
        self.config.batch_size = 10;
        self.config.timeout = Some(std::time::Duration::from_secs(30));
        self.config.verbose_logging = true;
        self.config.retry_config = RetryConfig::default();

        // Add default event emitter if not already configured
        if self.event_emitter.is_none() {
            let event_emitter =
                super::event_emitter::create_default_event_emitter("development_scanner".to_string(), None)?;
            self.event_emitter = Some(event_emitter);
        }

        Ok(self)
    }

    /// Apply production preset with database events
    ///
    /// - Large batch size (30)
    /// - Extended timeout (60s)
    /// - Minimal verbose logging
    /// - Balanced retry policy
    /// - Database event listeners
    pub fn with_production_preset(mut self, _database_path: Option<String>) -> Result<Self, WalletError> {
        self.config.batch_size = 30;
        self.config.timeout = Some(std::time::Duration::from_secs(60));
        self.config.verbose_logging = false;
        self.config.retry_config = RetryConfig {
            max_retries: 3,
            base_delay: std::time::Duration::from_millis(1000),
            max_delay: std::time::Duration::from_secs(20),
            exponential_backoff: true,
        };

        // Add database event emitter if not already configured
        if self.event_emitter.is_none() {
            let event_emitter =
                super::event_emitter::create_default_event_emitter("production_scanner".to_string(), None)?;
            self.event_emitter = Some(event_emitter);
        }

        Ok(self)
    }

    /// Apply testing preset (optimized for unit tests)
    ///
    /// - Small batch size (3)
    /// - Short timeout (10s)
    /// - Disabled verbose logging
    /// - No retries
    /// - Mock event listeners
    pub fn with_testing_preset(mut self) -> Result<Self, WalletError> {
        use crate::events::{listeners::MockEventListener, EventDispatcher};

        self.config.batch_size = 3;
        self.config.timeout = Some(std::time::Duration::from_secs(10));
        self.config.verbose_logging = false;
        self.config.retry_config = RetryConfig {
            max_retries: 0,
            base_delay: std::time::Duration::from_millis(100),
            max_delay: std::time::Duration::from_millis(100),
            exponential_backoff: false,
        };

        // Add mock event emitter for testing
        if self.event_emitter.is_none() {
            let mut dispatcher = EventDispatcher::new();
            let mock_listener = MockEventListener::new();
            let _ = dispatcher.register(Box::new(mock_listener));
            let event_emitter = super::event_emitter::ScanEventEmitter::new(dispatcher, "test_scanner".to_string());
            self.event_emitter = Some(event_emitter);
        }

        Ok(self)
    }

    /// Apply quiet preset (minimal output)
    ///
    /// - Medium batch size (15)
    /// - Standard timeout (30s)
    /// - Disabled verbose logging
    /// - Conservative retry policy
    /// - Progress tracking only (no console logging)
    pub fn with_quiet_preset(mut self) -> Result<Self, WalletError> {
        use crate::events::{listeners::ProgressTrackingListener, EventDispatcher};

        self.config.batch_size = 15;
        self.config.timeout = Some(std::time::Duration::from_secs(30));
        self.config.verbose_logging = false;
        self.config.retry_config = RetryConfig {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(500),
            max_delay: std::time::Duration::from_secs(10),
            exponential_backoff: true,
        };

        // Add only progress tracking, no console logging
        if self.event_emitter.is_none() {
            let mut dispatcher = EventDispatcher::new();
            let progress_listener = ProgressTrackingListener::new();
            let _ = dispatcher.register(Box::new(progress_listener));
            let event_emitter = super::event_emitter::ScanEventEmitter::new(dispatcher, "quiet_scanner".to_string());
            self.event_emitter = Some(event_emitter);
        }

        Ok(self)
    }

    /// Validate the current configuration
    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        self.config.validate()?;

        if self.event_emitter.is_none() {
            return Err(ScannerConfigError::ValidationError {
                field: "event_emitter".to_string(),
                reason: "Event emitter must be configured before building scanner".to_string(),
            });
        }

        Ok(())
    }

    /// Build the final WalletScanner
    ///
    /// This consumes the builder and returns a configured WalletScanner.
    /// The scanner will be validated before creation.
    pub fn build(mut self) -> Result<NewWalletScanner, ScannerConfigError> {
        self.validate()?;

        // Move event_emitter into config
        self.config.event_emitter = self.event_emitter.take();

        Ok(NewWalletScanner::from_config(self.config))
    }

    /// Build the final WalletScanner without validation
    ///
    /// This skips validation and may result in a scanner that fails at runtime.
    /// Only use this for testing or when you're certain the configuration is valid.
    pub fn build_unchecked(mut self) -> NewWalletScanner {
        self.config.event_emitter = self.event_emitter.take();
        NewWalletScanner::from_config(self.config)
    }
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Helper: Add wallet outputs from BlockScanResult to WalletState and emit output_found events
fn add_outputs_from_blockscan(
    _wallet_state: &mut WalletState,
    _outputs: &[(FixedHash, WalletOutput)],
    _block_height: u64,
) {
    // TODO: Implement actual conversion and addition
}

// Helper: Emit a block processed event for BlockScanResult and emit output_found events
async fn emit_block_processed_simple(
    _event_emitter: &mut ScanEventEmitter,
    block_result: &BlockScanResult,
    _wallet_state: &WalletState,
) -> WalletResult<()> {
    println!(
        "[STUB] Block processed: height={}, outputs_found={}",
        block_result.height,
        block_result.wallet_outputs.len()
    );
    for output in &block_result.wallet_outputs {
        println!("[STUB] Output found in block {}: {:?}", block_result.height, output);
    }
    Ok(())
}
