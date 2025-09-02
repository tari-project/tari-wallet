//! Configuration structures for wallet scanning operations.
//!
//! This module defines the configuration options and data structures
//! used to control wallet scanning behavior, including scan ranges,
//! output formats, and wallet context information.
//!
//! This module is part of the scanner.rs binary refactoring effort.



/// Output format options for scanner results
///
/// Controls how scanning results are displayed to the user.
///
/// # Examples
/// ```ignore
/// use lightweight_wallet_libs::scanning::OutputFormat;
/// use std::str::FromStr;
///
/// let format = OutputFormat::from_str("json").unwrap();
/// assert!(matches!(format, OutputFormat::Json));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    /// Detailed output with full transaction information
    Detailed,
    /// Summary output with condensed information
    Summary,
    /// JSON output for programmatic consumption
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "detailed" => Ok(OutputFormat::Detailed),
            "summary" => Ok(OutputFormat::Summary),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!(
                "Invalid output format: {s}. Valid options: detailed, summary, json"
            )),
        }
    }
}

/// Configuration for scanner binary operations
///
/// This structure contains all the configuration options needed by the scanner binary
/// to control scanning behavior, output format, storage, and progress reporting.
///
/// # Examples
/// ```ignore
/// use lightweight_wallet_libs::scanning::{BinaryScanConfig, OutputFormat};
///
/// let config = BinaryScanConfig {
///     from_block: 1000,
///     to_block: 2000,
///     block_heights: None,
///     progress_frequency: 10,
///     quiet: false,
///     output_format: OutputFormat::Detailed,
///     batch_size: 100,
///     database_path: Some("wallet.db".to_string()),
///     wallet_name: Some("main-wallet".to_string()),
///     explicit_from_block: None,
///     use_database: true,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct BinaryScanConfig {
    /// Starting block height for scanning
    pub from_block: u64,
    /// Ending block height for scanning
    pub to_block: u64,
    /// Specific block heights to scan (overrides range when specified)
    pub block_heights: Option<Vec<u64>>,
    /// Frequency of progress updates (every N blocks)
    pub progress_frequency: usize,
    /// Whether to suppress detailed output
    pub quiet: bool,
    /// Output format for scan results
    pub output_format: OutputFormat,
    /// Number of blocks to process in each batch
    pub batch_size: usize,
    /// Path to the database file (None for memory-only)
    pub database_path: Option<String>,
    /// Name of the wallet to use/create
    pub wallet_name: Option<String>,
    /// Explicitly set from_block (for resume functionality)
    pub explicit_from_block: Option<u64>,
    /// Whether to use database storage
    pub use_database: bool,
}

impl BinaryScanConfig {
    /// Create a new binary scan configuration with default values
    ///
    /// # Examples
    /// ```ignore
    /// use lightweight_wallet_libs::scanning::{BinaryScanConfig, OutputFormat};
    ///
    /// let config = BinaryScanConfig::new(1000, 2000);
    /// assert_eq!(config.from_block, 1000);
    /// assert_eq!(config.to_block, 2000);
    /// assert_eq!(config.batch_size, 100);
    /// ```
    pub fn new(from_block: u64, to_block: u64) -> Self {
        Self {
            from_block,
            to_block,
            block_heights: None,
            progress_frequency: 10,
            quiet: false,
            output_format: OutputFormat::Detailed,
            batch_size: 100,
            database_path: None,
            wallet_name: None,
            explicit_from_block: None,
            use_database: false,
        }
    }

    /// Enable database storage with the specified path
    pub fn with_database(mut self, database_path: String) -> Self {
        self.database_path = Some(database_path);
        self.use_database = true;
        self
    }

    /// Set the wallet name to use
    pub fn with_wallet_name(mut self, wallet_name: String) -> Self {
        self.wallet_name = Some(wallet_name);
        self
    }

    /// Set the output format
    pub fn with_output_format(mut self, output_format: OutputFormat) -> Self {
        self.output_format = output_format;
        self
    }

    /// Enable quiet mode (suppress detailed output)
    pub fn with_quiet_mode(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Set specific block heights to scan instead of a range
    pub fn with_specific_blocks(mut self, block_heights: Vec<u64>) -> Self {
        self.block_heights = Some(block_heights);
        self
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_output_format_from_str_valid() {
        assert_eq!(OutputFormat::from_str("detailed").unwrap(), OutputFormat::Detailed);
        assert_eq!(OutputFormat::from_str("summary").unwrap(), OutputFormat::Summary);
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);

        // Case insensitive
        assert_eq!(OutputFormat::from_str("DETAILED").unwrap(), OutputFormat::Detailed);
        assert_eq!(OutputFormat::from_str("Summary").unwrap(), OutputFormat::Summary);
        assert_eq!(OutputFormat::from_str("JSON").unwrap(), OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        let result = OutputFormat::from_str("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid output format: invalid"));

        let result = OutputFormat::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_scan_config_new() {
        let config = BinaryScanConfig::new(100, 200);

        assert_eq!(config.from_block, 100);
        assert_eq!(config.to_block, 200);
        assert_eq!(config.block_heights, None);
        assert_eq!(config.progress_frequency, 10);
        assert!(!config.quiet);
        assert_eq!(config.output_format, OutputFormat::Detailed);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.database_path, None);
        assert_eq!(config.wallet_name, None);
        assert_eq!(config.explicit_from_block, None);
        assert!(!config.use_database);
    }

    #[test]
    fn test_binary_scan_config_with_database() {
        let config = BinaryScanConfig::new(100, 200).with_database("test.db".to_string());

        assert_eq!(config.database_path, Some("test.db".to_string()));
        assert!(config.use_database);
    }

    #[test]
    fn test_binary_scan_config_with_wallet_name() {
        let config = BinaryScanConfig::new(100, 200).with_wallet_name("test-wallet".to_string());

        assert_eq!(config.wallet_name, Some("test-wallet".to_string()));
    }

    #[test]
    fn test_binary_scan_config_with_output_format() {
        let config = BinaryScanConfig::new(100, 200).with_output_format(OutputFormat::Json);

        assert_eq!(config.output_format, OutputFormat::Json);
    }

    #[test]
    fn test_binary_scan_config_with_quiet_mode() {
        let config = BinaryScanConfig::new(100, 200).with_quiet_mode(true);

        assert!(config.quiet);
    }

    #[test]
    fn test_binary_scan_config_with_specific_blocks() {
        let blocks = vec![100, 150, 200];
        let config = BinaryScanConfig::new(100, 200).with_specific_blocks(blocks.clone());

        assert_eq!(config.block_heights, Some(blocks));
    }

    #[test]
    fn test_binary_scan_config_builder_chain() {
        let config = BinaryScanConfig::new(100, 200)
            .with_database("test.db".to_string())
            .with_wallet_name("test-wallet".to_string())
            .with_output_format(OutputFormat::Json)
            .with_quiet_mode(true)
            .with_specific_blocks(vec![150]);

        assert_eq!(config.from_block, 100);
        assert_eq!(config.to_block, 200);
        assert_eq!(config.database_path, Some("test.db".to_string()));
        assert!(config.use_database);
        assert_eq!(config.wallet_name, Some("test-wallet".to_string()));
        assert_eq!(config.output_format, OutputFormat::Json);
        assert!(config.quiet);
        assert_eq!(config.block_heights, Some(vec![150]));
    }

}
