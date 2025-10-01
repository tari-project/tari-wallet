//! Block processing functionality for wallet scanning
//!
//! This module provides a `Block` struct that encapsulates all the logic for:
//! - Processing transaction outputs to discover wallet outputs
//! - Processing transaction inputs to detect spending
//! - Multiple decryption methods (regular, one-sided, range proof rewinding)
//! - Coinbase output handling with ownership verification
//! - **Parallel processing for performance optimization**

/// Summary information about a block
#[derive(Debug, Clone)]
pub struct BlockSummary {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: Vec<u8>,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of outputs in the block
    pub output_count: usize,
    /// Number of inputs in the block
    pub input_count: usize,
}

impl std::fmt::Display for BlockSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {} (outputs: {}, inputs: {})",
            self.height, self.output_count, self.input_count
        )
    }
}
