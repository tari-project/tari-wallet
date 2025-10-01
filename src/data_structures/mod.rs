//! Core data structures for wallets
//!
//! This module contains the essential data structures needed for
//! wallet operations, including UTXOs, transactions,
//! and cryptographic primitives.

pub mod block;
pub mod incompleted_scanned_output;

pub use block::BlockSummary;
