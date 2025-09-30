//! Wallet libraries for Tari
//!
//! This crate provides wallet functionality for the Tari blockchain,
//! including UTXO management, transaction validation, and key management.

pub mod common;
pub mod data_structures;
pub mod errors;
pub mod events;
pub mod extraction;
pub mod hex_utils;
pub mod scanning;

#[allow(dead_code)]
pub mod storage;
pub mod utils;
pub mod wallet;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use errors::*;
pub use extraction::*;
pub use hex_utils::*;
pub use scanning::*;
pub use storage::*;
pub use wallet::*;
