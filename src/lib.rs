//! Wallet libraries for Tari
//!
//! This crate provides wallet functionality for the Tari blockchain,
//! including UTXO management, transaction validation, and key management.

pub mod common;
// pub mod crypto;
pub mod data_structures;
pub mod errors;
pub mod events;
pub mod extraction;
pub mod hex_utils;
// pub mod key_management;
mod key_manager_builder;
pub mod scanning;
pub use key_manager_builder::KeyManagerBuilder;

#[allow(dead_code)]
pub mod storage;
pub mod utils;
// pub mod validation;
pub mod wallet;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use errors::*;
pub use extraction::*;
pub use hex_utils::*;
// pub use key_management::*;
pub use scanning::*;
pub use storage::*;
// Re-export types from transaction components for easier use
pub mod transaction_components;
// pub use validation::*;
pub use wallet::*;
