//! Wallet libraries for Tari
//!
//! This crate provides wallet functionality for the Tari blockchain,
//! including UTXO management, transaction validation, and key management.

pub mod errors;
mod key_manager_builder;
pub mod scanning;
pub use key_manager_builder::KeyManagerBuilder;

#[allow(dead_code)]
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use errors::*;
pub use scanning::*;
