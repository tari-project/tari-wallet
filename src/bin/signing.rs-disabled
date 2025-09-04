//! Tari Message Signing CLI Tool
//!
//! A command-line utility for signing and verifying messages using Tari-compatible
//! Schnorr signatures with domain separation.

#![cfg(not(target_arch = "wasm32"))]

use std::fs;

use clap::{Parser, Subcommand};
#[cfg(feature = "storage")]
use lightweight_wallet_libs::{
    key_management::{derive_view_and_spend_keys_from_entropy, mnemonic_to_bytes, seed_phrase::CipherSeed},
    storage::{SqliteStorage, WalletStorage},
};
use rand::rngs::OsRng;
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_utilities::hex::Hex;

#[derive(Parser)]
#[command(name = "signing")]
#[command(about = "Tari-compatible message signing and verification tool")]
#[command(
    long_about = "A CLI tool for signing and verifying messages using Schnorr signatures with Tari wallet-compatible \
                  domain separation"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    #[command(about = "Generate a new Ed25519 keypair")]
    Generate {
        /// Output file for the secret key (hex format)
        #[arg(long, short)]
        secret_key_file: Option<String>,

        /// Output file for the public key (hex format)
        #[arg(long, short)]
        public_key_file: Option<String>,

        /// Print keys to stdout instead of files
        #[arg(long)]
        stdout: bool,
    },

    /// Sign a message
    #[command(about = "Sign a message using a secret key")]
    Sign {
        /// Secret key in hex format
        #[arg(long, short, group = "key_input")]
        secret_key: Option<String>,

        /// File containing secret key in hex format
        #[arg(long, group = "key_input")]
        secret_key_file: Option<String>,

        /// Wallet name in database (requires storage feature)
        #[cfg(feature = "storage")]
        #[arg(long, group = "key_input")]
        wallet_name: Option<String>,

        /// Database file path (default: wallet.db)
        #[cfg(feature = "storage")]
        #[arg(long, default_value = "wallet.db")]
        database_path: String,

        /// Message to sign
        #[arg(long, short, group = "message_input")]
        message: Option<String>,

        /// File containing message to sign
        #[arg(long, group = "message_input")]
        message_file: Option<String>,

        /// Output signature to file
        #[arg(long)]
        output_file: Option<String>,

        /// Output format: 'compact' (signature:nonce) or 'json' (structured)
        #[arg(long, default_value = "compact")]
        format: String,
    },

    /// Verify a message signature
    #[command(about = "Verify a message signature using a public key")]
    Verify {
        /// Public key in hex format
        #[arg(long, short, group = "key_input")]
        public_key: Option<String>,

        /// File containing public key in hex format
        #[arg(long, group = "key_input")]
        public_key_file: Option<String>,

        /// Message that was signed
        #[arg(long, short, group = "message_input")]
        message: Option<String>,

        /// File containing message that was signed
        #[arg(long, group = "message_input")]
        message_file: Option<String>,

        /// Signature in hex format
        #[arg(long, short, requires = "nonce")]
        signature: Option<String>,

        /// Public nonce in hex format
        #[arg(long, short, requires = "signature")]
        nonce: Option<String>,

        /// File containing signature in compact format (signature:nonce)
        #[arg(long, conflicts_with_all = ["signature", "nonce"])]
        signature_file: Option<String>,

        /// Verbose output
        #[arg(long, short)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            secret_key_file,
            public_key_file,
            stdout,
        } => {
            let secret_key = RistrettoSecretKey::random(&mut OsRng);
            let public_key = RistrettoPublicKey::from_secret_key(&secret_key);

            let secret_hex = secret_key.to_hex();
            let public_hex = public_key.to_hex();

            if stdout {
                println!("Secret Key: {secret_hex}");
                println!("Public Key: {public_hex}");
            } else {
                if let Some(sk_file) = secret_key_file {
                    fs::write(&sk_file, &secret_hex)?;
                    println!("Secret key written to: {sk_file}");
                } else {
                    println!("Secret Key: {secret_hex}");
                }

                if let Some(pk_file) = public_key_file {
                    fs::write(&pk_file, &public_hex)?;
                    println!("Public key written to: {pk_file}");
                } else {
                    println!("Public Key: {public_hex}");
                }
            }
        },

        Commands::Sign {
            secret_key,
            secret_key_file,
            #[cfg(feature = "storage")]
            wallet_name,
            #[cfg(feature = "storage")]
            database_path,
            message,
            message_file,
            output_file,
            format,
        } => {
            todo!("implement on key manager");
            // Get secret key from various sources
           //  let secret_key = get_secret_key_for_signing(
           //      secret_key,
           //      secret_key_file,
           //      #[cfg(feature = "storage")]
           //      wallet_name,
           //      #[cfg(feature = "storage")]
           //      database_path,
           //  )
           //  .await?;
           //
           //  // Get message
           //  let message_text = match (message, message_file) {
           //      (Some(msg), None) => msg,
           //      (None, Some(file)) => fs::read_to_string(&file)?,
           //      _ => return Err("Must provide either --message or --message-file".into()),
           //  };
           //
           //  // Sign the message
           // // let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, &message_text)?;
           //
           //  let output = match format.as_str() {
           //      "compact" => format!("{signature_hex}:{nonce_hex}"),
           //      "json" => serde_json::to_string_pretty(&serde_json::json!({
           //          "signature": signature_hex,
           //          "nonce": nonce_hex,
           //          "message": message_text
           //      }))?,
           //      _ => return Err("Invalid format. Use 'compact' or 'json'".into()),
           //  };
           //
           //  if let Some(file) = output_file {
           //      fs::write(&file, &output)?;
           //      println!("Signature written to: {file}");
           //  } else {
           //      println!("{output}");
           //  }
        },

        Commands::Verify {
            public_key,
            public_key_file,
            message,
            message_file,
            signature,
            nonce,
            signature_file,
            verbose,
        } => {
            todo!("implement on key manager");
            // Get public key
            let public_key_hex = match (public_key, public_key_file) {
                (Some(key), None) => key,
                (None, Some(file)) => fs::read_to_string(&file)?.trim().to_string(),
                _ => return Err("Must provide either --public-key or --public-key-file".into()),
            };

            let public_key =
                RistrettoPublicKey::from_hex(&public_key_hex).map_err(|e| format!("Invalid public key hex: {e}"))?;

            // Get message
            let message_text = match (message, message_file) {
                (Some(msg), None) => msg,
                (None, Some(file)) => fs::read_to_string(&file)?,
                _ => return Err("Must provide either --message or --message-file".into()),
            };

            // Get signature components
            let (sig_hex, nonce_hex) = match (signature, nonce, signature_file) {
                (Some(sig), Some(n), None) => (sig, n),
                (None, None, Some(file)) => {
                    let content = fs::read_to_string(&file)?.trim().to_string();

                    // Try to parse as compact format first
                    if let Some((sig, n)) = content.split_once(':') {
                        (sig.to_string(), n.to_string())
                    } else {
                        // Try to parse as JSON
                        let parsed: serde_json::Value = serde_json::from_str(&content)?;
                        let sig = parsed["signature"]
                            .as_str()
                            .ok_or("Missing 'signature' field in JSON")?
                            .trim();
                        let n = parsed["nonce"].as_str().ok_or("Missing 'nonce' field in JSON")?.trim();
                        (sig.to_string(), n.to_string())
                    }
                },
                _ => return Err("Must provide either (--signature and --nonce) or --signature-file".into()),
            };

            // Verify the signature
           // let is_valid = verify_message_from_hex(&public_key, &message_text, &sig_hex, &nonce_hex)?;
let is_valid = true;
            if verbose {
                println!("Message: \"{message_text}\"");
                println!("Public Key: {public_key_hex}");
                println!("Signature: {sig_hex}");
                println!("Nonce: {nonce_hex}");
                println!("Valid: {is_valid}");
            } else {
                println!("{}", if is_valid { "VALID" } else { "INVALID" });
            }

            if !is_valid {
                std::process::exit(1);
            }
        },
    }

    Ok(())
}

/// Get secret key from various sources (file, hex string, or database wallet)
async fn get_secret_key_for_signing(
    secret_key: Option<String>,
    secret_key_file: Option<String>,
    #[cfg(feature = "storage")] wallet_name: Option<String>,
    #[cfg(feature = "storage")] database_path: String,
) -> Result<RistrettoSecretKey, Box<dyn std::error::Error>> {
    // Try different sources in order of preference
    if let Some(key) = secret_key {
        // Direct hex string
        return Ok(RistrettoSecretKey::from_hex(&key).map_err(|e| format!("Invalid secret key hex: {e}"))?);
    }

    if let Some(file) = secret_key_file {
        // Read from file
        let key_hex = fs::read_to_string(&file)?.trim().to_string();
        return Ok(RistrettoSecretKey::from_hex(&key_hex).map_err(|e| format!("Invalid secret key hex in file: {e}"))?);
    }

    #[cfg(feature = "storage")]
    if let Some(wallet_name) = wallet_name {
        // Get from database
        return get_secret_key_from_database(&wallet_name, &database_path).await;
    }

    Err("Must provide either --secret-key, --secret-key-file, or --wallet-name".into())
}

#[cfg(feature = "storage")]
async fn get_secret_key_from_database(
    wallet_name: &str,
    database_path: &str,
) -> Result<RistrettoSecretKey, Box<dyn std::error::Error>> {
    // Connect to database
    let storage = SqliteStorage::new(database_path)
        .await
        .map_err(|e| format!("Failed to open database: {e}"))?;

    // Initialize schema
    storage
        .initialize()
        .await
        .map_err(|e| format!("Failed to initialize database: {e}"))?;

    // Get wallet by name
    let wallet = storage
        .get_wallet_by_name(wallet_name)
        .await
        .map_err(|e| format!("Failed to query wallet: {e}"))?
        .ok_or_else(|| format!("Wallet '{wallet_name}' not found in database"))?;

    // Extract seed phrase
    let seed_phrase = wallet
        .seed_phrase
        .ok_or_else(|| format!("Wallet '{wallet_name}' has no seed phrase stored"))?;

    // Convert seed phrase to CipherSeed directly
    let cipher_seed = seed_phrase_to_cipher_seed(&seed_phrase, None)
        .map_err(|e| format!("Failed to convert seed phrase to CipherSeed: {e}"))?;

    // Derive the communication node identity secret key (used for message signing)
    // This is the exact same key that Tari wallet uses for message signing
    // Convert the entropy slice to the required array type
    let entropy_array: &[u8; 16] = cipher_seed
        .entropy()
        .try_into()
        .map_err(|_| "Invalid entropy length: expected 16 bytes")?;
    let (_, comms_key) = derive_view_and_spend_keys_from_entropy(entropy_array)
        .map_err(|e| format!("Failed to derive communication key: {e}"))?;

    println!("Using communication key from wallet '{wallet_name}' in database (Tari message signing key)");
    Ok(comms_key)
}

#[cfg(feature = "storage")]
fn seed_phrase_to_cipher_seed(
    seed_phrase: &str,
    passphrase: Option<&str>,
) -> Result<CipherSeed, lightweight_wallet_libs::errors::KeyManagementError> {
    // Convert mnemonic to encrypted bytes
    let encrypted_bytes = mnemonic_to_bytes(seed_phrase)?;

    // Decrypt the CipherSeed
    CipherSeed::from_enciphered_bytes(&encrypted_bytes, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        // This test verifies the keypair generation functionality
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);

        assert_eq!(secret_key.to_hex().len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(public_key.to_hex().len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sign_and_verify_workflow() -> Result<(), Box<dyn std::error::Error>> {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Test message for CLI";

        // Test signing
        let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message)?;

        // Test verification
        let is_valid = verify_message_from_hex(&public_key, message, &signature_hex, &nonce_hex)?;

        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_compact_format_parsing() {
        let signature = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let nonce = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let compact = format!("{signature}:{nonce}");

        let (parsed_sig, parsed_nonce) = compact.split_once(':').unwrap();
        assert_eq!(parsed_sig, signature);
        assert_eq!(parsed_nonce, nonce);
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("This binary is not for wasm32 targets.");
    std::process::exit(1);
}
