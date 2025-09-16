#![cfg(all(feature = "storage", feature = "http"))]

use std::str::FromStr;

use clap::{ArgGroup, Args, Parser, Subcommand};
use lightweight_wallet_libs::{
    common::format_number,
    DatabaseEncryptionFields,
    SqliteStorage,
    StoredWallet,
    WalletResult,
    WalletStorage,
};
use tari_common_types::{
    seeds::{cipher_seed::CipherSeed, mnemonic::Mnemonic, seed_words::SeedWords},
    types::{CompressedPublicKey, PrivateKey},
    wallet_types::{ProvidedKeysWallet, WalletType},
};
use tari_utilities::{hex::Hex, SafePassword};

#[derive(Debug, Parser)]
#[command(version, author, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create a new wallet with seed phrase or keys
    New(NewArgs),
    /// Clear all data from database
    ClearDatabase(ClearDatabaseArgs),
    /// List all wallets stored in database
    ListWallets(ListWalletsArgs),
    /// Scan wallet using HTTP scanner
    Scan(ScanArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("auth").required(true)))]
pub struct NewArgs {
    /// Wallet name
    #[arg(long)]
    name: String,

    /// Database file path
    #[arg(long, default_value = "./wallet.db")]
    database: String,

    /// Passphrase for CipherSeed encryption/decryption
    #[arg(long)]
    passphrase: String,

    /// Provide a seed phrase. Mutually exclusive with providing keys.
    #[arg(long, group = "auth", conflicts_with_all = &["view_key", "spend_key"])]
    seed_phrase: Option<String>,

    /// Private view key. Must be used with --spend-key.
    #[arg(long, group = "auth", requires = "spend_key")]
    view_key: Option<String>,

    /// Public spend key. Must be used with --view-key.
    #[arg(long, requires = "view_key")]
    spend_key: Option<String>,
}
#[derive(Debug, Args)]
pub struct ClearDatabaseArgs {
    /// Database file path
    #[arg(long, default_value = "./wallet.db")]
    database: String,

    /// Do not prompt for confirmation
    #[arg(long, default_value = "false")]
    no_prompt: bool,
}

#[derive(Debug, Args)]
pub struct ListWalletsArgs {
    /// Database file path
    #[arg(long, default_value = "./wallet.db")]
    database: String,

    /// Passphrase for CipherSeed encryption/decryption
    #[arg(long)]
    passphrase: String,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Wallet name
    #[arg(long)]
    name: String,

    /// Database file path
    #[arg(long, default_value = "./wallet.db")]
    database: String,

    /// Passphrase for CipherSeed encryption/decryption
    #[arg(long)]
    passphrase: String,

    /// Base URL for the Tari base node HTTP endpoint
    #[arg(
        short,
        long,
        default_value = "http://127.0.0.1:9005",
        help = "Base URL for Tari base node HTTP"
    )]
    base_url: String,
}

#[tokio::main]
async fn main() -> WalletResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::New(args) => handle_new_wallet(args).await?,
        Commands::ClearDatabase(args) => handle_clear_database(args).await?,
        Commands::ListWallets(args) => handle_list_wallets(args).await?,
        Commands::Scan(args) => handle_scan(args).await?,
    }

    Ok(())
}

async fn handle_new_wallet(args: NewArgs) -> WalletResult<()> {
    let wallet_name = args.name;
    let password = as_safe_password(&args.passphrase);
    let storage = SqliteStorage::new(&args.database, password.clone()).await?;
    storage.initialize().await?;

    let existing_wallet = storage.get_wallet_by_name(&wallet_name).await?;
    if existing_wallet.is_some() {
        println!("❌  Error: wallet {wallet_name} was not created, since it already exists");
        return Ok(());
    }

    let (wallet_type, master_key) = match (args.seed_phrase, args.view_key, args.spend_key) {
        (Some(seed_phrase), _, _) => {
            let seed_words = SeedWords::from_str(&seed_phrase).map_err(|e| e.to_string())?;
            (WalletType::DerivedKeys, CipherSeed::from_mnemonic(&seed_words, None)?)
        },
        (_, Some(view_key), Some(public_spend_key)) => {
            let view_key = PrivateKey::from_hex(&view_key).map_err(|e| format!("Invalid format of view key: {e}"))?;
            let public_spend_key = CompressedPublicKey::from_hex(&public_spend_key)
                .map_err(|e| format!("Invalid format of public spend key: {e}"))?;
            let provided_keys = ProvidedKeysWallet {
                view_key,
                public_spend_key,
                private_spend_key: None,
                private_comms_key: None,
                birthday: None,
            };
            (WalletType::ProvidedKeys(provided_keys), CipherSeed::new())
        },
        _ => panic!("Impossible"),
    };

    let encryption_fields = DatabaseEncryptionFields::new(&password)?;
    let wallet = StoredWallet::new(wallet_name.clone(), wallet_type, encryption_fields, master_key);
    storage.save_wallet(&wallet).await?;

    println!("✅ Wallet {wallet_name} added successfully");

    Ok(())
}

async fn handle_clear_database(args: ClearDatabaseArgs) -> WalletResult<()> {
    let database_path = args.database;
    // Confirm action
    println!("⚠️  WARNING: This will permanently delete ALL data from: {database_path}");
    let confirmation = if !args.no_prompt {
        print!("Are you sure you want to continue? (yes/no): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {e}"))?;
        input.trim().to_lowercase()
    } else {
        "yes".to_string()
    };

    if confirmation != "yes" && confirmation != "y" {
        println!("Operation cancelled");
        return Ok(());
    }

    // Create storage connection
    let storage = SqliteStorage::new(&database_path, "".into()).await?;
    storage.initialize().await?;

    // Clear all data
    storage.clear_all_transactions().await?;

    println!("✅ Database cleared successfully: {database_path}");

    Ok(())
}

async fn handle_list_wallets(args: ListWalletsArgs) -> WalletResult<()> {
    let database_path = args.database;
    let password = as_safe_password(&args.passphrase);
    let storage = SqliteStorage::new(&database_path, password).await?;
    storage.initialize().await?;

    let wallets = storage.list_wallets().await?;
    if wallets.is_empty() {
        println!("📂 No wallets found in database: {database_path}");
    } else {
        println!("📂 Available wallets in database: {database_path}");
        for wallet in &wallets {
            let wallet_type = match wallet.wallet_type {
                WalletType::DerivedKeys => "full",
                WalletType::ProvidedKeys(_) => "view-only",
                _ => "unknown",
            };
            println!(
                "  • {} - {} (birthday: block {})",
                wallet.name,
                wallet_type,
                format_number(wallet.birthday_block)
            );
        }
    }

    Ok(())
}

async fn handle_scan(args: ScanArgs) -> WalletResult<()> {
    Ok(())
}

fn as_safe_password(passphrase: &str) -> SafePassword {
    SafePassword::from_str(&passphrase).unwrap() // cannot fail
}
