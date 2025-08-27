//! Complete wallet workflow integration tests
//!
//! Tests the full lifecycle of wallet operations from creation to address generation
//! to transaction handling, covering the complete user journey.

use lightweight_wallet_libs::{
    data_structures::{address::TariAddressFeatures, Network},
    key_management::*,
    wallet::*,
};
use zeroize::Zeroize;

#[cfg(feature = "storage")]

/// Test complete wallet creation and key derivation workflow
#[tokio::test]
async fn test_complete_wallet_creation_workflow() {
    // Phase 1: Wallet Creation from Seed Phrase

    use lightweight_wallet_libs::data_structures::TariAddress;
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    // Validate seed phrase format and structure
    validate_seed_phrase(&seed_phrase).expect("Generated seed phrase is invalid");
    assert_eq!(seed_phrase.split_whitespace().count(), 24);

    // Create wallet from seed phrase
    let wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet from seed phrase");

    // Verify wallet creation
    assert!(wallet.birthday() > 0);
    assert_eq!(wallet.current_key_index(), 0);
    assert_eq!(wallet.network(), ""); // Default empty network
    assert!(wallet.label().is_none());

    // Verify seed phrase export works
    let exported_seed = wallet.export_seed_phrase().expect("Failed to export seed phrase");
    assert_eq!(exported_seed, seed_phrase);

    // Phase 2: Key Derivation and Address Generation
    let mut wallet = wallet;
    wallet.set_network("mainnet".to_string());
    wallet.set_label(Some("Test Integration Wallet".to_string()));

    // Generate dual address with interactive and one-sided features
    let dual_address = wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate dual address");

    // Verify dual address properties
    assert!(matches!(dual_address, TariAddress::Dual(_)));
    assert!(dual_address.public_view_key().is_some());
    assert_eq!(dual_address.network(), Network::MainNet);
    assert!(dual_address.features().contains(TariAddressFeatures::INTERACTIVE_ONLY));
    assert!(dual_address.features().contains(TariAddressFeatures::ONE_SIDED_ONLY));

    // Generate single address for comparison
    let single_address = wallet
        .get_single_address(TariAddressFeatures::create_interactive_only())
        .expect("Failed to generate single address");

    // Verify single address properties
    assert!(matches!(single_address, TariAddress::Single(_)));
    assert!(single_address.public_view_key().is_none());
    assert_eq!(single_address.network(), Network::MainNet);
    assert!(single_address
        .features()
        .contains(TariAddressFeatures::INTERACTIVE_ONLY));

    // Verify deterministic generation
    let dual_address_2 = wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate second dual address");
    assert_eq!(dual_address.to_hex(), dual_address_2.to_hex());

    // Phase 3: Address with Payment ID
    let payment_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let address_with_payment = wallet
        .get_dual_address(TariAddressFeatures::create_interactive_only(), Some(payment_id.clone()))
        .expect("Failed to generate address with payment ID");

    // Verify payment ID is included
    assert!(address_with_payment
        .features()
        .contains(TariAddressFeatures::PAYMENT_ID));

    // Phase 4: Wallet Reconstruction from Seed
    let reconstructed_wallet =
        Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to reconstruct wallet from seed phrase");

    // Verify reconstruction produces same master key
    assert_eq!(wallet.master_key_bytes(), reconstructed_wallet.master_key_bytes());

    // Configure reconstructed wallet with same settings
    let mut reconstructed_wallet = reconstructed_wallet;
    reconstructed_wallet.set_network("mainnet".to_string());
    reconstructed_wallet.set_label(Some("Test Integration Wallet".to_string()));

    // Verify same addresses are generated
    let reconstructed_dual = reconstructed_wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate dual address from reconstructed wallet");

    assert_eq!(dual_address.to_hex(), reconstructed_dual.to_hex());

    println!("✓ Complete wallet workflow test passed");
}

/// Test wallet creation with different entropy sources
#[tokio::test]
async fn test_wallet_creation_entropy_sources() {
    // Test 1: Wallet from random generation
    let wallet_random = Wallet::generate_new(None);
    assert!(wallet_random.birthday() > 0);
    assert!(wallet_random.export_seed_phrase().is_err()); // No seed phrase available

    // Test 2: Wallet from generated seed phrase
    let wallet_with_phrase =
        Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet with seed phrase");

    assert!(wallet_with_phrase.birthday() > 0);
    assert!(wallet_with_phrase.export_seed_phrase().is_ok());

    // Test 3: Wallet from manual seed phrase
    let manual_seed = generate_seed_phrase().expect("Failed to generate manual seed");
    let wallet_manual =
        Wallet::new_from_seed_phrase(&manual_seed, None).expect("Failed to create wallet from manual seed");

    assert!(wallet_manual.birthday() > 0);
    assert_eq!(wallet_manual.export_seed_phrase().unwrap(), manual_seed);

    // Test 4: Wallet with passphrase
    let cipher_seed = CipherSeed::new();
    let encrypted_bytes = cipher_seed
        .encipher(Some("test_passphrase"))
        .expect("Failed to encrypt cipher seed");
    let seed_with_passphrase = bytes_to_mnemonic(&encrypted_bytes).expect("Failed to convert to mnemonic");

    let wallet_with_passphrase = Wallet::new_from_seed_phrase(&seed_with_passphrase, Some("test_passphrase"))
        .expect("Failed to create wallet with passphrase");

    assert!(wallet_with_passphrase.birthday() > 0);
    assert_eq!(
        wallet_with_passphrase.export_seed_phrase().unwrap(),
        seed_with_passphrase
    );

    // Verify all wallets have different master keys
    let keys = [
        wallet_random.master_key_bytes(),
        wallet_with_phrase.master_key_bytes(),
        wallet_manual.master_key_bytes(),
        wallet_with_passphrase.master_key_bytes(),
    ];

    for i in 0..keys.len() {
        for j in i + 1..keys.len() {
            assert_ne!(keys[i], keys[j], "Wallets {i} and {j} have the same master key");
        }
    }

    println!("✓ Wallet entropy sources test passed");
}

/// Test wallet metadata management workflow
#[tokio::test]
async fn test_wallet_metadata_workflow() {
    let mut wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    // Test metadata operations
    wallet.set_label(Some("Production Wallet".to_string()));
    wallet.set_network("mainnet".to_string());
    wallet.set_current_key_index(100);

    // Test custom properties
    wallet.set_property("version".to_string(), "1.0.0".to_string());
    wallet.set_property("created_by".to_string(), "integration_test".to_string());
    wallet.set_property("environment".to_string(), "production".to_string());

    // Verify metadata
    assert_eq!(wallet.label(), Some(&"Production Wallet".to_string()));
    assert_eq!(wallet.network(), "mainnet");
    assert_eq!(wallet.current_key_index(), 100);
    assert_eq!(wallet.get_property("version"), Some(&"1.0.0".to_string()));
    assert_eq!(wallet.get_property("created_by"), Some(&"integration_test".to_string()));
    assert_eq!(wallet.get_property("environment"), Some(&"production".to_string()));

    // Test property removal
    let removed_version = wallet.remove_property("version");
    assert_eq!(removed_version, Some("1.0.0".to_string()));
    assert_eq!(wallet.get_property("version"), None);

    // Test address generation with metadata
    let address = wallet
        .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
        .expect("Failed to generate address");

    // Verify network is reflected in address
    assert_eq!(address.network(), Network::MainNet);

    println!("✓ Wallet metadata workflow test passed");
}

/// Test wallet key derivation consistency
#[tokio::test]
async fn test_wallet_key_derivation_consistency() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    // Create multiple wallet instances from same seed
    let wallet1 = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet 1");
    let wallet2 = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet 2");

    // Configure both wallets identically
    let mut wallet1 = wallet1;
    let mut wallet2 = wallet2;

    for wallet in [&mut wallet1, &mut wallet2] {
        wallet.set_network("stagenet".to_string());
        wallet.set_current_key_index(42);
    }

    // Test dual address consistency
    let addr1_dual = wallet1
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate dual address from wallet 1");

    let addr2_dual = wallet2
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate dual address from wallet 2");

    assert_eq!(addr1_dual.to_hex(), addr2_dual.to_hex());
    assert_eq!(addr1_dual.network(), addr2_dual.network());
    assert_eq!(addr1_dual.features(), addr2_dual.features());

    // Test single address consistency
    let addr1_single = wallet1
        .get_single_address(TariAddressFeatures::create_one_sided_only())
        .expect("Failed to generate single address from wallet 1");

    let addr2_single = wallet2
        .get_single_address(TariAddressFeatures::create_one_sided_only())
        .expect("Failed to generate single address from wallet 2");

    assert_eq!(addr1_single.to_hex(), addr2_single.to_hex());
    assert_eq!(addr1_single.network(), addr2_single.network());
    assert_eq!(addr1_single.features(), addr2_single.features());

    // Test with payment ID
    let payment_id = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let addr1_payment = wallet1
        .get_dual_address(TariAddressFeatures::create_interactive_only(), Some(payment_id.clone()))
        .expect("Failed to generate payment address from wallet 1");

    let addr2_payment = wallet2
        .get_dual_address(TariAddressFeatures::create_interactive_only(), Some(payment_id.clone()))
        .expect("Failed to generate payment address from wallet 2");

    assert_eq!(addr1_payment.to_hex(), addr2_payment.to_hex());

    println!("✓ Wallet key derivation consistency test passed");
}

#[cfg(feature = "storage")]
/// Test wallet persistence and recovery workflow
#[tokio::test]
async fn test_wallet_storage_workflow() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Failed to create temp directory");
    let _db_path = temp_dir.path().join("test_wallet.db");

    // Create wallet with specific configuration
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");
    let mut original_wallet =
        Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create original wallet");

    original_wallet.set_label(Some("Storage Test Wallet".to_string()));
    original_wallet.set_network("mainnet".to_string());
    original_wallet.set_current_key_index(123);
    original_wallet.set_property("test_key".to_string(), "test_value".to_string());

    // Generate some addresses to verify consistency
    let dual_address = original_wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate dual address");

    let single_address = original_wallet
        .get_single_address(TariAddressFeatures::create_interactive_only())
        .expect("Failed to generate single address");

    // Store wallet data (simulated - in real implementation this would use the storage trait)
    let stored_seed = original_wallet
        .export_seed_phrase()
        .expect("Failed to export seed phrase");
    let stored_birthday = original_wallet.birthday();
    let stored_label = original_wallet.label().cloned();
    let stored_network = original_wallet.network().to_string();
    let stored_key_index = original_wallet.current_key_index();
    let stored_property = original_wallet.get_property("test_key").cloned();

    // Simulate wallet recovery from storage
    let mut recovered_wallet =
        Wallet::new_from_seed_phrase(&stored_seed, None).expect("Failed to recover wallet from seed");

    // Restore metadata
    recovered_wallet.set_birthday(stored_birthday);
    if let Some(label) = stored_label {
        recovered_wallet.set_label(Some(label));
    }
    recovered_wallet.set_network(stored_network);
    recovered_wallet.set_current_key_index(stored_key_index);
    if let Some(property_value) = stored_property {
        recovered_wallet.set_property("test_key".to_string(), property_value);
    }

    // Verify recovered wallet matches original
    assert_eq!(original_wallet.master_key_bytes(), recovered_wallet.master_key_bytes());
    assert_eq!(original_wallet.birthday(), recovered_wallet.birthday());
    assert_eq!(original_wallet.label(), recovered_wallet.label());
    assert_eq!(original_wallet.network(), recovered_wallet.network());
    assert_eq!(
        original_wallet.current_key_index(),
        recovered_wallet.current_key_index()
    );
    assert_eq!(
        original_wallet.get_property("test_key"),
        recovered_wallet.get_property("test_key")
    );

    // Verify addresses are consistent
    let recovered_dual = recovered_wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate dual address from recovered wallet");

    let recovered_single = recovered_wallet
        .get_single_address(TariAddressFeatures::create_interactive_only())
        .expect("Failed to generate single address from recovered wallet");

    assert_eq!(dual_address.to_hex(), recovered_dual.to_hex());
    assert_eq!(single_address.to_hex(), recovered_single.to_hex());

    println!("✓ Wallet storage workflow test passed");
}

/// Test wallet security features and zeroization
#[tokio::test]
async fn test_wallet_security_workflow() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");
    let mut wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet");

    wallet.set_label(Some("Secret Wallet".to_string()));
    wallet.set_network("testnet".to_string());

    // Verify initial state
    let original_master_key = wallet.master_key_bytes();
    let original_birthday = wallet.birthday();
    assert_eq!(wallet.export_seed_phrase().unwrap(), seed_phrase);
    assert_eq!(wallet.label(), Some(&"Secret Wallet".to_string()));

    // Test zeroization
    wallet.zeroize();

    // Verify sensitive data is cleared
    assert_eq!(wallet.master_key_bytes(), [0u8; 32]);
    assert_eq!(wallet.birthday(), 0);
    assert_eq!(wallet.current_key_index(), 0);
    assert!(wallet.export_seed_phrase().is_err());

    // Verify zeroization doesn't affect ability to create new wallet
    let new_wallet =
        Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create new wallet after zeroization");

    assert_eq!(new_wallet.master_key_bytes(), original_master_key);
    assert_eq!(new_wallet.birthday(), original_birthday);

    println!("✓ Wallet security workflow test passed");
}

/// Test address features and network compatibility
#[tokio::test]
async fn test_address_features_workflow() {
    let mut wallet = Wallet::generate_new_with_seed_phrase(None).expect("Failed to generate wallet");

    // Test all supported networks
    let networks = [
        ("mainnet", Network::MainNet),
        ("stagenet", Network::StageNet),
        ("esmeralda", Network::Esmeralda),
        ("localnet", Network::LocalNet),
        ("unknown", Network::Esmeralda), // Default fallback
    ];

    for (network_name, expected_network) in networks {
        wallet.set_network(network_name.to_string());

        // Test interactive only features
        let interactive_dual = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
            .expect("Failed to generate interactive dual address");

        let interactive_single = wallet
            .get_single_address(TariAddressFeatures::create_interactive_only())
            .expect("Failed to generate interactive single address");

        assert_eq!(interactive_dual.network(), expected_network);
        assert_eq!(interactive_single.network(), expected_network);
        assert!(interactive_dual
            .features()
            .contains(TariAddressFeatures::INTERACTIVE_ONLY));
        assert!(interactive_single
            .features()
            .contains(TariAddressFeatures::INTERACTIVE_ONLY));

        // Test one-sided only features
        let onesided_dual = wallet
            .get_dual_address(TariAddressFeatures::create_one_sided_only(), None)
            .expect("Failed to generate one-sided dual address");

        let onesided_single = wallet
            .get_single_address(TariAddressFeatures::create_one_sided_only())
            .expect("Failed to generate one-sided single address");

        assert_eq!(onesided_dual.network(), expected_network);
        assert_eq!(onesided_single.network(), expected_network);
        assert!(onesided_dual.features().contains(TariAddressFeatures::ONE_SIDED_ONLY));
        assert!(onesided_single.features().contains(TariAddressFeatures::ONE_SIDED_ONLY));

        // Test combined features
        let combined_dual = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
            .expect("Failed to generate combined dual address");

        assert_eq!(combined_dual.network(), expected_network);
        assert!(combined_dual.features().contains(TariAddressFeatures::INTERACTIVE_ONLY));
        assert!(combined_dual.features().contains(TariAddressFeatures::ONE_SIDED_ONLY));
    }

    println!("✓ Address features workflow test passed");
}
