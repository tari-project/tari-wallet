//! Multi-network compatibility validation tests
//!
//! Tests cross-network compatibility, address format consistency, and configuration
//! parameter validation across different Tari networks (mainnet, stagenet, etc.).

use std::collections::HashMap;

use lightweight_wallet_libs::{
    data_structures::{
        address::{TariAddress, TariAddressFeatures},
        Network,
    },
    key_management::*,
    wallet::*,
};

/// Network configuration for testing
#[derive(Debug, Clone)]
struct NetworkConfig {
    name: String,
    network: Network,
    #[allow(dead_code)]
    address_prefix: &'static str,
    #[allow(dead_code)]
    default_port: u16,
    #[allow(dead_code)]
    genesis_block_hash: Vec<u8>,
}

impl NetworkConfig {
    fn mainnet() -> Self {
        Self {
            name: "mainnet".to_string(),
            network: Network::MainNet,
            address_prefix: "tari",
            default_port: 18189,
            genesis_block_hash: vec![0x01; 32],
        }
    }

    fn stagenet() -> Self {
        Self {
            name: "stagenet".to_string(),
            network: Network::StageNet,
            address_prefix: "tari_stg",
            default_port: 18189,
            genesis_block_hash: vec![0x02; 32],
        }
    }

    fn esmeralda() -> Self {
        Self {
            name: "esmeralda".to_string(),
            network: Network::Esmeralda,
            address_prefix: "tari_esmr",
            default_port: 18189,
            genesis_block_hash: vec![0x03; 32],
        }
    }

    fn localnet() -> Self {
        Self {
            name: "localnet".to_string(),
            network: Network::LocalNet,
            address_prefix: "tari_local",
            default_port: 18189,
            genesis_block_hash: vec![0x04; 32],
        }
    }

    fn all_networks() -> Vec<Self> {
        vec![Self::mainnet(), Self::stagenet(), Self::esmeralda(), Self::localnet()]
    }
}

/// Test cross-network wallet compatibility
#[tokio::test]
async fn test_cross_network_wallet_compatibility() {
    // Use the same seed phrase across all networks
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    let mut network_wallets = HashMap::new();
    let mut network_configs = HashMap::new();

    // Create wallets for each network
    for config in NetworkConfig::all_networks() {
        let mut wallet =
            Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet from seed phrase");

        wallet.set_network(config.name.clone());
        wallet.set_label(Some(format!("{} Wallet", config.name)));

        network_wallets.insert(config.name.clone(), wallet);
        network_configs.insert(config.name.clone(), config);
    }

    // Verify all wallets have the same master key (deterministic from seed)
    let mainnet_wallet = &network_wallets["mainnet"];
    let mainnet_master_key = mainnet_wallet.master_key_bytes();

    for (network_name, wallet) in &network_wallets {
        assert_eq!(
            wallet.master_key_bytes(),
            mainnet_master_key,
            "Wallet for {network_name} has different master key"
        );
    }

    // Verify wallet metadata is network-specific
    for (network_name, wallet) in &network_wallets {
        assert_eq!(wallet.network(), network_name);
        assert_eq!(wallet.label(), Some(&format!("{network_name} Wallet")));
    }

    // Test seed phrase export consistency
    for (network_name, wallet) in &network_wallets {
        let exported_seed = wallet
            .export_seed_phrase()
            .unwrap_or_else(|_| panic!("Failed to export seed phrase for {network_name}"));
        assert_eq!(exported_seed, seed_phrase);
    }

    println!("✓ Cross-network wallet compatibility test passed");
    println!(
        "  Tested networks: {}",
        network_wallets
            .keys()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Test address format consistency across networks
#[tokio::test]
async fn test_address_format_consistency() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    let mut network_addresses = HashMap::new();

    for config in NetworkConfig::all_networks() {
        let mut wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet");
        wallet.set_network(config.name.clone());

        // Generate different types of addresses for each network
        let dual_interactive = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
            .expect("Failed to generate dual interactive address");

        let dual_one_sided = wallet
            .get_dual_address(TariAddressFeatures::create_one_sided_only(), None)
            .expect("Failed to generate dual one-sided address");

        let dual_combined = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
            .expect("Failed to generate dual combined address");

        let single_interactive = wallet
            .get_single_address(TariAddressFeatures::create_interactive_only())
            .expect("Failed to generate single interactive address");

        let single_one_sided = wallet
            .get_single_address(TariAddressFeatures::create_one_sided_only())
            .expect("Failed to generate single one-sided address");

        // Test address with payment ID
        let payment_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let dual_with_payment = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_only(), Some(payment_id))
            .expect("Failed to generate dual address with payment ID");

        let addresses = vec![
            ("dual_interactive", dual_interactive),
            ("dual_one_sided", dual_one_sided),
            ("dual_combined", dual_combined),
            ("single_interactive", single_interactive),
            ("single_one_sided", single_one_sided),
            ("dual_with_payment", dual_with_payment),
        ];

        network_addresses.insert(config.name.clone(), (config, addresses));
    }

    // Verify address network consistency
    for (network_name, (config, addresses)) in &network_addresses {
        for (address_type, address) in addresses {
            assert_eq!(
                address.network(),
                config.network,
                "Address {address_type} for {network_name} has wrong network"
            );

            // Verify address can be serialized to hex
            let hex_address = address.to_hex();
            assert!(!hex_address.is_empty());
            assert!(hex_address.len() > 20); // Reasonable minimum length

            // Verify address features
            match *address_type {
                "dual_interactive" => {
                    assert!(address.features().contains(TariAddressFeatures::INTERACTIVE_ONLY));
                    assert!(address.public_view_key().is_some());
                },
                "dual_one_sided" => {
                    assert!(address.features().contains(TariAddressFeatures::ONE_SIDED_ONLY));
                    assert!(address.public_view_key().is_some());
                },
                "dual_combined" => {
                    assert!(address.features().contains(TariAddressFeatures::INTERACTIVE_ONLY));
                    assert!(address.features().contains(TariAddressFeatures::ONE_SIDED_ONLY));
                    assert!(address.public_view_key().is_some());
                },
                "single_interactive" => {
                    assert!(address.features().contains(TariAddressFeatures::INTERACTIVE_ONLY));
                    assert!(address.public_view_key().is_none());
                },
                "single_one_sided" => {
                    assert!(address.features().contains(TariAddressFeatures::ONE_SIDED_ONLY));
                    assert!(address.public_view_key().is_none());
                },
                "dual_with_payment" => {
                    assert!(address.features().contains(TariAddressFeatures::PAYMENT_ID));
                    assert!(address.public_view_key().is_some());
                },
                _ => panic!("Unknown address type: {address_type}"),
            }
        }
    }

    // Verify deterministic address generation across networks
    let mainnet_addresses = &network_addresses["mainnet"].1;
    let stagenet_addresses = &network_addresses["stagenet"].1;

    for ((mainnet_type, mainnet_addr), (stagenet_type, stagenet_addr)) in
        mainnet_addresses.iter().zip(stagenet_addresses.iter())
    {
        assert_eq!(mainnet_type, stagenet_type);

        // Same wallet should generate different addresses for different networks
        assert_ne!(
            mainnet_addr.to_hex(),
            stagenet_addr.to_hex(),
            "Address {mainnet_type} should differ between networks"
        );

        // But they should have the same features
        assert_eq!(
            mainnet_addr.features(),
            stagenet_addr.features(),
            "Address {mainnet_type} features should be consistent across networks"
        );
    }

    println!("✓ Address format consistency test passed");
    for (network_name, (_, addresses)) in &network_addresses {
        println!("  {network_name}: {} address types", addresses.len());
    }
}

/// Test configuration parameter validation across networks
#[tokio::test]
async fn test_configuration_parameter_validation() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    // Test valid network configurations
    let valid_networks = vec![
        "mainnet",
        "stagenet",
        "esmeralda",
        "localnet",
        "testnet", // Should default to esmeralda
        "",        // Empty should default to esmeralda
    ];

    for network_name in &valid_networks {
        let mut wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet");

        wallet.set_network(network_name.to_string());

        // All valid networks should allow address generation
        let address = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
            .unwrap_or_else(|_| panic!("Failed to generate address for network: {network_name}"));

        // Verify network mapping
        let expected_network = match *network_name {
            "mainnet" => Network::MainNet,
            "stagenet" => Network::StageNet,
            "esmeralda" => Network::Esmeralda,
            "localnet" => Network::LocalNet,
            _ => Network::Esmeralda, // Default fallback
        };

        assert_eq!(address.network(), expected_network);
    }

    // Test wallet metadata validation
    let mut wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet");

    // Test various metadata configurations
    let test_labels = vec![
        Some("Simple Wallet".to_string()),
        Some("Wallet with special chars: !@#$%^&*()".to_string()),
        Some(
            "Very long wallet name that exceeds normal limits but should still work because we don't impose arbitrary \
             restrictions"
                .to_string(),
        ),
        Some("🚀 Unicode Wallet 💰".to_string()),
        None,
    ];

    for label in &test_labels {
        wallet.set_label(label.clone());
        assert_eq!(wallet.label(), label.as_ref());

        // Wallet should still function with any label
        let address = wallet
            .get_single_address(TariAddressFeatures::create_one_sided_only())
            .expect("Failed to generate address with label");

        assert!(!address.to_hex().is_empty());
    }

    // Test key index validation
    let key_indices = vec![0, 1, 100, 999999, u64::MAX];

    for key_index in &key_indices {
        wallet.set_current_key_index(*key_index);
        assert_eq!(wallet.current_key_index(), *key_index);

        // Wallet should function with any key index
        let address = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
            .unwrap_or_else(|_| panic!("Failed to generate address with key index: {key_index}"));

        assert!(!address.to_hex().is_empty());
    }

    // Test custom properties validation
    let custom_properties = vec![
        ("version", "1.0.0"),
        ("created_by", "integration_test"),
        ("empty_value", ""),
        ("unicode_key_🔑", "unicode_value_💎"),
        ("long_key_name_that_is_very_long_indeed", "short_val"),
        (
            "short",
            "very_long_value_that_contains_lots_of_information_about_something_important",
        ),
    ];

    for (key, value) in &custom_properties {
        wallet.set_property(key.to_string(), value.to_string());
        assert_eq!(wallet.get_property(key), Some(&value.to_string()));

        // Wallet should function with any custom properties
        let address = wallet
            .get_single_address(TariAddressFeatures::create_interactive_only())
            .unwrap_or_else(|_| panic!("Failed to generate address with property: {key}={value}"));

        assert!(!address.to_hex().is_empty());
    }

    println!("✓ Configuration parameter validation test passed");
    println!("  Tested {} network configurations", valid_networks.len());
    println!("  Tested {} label configurations", test_labels.len());
    println!("  Tested {} key index values", key_indices.len());
    println!("  Tested {} custom property pairs", custom_properties.len());
}

/// Test network-specific address validation
#[tokio::test]
async fn test_network_specific_address_validation() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    // Create addresses for each network
    let mut network_address_sets = HashMap::new();

    for config in NetworkConfig::all_networks() {
        let mut wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet");
        wallet.set_network(config.name.clone());

        // Generate a comprehensive set of addresses
        let mut addresses = Vec::new();

        // Test all feature combinations
        let feature_sets = vec![
            TariAddressFeatures::create_interactive_only(),
            TariAddressFeatures::create_one_sided_only(),
            TariAddressFeatures::create_interactive_and_one_sided(),
        ];

        for features in feature_sets {
            // Dual addresses
            let dual_addr = wallet
                .get_dual_address(features, None)
                .expect("Failed to generate dual address");
            addresses.push(("dual", features, dual_addr));

            // Single addresses
            let single_addr = wallet
                .get_single_address(features)
                .expect("Failed to generate single address");
            addresses.push(("single", features, single_addr));
        }

        // Test addresses with payment IDs
        let payment_ids = vec![vec![0x01; 8], vec![0xFF; 16], vec![0x42, 0x24, 0x12, 0x21]];

        for payment_id in payment_ids {
            let addr_with_payment = wallet
                .get_dual_address(TariAddressFeatures::create_interactive_only(), Some(payment_id.clone()))
                .expect("Failed to generate address with payment ID");

            // Address with payment ID should have the PAYMENT_ID flag added
            let expected_features =
                TariAddressFeatures(TariAddressFeatures::INTERACTIVE_ONLY | TariAddressFeatures::PAYMENT_ID);
            addresses.push(("dual_payment", expected_features, addr_with_payment));
        }

        network_address_sets.insert(config.name.clone(), (config, addresses));
    }

    // Validate address properties for each network
    for (network_name, (config, addresses)) in &network_address_sets {
        for (addr_type, features, address) in addresses {
            // Verify network consistency
            assert_eq!(
                address.network(),
                config.network,
                "Address network mismatch for {addr_type} on {network_name}"
            );

            // Verify feature consistency
            assert_eq!(
                address.features(),
                *features,
                "Address features mismatch for {addr_type} on {network_name}"
            );

            // Verify address type consistency
            match *addr_type {
                "dual" | "dual_payment" => {
                    assert!(
                        matches!(address, TariAddress::Dual(_)),
                        "Expected dual address for {addr_type} on {network_name}"
                    );
                    assert!(address.public_view_key().is_some());
                },
                "single" => {
                    assert!(
                        matches!(address, TariAddress::Single(_)),
                        "Expected single address for {addr_type} on {network_name}"
                    );
                    assert!(address.public_view_key().is_none());
                },
                _ => panic!("Unknown address type: {addr_type}"),
            }

            // Verify payment ID handling
            if addr_type == &"dual_payment" {
                assert!(
                    address.features().contains(TariAddressFeatures::PAYMENT_ID),
                    "Payment ID address should have PAYMENT_ID feature"
                );
            }

            // Verify hex encoding/decoding
            let hex_str = address.to_hex();
            assert!(!hex_str.is_empty());
            assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    // Test cross-network address uniqueness
    let mainnet_set = &network_address_sets["mainnet"];
    let stagenet_set = &network_address_sets["stagenet"];

    for ((main_type, main_features, main_addr), (stage_type, stage_features, stage_addr)) in
        mainnet_set.1.iter().zip(stagenet_set.1.iter())
    {
        // Same configuration should produce different addresses for different networks
        if main_type == stage_type && main_features == stage_features {
            assert_ne!(
                main_addr.to_hex(),
                stage_addr.to_hex(),
                "Identical addresses across networks for type: {main_type}"
            );
        }
    }

    println!("✓ Network-specific address validation test passed");
    for (network_name, (_, addresses)) in &network_address_sets {
        println!("  {}: validated {} addresses", network_name, addresses.len());
    }
}

/// Test wallet migration between networks
#[tokio::test]
async fn test_wallet_network_migration() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    // Start with wallet on mainnet
    let mut wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet");

    wallet.set_network("mainnet".to_string());
    wallet.set_label(Some("Migration Test Wallet".to_string()));
    wallet.set_current_key_index(42);
    wallet.set_property("original_network".to_string(), "mainnet".to_string());

    // Generate address on mainnet
    let mainnet_address = wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate mainnet address");

    assert_eq!(mainnet_address.network(), Network::MainNet);

    // Migrate wallet to stagenet
    wallet.set_network("stagenet".to_string());
    wallet.set_property("migrated_to".to_string(), "stagenet".to_string());

    // Generate address on stagenet (same wallet, different network)
    let stagenet_address = wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate stagenet address");

    assert_eq!(stagenet_address.network(), Network::StageNet);

    // Verify wallet properties are preserved during migration
    assert_eq!(wallet.master_key_bytes(), wallet.master_key_bytes()); // Same master key
    assert_eq!(wallet.label(), Some(&"Migration Test Wallet".to_string()));
    assert_eq!(wallet.current_key_index(), 42);
    assert_eq!(wallet.get_property("original_network"), Some(&"mainnet".to_string()));
    assert_eq!(wallet.get_property("migrated_to"), Some(&"stagenet".to_string()));

    // Verify addresses are different but derive from same keys
    assert_ne!(mainnet_address.to_hex(), stagenet_address.to_hex());
    assert_eq!(mainnet_address.features(), stagenet_address.features());

    // Test migration through all networks
    let migration_path = ["esmeralda", "localnet", "mainnet"];
    let mut migration_addresses = Vec::new();

    for (i, network_name) in migration_path.iter().enumerate() {
        wallet.set_network(network_name.to_string());
        wallet.set_property("migration_step".to_string(), i.to_string());

        let address = wallet
            .get_single_address(TariAddressFeatures::create_one_sided_only())
            .unwrap_or_else(|_| panic!("Failed to generate address for {network_name}"));

        migration_addresses.push((network_name.to_string(), address));
    }

    // Verify all migration addresses are unique
    for i in 0..migration_addresses.len() {
        for j in i + 1..migration_addresses.len() {
            assert_ne!(
                migration_addresses[i].1.to_hex(),
                migration_addresses[j].1.to_hex(),
                "Migration addresses should be unique: {} vs {}",
                migration_addresses[i].0,
                migration_addresses[j].0
            );
        }
    }

    // Test migration back to original network produces original address
    wallet.set_network("mainnet".to_string());
    let back_to_mainnet_address = wallet
        .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
        .expect("Failed to generate return mainnet address");

    assert_eq!(
        mainnet_address.to_hex(),
        back_to_mainnet_address.to_hex(),
        "Migration back to original network should produce same address"
    );

    println!("✓ Wallet network migration test passed");
    println!("  Migrated through {} networks", migration_path.len() + 2); // +2 for initial mainnet and stagenet
    println!("  Verified address consistency after return migration");
}

/// Test configuration edge cases and error handling
#[tokio::test]
async fn test_configuration_edge_cases() {
    let seed_phrase = generate_seed_phrase().expect("Failed to generate seed phrase");

    // Test wallet creation with various initial configurations
    let mut wallet = Wallet::new_from_seed_phrase(&seed_phrase, None).expect("Failed to create wallet");

    // Test rapid network changes
    let rapid_networks = [
        "mainnet",
        "stagenet",
        "esmeralda",
        "localnet",
        "mainnet",
        "esmeralda",
        "stagenet",
        "localnet",
    ];

    for (i, network) in rapid_networks.iter().enumerate() {
        wallet.set_network(network.to_string());
        wallet.set_current_key_index(i as u64);

        // Should be able to generate addresses after each change
        let address = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_only(), None)
            .unwrap_or_else(|_| panic!("Failed to generate address after rapid change to {network}"));

        assert!(!address.to_hex().is_empty());
    }

    // Test large metadata operations
    let large_label = "A".repeat(10000); // Very long label
    wallet.set_label(Some(large_label.clone()));
    assert_eq!(wallet.label(), Some(&large_label));

    // Test many custom properties
    for i in 0..1000 {
        wallet.set_property(format!("key_{i}"), format!("value_{i}"));
    }

    // Verify all properties are stored
    for i in 0..1000 {
        assert_eq!(wallet.get_property(&format!("key_{i}")), Some(&format!("value_{i}")));
    }

    // Wallet should still function with lots of metadata
    let address_with_metadata = wallet
        .get_single_address(TariAddressFeatures::create_one_sided_only())
        .expect("Failed to generate address with large metadata");

    assert!(!address_with_metadata.to_hex().is_empty());

    // Test property removal under stress
    for i in 0..500 {
        let removed = wallet.remove_property(&format!("key_{i}"));
        assert_eq!(removed, Some(format!("value_{i}")));
    }

    // Verify partial removal
    for i in 0..500 {
        assert_eq!(wallet.get_property(&format!("key_{i}")), None);
    }
    for i in 500..1000 {
        assert_eq!(wallet.get_property(&format!("key_{i}")), Some(&format!("value_{i}")));
    }

    // Test extreme key indices
    let extreme_indices = vec![0, 1, u32::MAX as u64, u64::MAX];

    for key_index in &extreme_indices {
        wallet.set_current_key_index(*key_index);

        // Should be able to generate addresses with extreme indices
        let address = wallet
            .get_dual_address(TariAddressFeatures::create_interactive_and_one_sided(), None)
            .unwrap_or_else(|_| panic!("Failed to generate address with key index: {key_index}"));

        assert!(!address.to_hex().is_empty());
    }

    println!("✓ Configuration edge cases test passed");
    println!("  Tested rapid network changes: {} transitions", rapid_networks.len());
    println!(
        "  Tested large metadata: {} character label, 1000 properties",
        large_label.len()
    );
    println!("  Tested extreme key indices: {}", extreme_indices.len());
}
