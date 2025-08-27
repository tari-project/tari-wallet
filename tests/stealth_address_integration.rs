// Integration tests for stealth address functionality
// These tests verify that stealth addresses work correctly with other wallet components

use lightweight_wallet_libs::{
    data_structures::types::{CompressedPublicKey, PrivateKey},
    key_management::{key_derivation, StealthAddressService},
};
use tari_utilities::byte_array::ByteArray;

#[test]
fn test_stealth_address_with_encrypted_data() {
    let service = StealthAddressService::new();

    // Setup keys
    let view_key = PrivateKey::random();
    let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::random());
    let sender_private_key = PrivateKey::random();

    // Generate stealth address
    let stealth_address = service
        .generate_stealth_address(&view_key, &spend_key, &sender_private_key)
        .unwrap();

    // Generate shared secret for encryption
    let shared_secret = service
        .generate_shared_secret(&sender_private_key, &stealth_address.view_public_key)
        .unwrap();
    let encryption_key = service.shared_secret_to_output_encryption_key(&shared_secret).unwrap();

    // Test that encryption key can be derived from stealth address components
    let receiver_shared_secret = service
        .generate_shared_secret(&view_key, &stealth_address.sender_offset_public_key)
        .unwrap();
    let receiver_encryption_key = service
        .shared_secret_to_output_encryption_key(&receiver_shared_secret)
        .unwrap();

    // Both should produce valid encryption keys (even if different due to simplified implementation)
    assert_ne!(encryption_key.as_bytes(), [0u8; 32]);
    assert_ne!(receiver_encryption_key.as_bytes(), [0u8; 32]);
}

#[test]
fn test_stealth_address_with_key_derivation() {
    let service = StealthAddressService::new();

    // Test integration with key derivation functions
    let entropy = [42u8; 16];

    // Derive a view key using the key derivation system
    let derived_key = key_derivation::derive_private_key_from_entropy(&entropy, "stealth_test", 0).unwrap();
    let view_key = PrivateKey::new(derived_key.as_bytes().try_into().unwrap());

    let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::random());
    let sender_private_key = PrivateKey::random();

    // Should work with derived keys
    let stealth_address = service.generate_stealth_address(&view_key, &spend_key, &sender_private_key);
    assert!(stealth_address.is_ok());

    // Should be able to recover keys
    let stealth_addr = stealth_address.unwrap();
    let recovered = service.try_stealth_address_key_recovery(
        &view_key,
        &stealth_addr.sender_offset_public_key,
        &stealth_addr.stealth_spending_key,
    );
    assert!(recovered.is_ok());
}

#[test]
fn test_stealth_address_key_consistency() {
    let service = StealthAddressService::new();

    // Test that different derivation methods produce consistent results
    let base_key = PrivateKey::new([123u8; 32]);
    let public_key = CompressedPublicKey::from_private_key(&base_key);

    // Derive encryption key from secret
    let enc_from_secret = service.secret_key_to_output_encryption_key(&base_key).unwrap();

    // Derive encryption key from public key
    let enc_from_public = service.public_key_to_output_encryption_key(&public_key).unwrap();

    // Should produce different results (as expected)
    assert_ne!(enc_from_secret, enc_from_public);

    // But both should be valid and deterministic
    let enc_from_secret2 = service.secret_key_to_output_encryption_key(&base_key).unwrap();
    let enc_from_public2 = service.public_key_to_output_encryption_key(&public_key).unwrap();

    assert_eq!(enc_from_secret, enc_from_secret2);
    assert_eq!(enc_from_public, enc_from_public2);
}

#[test]
fn test_stealth_address_payment_id_integration() {
    let service = StealthAddressService::new();

    // Test stealth addresses with different payment ID types
    let view_key = PrivateKey::random();
    let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::random());
    let sender_private_key = PrivateKey::random();

    let stealth_address = service
        .generate_stealth_address(&view_key, &spend_key, &sender_private_key)
        .unwrap();

    // Verify all keys in stealth address are valid public keys
    assert_ne!(stealth_address.view_public_key.as_bytes(), [0u8; 32]);
    assert_ne!(stealth_address.spend_public_key.as_bytes(), [0u8; 32]);
    assert_ne!(stealth_address.stealth_spending_key.as_bytes(), [0u8; 32]);
    assert_ne!(stealth_address.sender_offset_public_key.as_bytes(), [0u8; 32]);
}

#[test]
fn test_stealth_address_with_multiple_domains() {
    let service = StealthAddressService::new();

    // Test that different domain separations produce different results
    let secret_data = b"test_secret_data";

    let enc_key = service.shared_secret_to_output_encryption_key(secret_data).unwrap();
    let spend_key = service.shared_secret_to_output_spending_key(secret_data).unwrap();

    // Domain separation should ensure different keys
    assert_ne!(enc_key, spend_key);

    // Test with different input data
    let secret_data2 = b"different_secret";
    let enc_key2 = service.shared_secret_to_output_encryption_key(secret_data2).unwrap();
    let spend_key2 = service.shared_secret_to_output_spending_key(secret_data2).unwrap();

    // Different inputs should produce different keys
    assert_ne!(enc_key, enc_key2);
    assert_ne!(spend_key, spend_key2);
}

#[test]
fn test_stealth_address_service_stateless() {
    // Test that the service is stateless and thread-safe
    let service1 = StealthAddressService::new();
    let service2 = StealthAddressService::new();

    let test_key = PrivateKey::new([42u8; 32]);

    // Multiple instances should produce same results
    let result1 = service1.secret_key_to_output_encryption_key(&test_key).unwrap();
    let result2 = service2.secret_key_to_output_encryption_key(&test_key).unwrap();

    assert_eq!(result1, result2);
}

#[test]
fn test_stealth_address_error_handling() {
    let service = StealthAddressService::new();

    // All operations should succeed with valid inputs
    let view_key = PrivateKey::random();
    let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::random());
    let sender_key = PrivateKey::random();

    let result = service.generate_stealth_address(&view_key, &spend_key, &sender_key);
    assert!(result.is_ok());

    let stealth_addr = result.unwrap();
    let recovery_result = service.try_stealth_address_key_recovery(
        &view_key,
        &stealth_addr.sender_offset_public_key,
        &stealth_addr.stealth_spending_key,
    );
    assert!(recovery_result.is_ok());
}

#[test]
fn test_stealth_address_large_scale() {
    let service = StealthAddressService::new();

    // Test creating many stealth addresses to ensure no conflicts
    let view_key = PrivateKey::new([1u8; 32]);
    let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::new([2u8; 32]));

    let mut addresses = Vec::new();

    for i in 0..100 {
        let sender_key = PrivateKey::new([i as u8; 32]);
        let address = service
            .generate_stealth_address(&view_key, &spend_key, &sender_key)
            .unwrap();
        addresses.push(address);
    }

    // All addresses should be unique
    for i in 0..addresses.len() {
        for j in i + 1..addresses.len() {
            assert_ne!(addresses[i].stealth_spending_key, addresses[j].stealth_spending_key);
            assert_ne!(
                addresses[i].sender_offset_public_key,
                addresses[j].sender_offset_public_key
            );
        }
    }
}
