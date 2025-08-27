//! Key derivation functions for lightweight wallets
//!
//! This implementation follows the Tari key derivation specification for compatibility
//! with the main Tari wallet implementation.

use blake2::Blake2b;
use digest::{consts::U64, Digest};
use tari_utilities::ByteArray;

use crate::{
    crypto::{DomainSeparatedHasher, KeyManagerDomain, PublicKey, RistrettoPublicKey, RistrettoSecretKey, SecretKey},
    errors::KeyManagementError,
};

/// Derives a public key from a private key
pub fn derive_public_key_from_private(
    private_key: &RistrettoSecretKey,
) -> Result<RistrettoPublicKey, KeyManagementError> {
    Ok(RistrettoPublicKey::from_secret_key(private_key))
}

/// Derives view and spend keys from CipherSeed entropy using Tari's exact key derivation pattern
/// This matches the main Tari KeyManager implementation which uses entropy directly
pub fn derive_view_and_spend_keys_from_entropy(
    entropy: &[u8; 16],
) -> Result<(RistrettoSecretKey, RistrettoSecretKey), KeyManagementError> {
    // Tari uses specific branch seeds for view and spend keys
    // These constants match the main Tari wallet implementation
    const VIEW_KEY_BRANCH: &str = "data encryption"; // For encrypted data decryption (view key)
    const SPEND_KEY_BRANCH: &str = "comms"; // Communication node identity key (spending + message signing)

    let view_key = derive_private_key_from_entropy(entropy, VIEW_KEY_BRANCH, 0)
        .map_err(|e| KeyManagementError::view_key_derivation_failed(&format!("Failed to derive view key: {e}")))?;

    let spend_key = derive_private_key_from_entropy(entropy, SPEND_KEY_BRANCH, 0)
        .map_err(|e| KeyManagementError::spend_key_derivation_failed(&format!("Failed to derive spend key: {e}")))?;

    Ok((view_key, spend_key))
}

/// Derives a private key directly from CipherSeed entropy using Tari's key derivation specification
/// This matches the main Tari KeyManager.derive_private_key implementation exactly
pub fn derive_private_key_from_entropy(
    entropy: &[u8; 16],
    branch_seed: &str,
    key_index: u64,
) -> Result<RistrettoSecretKey, KeyManagementError> {
    // This matches the main Tari KeyManager implementation exactly:
    // DomainSeparatedHasher::new_with_label(HASHER_LABEL_DERIVE_KEY)
    //   .chain(self.seed.entropy())  // CipherSeed entropy directly (16 bytes)
    //   .chain(self.branch_seed.as_bytes())
    //   .chain(key_index.to_le_bytes())
    let derive_key = DomainSeparatedHasher::<Blake2b<U64>, KeyManagerDomain>::new_with_label("derive_key")
            .chain(entropy) // Use the 16-byte CipherSeed entropy directly
            .chain(branch_seed.as_bytes())
            .chain(key_index.to_le_bytes())
            .finalize();

    let derive_key = derive_key.as_ref();
    RistrettoSecretKey::from_uniform_bytes(derive_key).map_err(|e| {
        KeyManagementError::branch_key_derivation_failed(
            branch_seed,
            key_index,
            &format!("Failed to create private key: {e}"),
        )
    })
}

/// Derives a stealth address from view and spend public keys
pub fn derive_stealth_address(
    view_public_key: &RistrettoPublicKey,
    spend_public_key: &RistrettoPublicKey,
) -> Result<[u8; 32], KeyManagementError> {
    // This is a simplified implementation - in practice, Tari stealth addresses
    // use a more complex derivation involving the view and spend keys
    let mut hasher = Blake2b::<U64>::new();
    hasher.update(view_public_key.as_bytes());
    hasher.update(spend_public_key.as_bytes());
    let result = hasher.finalize();

    let mut stealth_address = [0u8; 32];
    stealth_address.copy_from_slice(&result[..32]);
    Ok(stealth_address)
}

#[cfg(test)]
mod tests {
    use tari_utilities::ByteArray;

    use super::*;
    use crate::crypto::PublicKey;

    #[test]
    fn test_tari_test_vector_validation() {
        // Official Tari test vector data for validation
        let seed_phrase = "scare harsh invite normal satisfy subject similar excite dragon gap fence machine monster \
                           flavor spoon tape rice require risk sting health nurse orange stick";

        // Expected keys from the test vector
        let expected_view_private_key = "7755e59ca4a10d19d14f56a014826d005d029ff9a5053c850d63f9322005080a";
        let expected_spend_private_key = "ef5d6881f2b1ff65dd6d62a77f73be2179cad40c6d587d5ff9f4ed49b5378b05";
        let expected_view_public_key = "c64341cddadc29e1e31ce1f568d3bbd0262ef2f9bfdbf2405d85735d45f1bb02";
        let expected_spend_public_key = "5285073b72f698132432e1be6b76e170d437e4ba11bfaf5f7539d5c998523226";

        // Expected addresses (for future validation once address generation is implemented)
        let expected_base58_address =
            "12JVm6ARPDg2GvBEpaKxADBW4SkacGRWZYhowEzoUvHrz9kFWCVv4QSYUE6JWiLFYcjEeZv43YJw8W7E8ynrMUWsDm5";
        let expected_emoji_address = "🐢📟📈🎉🤖⏰🔪🔬🍟😂😈🍋😂🚜🏦🔑💦🔋🍗🍪🚓🚨💯🔫🚓🎃🎼🐯🐔🎼🎓🚒💦🌈🎮🐯🤔🍺🐑🚢💅🍀🍔🍯😂➕🐀🐘😂🦁🔔🍶🤑💤🌻💯💊🎾🐗🍸🔥📎💅🎮🍯🍗💄";

        println!("=== Testing Tari Test Vector ===");
        println!("Seed phrase: {seed_phrase}");

        // Convert seed phrase to encrypted bytes (correct approach)
        let encrypted_bytes = crate::key_management::seed_phrase::mnemonic_to_bytes(seed_phrase)
            .expect("Failed to convert mnemonic to bytes");

        // Decrypt the CipherSeed to get the entropy
        let cipher_seed = crate::key_management::seed_phrase::CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)
            .expect("Failed to decrypt CipherSeed");

        // Use the entropy directly for key derivation (matching main Tari implementation)
        let entropy: [u8; 16] = cipher_seed
            .entropy()
            .try_into()
            .expect("Failed to convert entropy to 16-byte array");

        println!("CipherSeed entropy: {}", hex::encode(entropy));

        // Derive view and spend keys using entropy directly
        let (view_private_key, spend_private_key) =
            derive_view_and_spend_keys_from_entropy(&entropy).expect("Failed to derive view and spend keys");

        // Convert to public keys
        let view_public_key = RistrettoPublicKey::from_secret_key(&view_private_key);
        let spend_public_key = RistrettoPublicKey::from_secret_key(&spend_private_key);

        // Convert to hex strings for comparison
        let actual_view_private_key = hex::encode(view_private_key.as_bytes());
        let actual_spend_private_key = hex::encode(spend_private_key.as_bytes());
        let actual_view_public_key = hex::encode(view_public_key.as_bytes());
        let actual_spend_public_key = hex::encode(spend_public_key.as_bytes());

        println!("Expected View Private Key:  {expected_view_private_key}");
        println!("Actual View Private Key:    {actual_view_private_key}");
        println!("Expected Spend Private Key: {expected_spend_private_key}");
        println!("Actual Spend Private Key:   {actual_spend_private_key}");
        println!("Expected View Public Key:   {expected_view_public_key}");
        println!("Actual View Public Key:     {actual_view_public_key}");
        println!("Expected Spend Public Key:  {expected_spend_public_key}");
        println!("Actual Spend Public Key:    {actual_spend_public_key}");

        // Validate that we can derive keys successfully and they're different
        assert_ne!(
            view_private_key, spend_private_key,
            "View and spend private keys should be different"
        );
        assert_ne!(
            view_public_key, spend_public_key,
            "View and spend public keys should be different"
        );

        // Validate that public keys correspond to private keys
        assert_eq!(view_public_key, RistrettoPublicKey::from_secret_key(&view_private_key));
        assert_eq!(
            spend_public_key,
            RistrettoPublicKey::from_secret_key(&spend_private_key)
        );

        // Now test the exact value validation - this is the real test of correctness
        assert_eq!(
            actual_view_private_key, expected_view_private_key,
            "View private key mismatch"
        );
        assert_eq!(
            actual_spend_private_key, expected_spend_private_key,
            "Spend private key mismatch"
        );
        assert_eq!(
            actual_view_public_key, expected_view_public_key,
            "View public key mismatch"
        );
        assert_eq!(
            actual_spend_public_key, expected_spend_public_key,
            "Spend public key mismatch"
        );

        // Store expected addresses for future validation
        let _ = expected_base58_address;
        let _ = expected_emoji_address;

        println!("✅ Exact Tari test vector validation passed!");
    }

    #[test]
    fn test_entropy_based_key_derivation_consistency() {
        let entropy = [1u8; 16];
        let branch_seed = "test_branch";

        // Derive the same key multiple times
        let key1 = derive_private_key_from_entropy(&entropy, branch_seed, 0).unwrap();
        let key2 = derive_private_key_from_entropy(&entropy, branch_seed, 0).unwrap();
        let key3 = derive_private_key_from_entropy(&entropy, branch_seed, 1).unwrap();

        // Same parameters should produce same key
        assert_eq!(key1, key2);

        // Different index should produce different key
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_entropy_based_different_branch_seeds() {
        let entropy = [1u8; 16];

        let key1 = derive_private_key_from_entropy(&entropy, "branch1", 0).unwrap();
        let key2 = derive_private_key_from_entropy(&entropy, "branch2", 0).unwrap();

        // Different branch seeds should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_view_and_spend_keys_are_different() {
        let entropy = [1u8; 16];

        let (view_key, spend_key) = derive_view_and_spend_keys_from_entropy(&entropy).unwrap();

        // View and spend keys should be different
        assert_ne!(view_key, spend_key);

        // Verify they can be converted to public keys
        let view_public = RistrettoPublicKey::from_secret_key(&view_key);
        let spend_public = RistrettoPublicKey::from_secret_key(&spend_key);
        assert_ne!(view_public, spend_public);
    }

    /// Test vectors generated from the reference Tari KeyManager implementation
    /// These test vectors validate exact compatibility with the main Tari implementation
    #[test]
    fn test_key_derivation_test_vectors_empty_branch() {
        // Test entropy from reference implementation
        let entropy = hex::decode("69ccc5d42c8f57b2cf2851e0a77d1ee7").unwrap();
        let entropy_array: [u8; 16] = entropy.try_into().unwrap();

        // Test Case: Empty branch seed
        let branch_seed = "";

        // Test at index 0
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 0).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "2b0f7d935bcf9f4f9c6c4e550c44146a3502a521fbc6e9829bb5a2831e352000",
            "Private key mismatch at index 0 with empty branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "48b0f9604c5a23ecc3189fcb3869732ae01d0d14ebb3099640e9a662c549b319",
            "Public key mismatch at index 0 with empty branch"
        );

        // Test at index 1
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 1).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "9b359f7f3b56564c03a45f5abe1c9d1bb72dab7a71e5b665ffd8fc66a325ed05",
            "Private key mismatch at index 1 with empty branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "36ab505d558a7c03d233c7992f9266e39176631248235d3c83dd0540e2cc3871",
            "Public key mismatch at index 1 with empty branch"
        );

        // Test at index 2
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 2).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "1e3fbd7065248d2a7eb6a850c9019fd0f21642a7b5d82d88e6aefdc6c9990f04",
            "Private key mismatch at index 2 with empty branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "a62cc704b5c15cf18d50b34ee643662fd99ad2266267b445e54a400ba50b3902",
            "Public key mismatch at index 2 with empty branch"
        );

        // Test at index 10
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 10).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "f57bda036fa15f685edf75ddc29cc76436d4e812d0bb09019df1ba61f2975b0b",
            "Private key mismatch at index 10 with empty branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "6a369d19c856c7d6c0e729127d9101159f0239f5f98d9f9fa130c999eeada04f",
            "Public key mismatch at index 10 with empty branch"
        );

        // Test at index 255
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 255).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "a01ad09a2202093979b58ae3af4e07bcf6776ea29d258d01fe40c1f853263100",
            "Private key mismatch at index 255 with empty branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "30027590292a5ca454fe4b71c22ad7449540feff3e8c159e2a71c207e8260b48",
            "Public key mismatch at index 255 with empty branch"
        );
    }

    #[test]
    fn test_key_derivation_test_vectors_simple_branch() {
        // Test entropy from reference implementation
        let entropy = hex::decode("69ccc5d42c8f57b2cf2851e0a77d1ee7").unwrap();
        let entropy_array: [u8; 16] = entropy.try_into().unwrap();

        // Test Case: Simple branch seed
        let branch_seed = "test";

        // Test at index 0
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 0).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "e3780919a5babfe9d47dd68c6bba8d086681a07eb49c334589f63ebc0d682909",
            "Private key mismatch at index 0 with 'test' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "8847109d2cd6fe7475a38eca3219198430424e9a78be17e7c6fe4a12dbff5251",
            "Public key mismatch at index 0 with 'test' branch"
        );

        // Test at index 1
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 1).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "3c66cc2bb9a20527583085d57d464c21dbb0aff2e44300c67f62957001b63402",
            "Private key mismatch at index 1 with 'test' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "6e40e9825dc229b7329f5361650fba0ba104190766aa1539137202bf16177737",
            "Public key mismatch at index 1 with 'test' branch"
        );

        // Test at index 2
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 2).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "a589c38be9d22e7fd9097dff0dfd8f4164b098d1a5e7970e74441738b15a8f00",
            "Private key mismatch at index 2 with 'test' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "f45c406d073cf482ddb6dad772d565194e45d776c6379c3b8c4e332b1416e365",
            "Public key mismatch at index 2 with 'test' branch"
        );

        // Test at index 10
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 10).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "165840066b2781b5a632b2b9e3f4d41677634f0a33b33e59cd01013263854205",
            "Private key mismatch at index 10 with 'test' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "aeef00f776db94b0cf6945c1b7c73f3e0f5f08897ba5503188486847d3238377",
            "Public key mismatch at index 10 with 'test' branch"
        );

        // Test at index 255
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 255).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "32ce9bca020826b0bbf654b37605f7ccd50fb66f287e96af45bf4eb8486c580a",
            "Private key mismatch at index 255 with 'test' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "3e74d63504175268bf561048fa8e5574a02b987922db9fa3e962d7d1cb577f33",
            "Public key mismatch at index 255 with 'test' branch"
        );
    }

    #[test]
    fn test_key_derivation_test_vectors_realistic_branch() {
        // Test entropy from reference implementation
        let entropy = hex::decode("69ccc5d42c8f57b2cf2851e0a77d1ee7").unwrap();
        let entropy_array: [u8; 16] = entropy.try_into().unwrap();

        // Test Case: Realistic branch seed
        let branch_seed = "wallet_spending";

        // Test at index 0
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 0).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "66f713c1859cceb855bb49b5d1bcdd3a32f6e2163bc4fc4d1baeea39aea70508",
            "Private key mismatch at index 0 with 'wallet_spending' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "6e2480e880f9ac6da87f7a9ef3144c93cba5cde7f0af0c114a875868d25f4772",
            "Public key mismatch at index 0 with 'wallet_spending' branch"
        );

        // Test at index 1
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 1).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "57342dec2029bde37211fec09df09bdffd9c6ce6334f94aff87a492240881a05",
            "Private key mismatch at index 1 with 'wallet_spending' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "0afd8f41017656376321025669800e654996d58c951eba5e647692c75493dc5d",
            "Public key mismatch at index 1 with 'wallet_spending' branch"
        );

        // Test at index 2
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 2).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "b02247769bfddec3f477224639b47174ff5bb7648442440f279aa38a496dbe0f",
            "Private key mismatch at index 2 with 'wallet_spending' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "280520414f67908f71700f098bba6e2fa6a54759760bd52cbc7f171813581f75",
            "Public key mismatch at index 2 with 'wallet_spending' branch"
        );

        // Test at index 10
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 10).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "a810ea9be4b3dd60a6cb48e7778f4baf0ea9d4cf55377e27ef79a78cf90a1a01",
            "Private key mismatch at index 10 with 'wallet_spending' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "dab48a5757bfd0c7b273f3fef38bfa46dc113589528d4473bafd9597e06d146e",
            "Public key mismatch at index 10 with 'wallet_spending' branch"
        );

        // Test at index 255
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 255).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "8e2dfecde51c6c0d04376407ff1c43f2a4e0e9743f3a56f6117cb36f40fa6e0f",
            "Private key mismatch at index 255 with 'wallet_spending' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "443ee88f8f12adb64fe4f46b266276a8b9e62d9ec3f6215561ad08833a227d75",
            "Public key mismatch at index 255 with 'wallet_spending' branch"
        );
    }

    #[test]
    fn test_key_derivation_test_vectors_unicode_branch() {
        // Test entropy from reference implementation
        let entropy = hex::decode("69ccc5d42c8f57b2cf2851e0a77d1ee7").unwrap();
        let entropy_array: [u8; 16] = entropy.try_into().unwrap();

        // Test Case: Unicode branch seed (rocket emoji)
        let branch_seed = "🚀";

        // Test at index 0
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 0).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "93b94c4d9ad253f9821d8c5ebe1ca14c56f4d39acfece3e4579892850d136609",
            "Private key mismatch at index 0 with '🚀' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "d64901b0d5ae500b62dbe9125e1721653587a50e96dc0d144f2261293b169631",
            "Public key mismatch at index 0 with '🚀' branch"
        );

        // Test at index 1
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 1).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "eea864243f056b3ff8d85eb2d6706db1aca24c4ace955f633c29f5f5c6b8b504",
            "Private key mismatch at index 1 with '🚀' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "d6ab8cf3ec96ff4c75bcb0d2d3ad0cfa81c625b095d0e4b7f74ea22c8f84394b",
            "Public key mismatch at index 1 with '🚀' branch"
        );

        // Test at index 2
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 2).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "fb028f6fd1693393ed2d0f97dbe5cda550b2bbef179f72429ef189bd9862bb05",
            "Private key mismatch at index 2 with '🚀' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "0c1f1a1fc7ab66cf5987081257e28341df4a874b0c8ca7b4302fd071dba88339",
            "Public key mismatch at index 2 with '🚀' branch"
        );

        // Test at index 10
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 10).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "0f59822217529e909bc2359ff07fc8939943b87d6ed8c4ee5daa7e76ab52070a",
            "Private key mismatch at index 10 with '🚀' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "5c3a6d4254b5810ae4dcdf1655f0e6d024809abcd5dff51f7cea2a0ba7d36b59",
            "Public key mismatch at index 10 with '🚀' branch"
        );

        // Test at index 255
        let private_key = derive_private_key_from_entropy(&entropy_array, branch_seed, 255).unwrap();
        let public_key = RistrettoPublicKey::from_secret_key(&private_key);

        assert_eq!(
            hex::encode(private_key.as_bytes()),
            "f51b698e5f493ee47b9048e6c26f216cae191248a80b3b5b9ee5a2eaa51e2605",
            "Private key mismatch at index 255 with '🚀' branch"
        );
        assert_eq!(
            hex::encode(public_key.as_bytes()),
            "369ce97a1cd22e1aea8038bc05223511e00ba093c9ef2069321d979fd03f1c49",
            "Public key mismatch at index 255 with '🚀' branch"
        );
    }

    #[test]
    fn test_comprehensive_cross_validation() {
        // Comprehensive test to ensure all derivations work correctly
        let entropy = hex::decode("69ccc5d42c8f57b2cf2851e0a77d1ee7").unwrap();
        let entropy_array: [u8; 16] = entropy.try_into().unwrap();

        let test_cases = vec![
            ("", vec![
                (0, "2b0f7d935bcf9f4f9c6c4e550c44146a3502a521fbc6e9829bb5a2831e352000"),
                (1, "9b359f7f3b56564c03a45f5abe1c9d1bb72dab7a71e5b665ffd8fc66a325ed05"),
                (2, "1e3fbd7065248d2a7eb6a850c9019fd0f21642a7b5d82d88e6aefdc6c9990f04"),
            ]),
            ("test", vec![
                (0, "e3780919a5babfe9d47dd68c6bba8d086681a07eb49c334589f63ebc0d682909"),
                (1, "3c66cc2bb9a20527583085d57d464c21dbb0aff2e44300c67f62957001b63402"),
                (2, "a589c38be9d22e7fd9097dff0dfd8f4164b098d1a5e7970e74441738b15a8f00"),
            ]),
            ("wallet_spending", vec![
                (0, "66f713c1859cceb855bb49b5d1bcdd3a32f6e2163bc4fc4d1baeea39aea70508"),
                (1, "57342dec2029bde37211fec09df09bdffd9c6ce6334f94aff87a492240881a05"),
                (2, "b02247769bfddec3f477224639b47174ff5bb7648442440f279aa38a496dbe0f"),
            ]),
            ("🚀", vec![
                (0, "93b94c4d9ad253f9821d8c5ebe1ca14c56f4d39acfece3e4579892850d136609"),
                (1, "eea864243f056b3ff8d85eb2d6706db1aca24c4ace955f633c29f5f5c6b8b504"),
                (2, "fb028f6fd1693393ed2d0f97dbe5cda550b2bbef179f72429ef189bd9862bb05"),
            ]),
        ];

        for (branch_seed, expected_keys) in test_cases {
            for (index, expected_private_hex) in expected_keys {
                let derived_key = derive_private_key_from_entropy(&entropy_array, branch_seed, index).unwrap();
                let derived_hex = hex::encode(derived_key.as_bytes());

                assert_eq!(
                    derived_hex, expected_private_hex,
                    "Mismatch for branch '{branch_seed}' at index {index}"
                );

                // Ensure we can derive public key consistently
                let public_key = RistrettoPublicKey::from_secret_key(&derived_key);
                let public_key2 = derive_public_key_from_private(&derived_key).unwrap();
                assert_eq!(public_key, public_key2, "Public key derivation inconsistency");
            }
        }
    }
}
