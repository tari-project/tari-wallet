//! Hash domain definitions for domain separation

use tari_crypto::hashing::DomainSeparation;

/// Domain for key manager operations
pub struct KeyManagerDomain;

impl DomainSeparation for KeyManagerDomain {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.base_layer.key_manager"
    }
}

/// Domain for wallet message signing operations
/// This must match the exact domain used by Tari wallet for compatibility
pub struct WalletMessageSigningDomain;

impl DomainSeparation for WalletMessageSigningDomain {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.base_layer.wallet.message_signing"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_domain_version() {
        assert_eq!(KeyManagerDomain::version(), 1);
    }

    #[test]
    fn test_key_manager_domain_name() {
        assert_eq!(KeyManagerDomain::domain(), "com.tari.base_layer.key_manager");
    }

    #[test]
    fn test_wallet_message_signing_domain_version() {
        assert_eq!(WalletMessageSigningDomain::version(), 1);
    }

    #[test]
    fn test_wallet_message_signing_domain_name() {
        assert_eq!(
            WalletMessageSigningDomain::domain(),
            "com.tari.base_layer.wallet.message_signing"
        );
    }

    #[test]
    fn test_domain_separation_trait_implementation() {
        // Test that both domains implement DomainSeparation trait correctly
        let _key_version = KeyManagerDomain::version();
        let _key_domain = KeyManagerDomain::domain();
        let _wallet_version = WalletMessageSigningDomain::version();
        let _wallet_domain = WalletMessageSigningDomain::domain();

        // Verify domain names are different
        assert_ne!(KeyManagerDomain::domain(), WalletMessageSigningDomain::domain());

        // Verify versions are consistent
        assert_eq!(KeyManagerDomain::version(), WalletMessageSigningDomain::version());
    }

    #[test]
    fn test_domain_strings_are_static() {
        // Test that domain strings are 'static and valid
        let key_domain = KeyManagerDomain::domain();
        let wallet_domain = WalletMessageSigningDomain::domain();

        assert!(!key_domain.is_empty());
        assert!(!wallet_domain.is_empty());
        assert!(key_domain.contains("com.tari"));
        assert!(wallet_domain.contains("com.tari"));
    }
}
