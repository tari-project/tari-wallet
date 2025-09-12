use std::str::FromStr;

use argon2::password_hash::{
    rand_core::{OsRng, RngCore},
    SaltString,
};
use blake2::Blake2b;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use digest::{consts::U32, generic_array::GenericArray, FixedOutput};
use serde::{Deserialize, Serialize};
use tari_common_types::encryption::{decrypt_bytes_integral_nonce, encrypt_bytes_integral_nonce};
use tari_crypto::{hash_domain, hashing::DomainSeparatedHasher};
use tari_utilities::{hidden_type, safe_array::SafeArray, Hidden, SafePassword};
use zeroize::Zeroize;

use crate::{EncryptionError, KeyManagementError, WalletResult};

hidden_type!(WalletMainEncryptionKey, Vec<u8>);
hidden_type!(WalletSecondaryEncryptionKey, SafeArray<u8, { size_of::<Key>() }>);
hidden_type!(WalletSecondaryDerivationKey, SafeArray<u8, { size_of::<Key>() }>);
hash_domain!(SecondaryKeyDomain, "com.tari.base_layer.wallet.secondary_key", 0);
// Authenticated data prefix for main key encryption; append the encryption version later
const MAIN_KEY_AAD_PREFIX: &str = "wallet_main_key_encryption_v";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseEncryptionFields {
    secondary_key_version: u8,   // the encryption parameter version
    secondary_key_salt: String,  // the high-entropy salt used to derive the secondary derivation key
    secondary_key_hash: Vec<u8>, // a hash commitment to the secondary derivation key
    encrypted_main_key: Vec<u8>, // the main key, encrypted with the secondary key
}

impl DatabaseEncryptionFields {
    pub fn new(passphrase: &SafePassword) -> WalletResult<Self> {
        let mut main_key = WalletMainEncryptionKey::from(vec![0u8; size_of::<Key>()]);
        let mut rng = OsRng;
        rng.fill_bytes(main_key.reveal_mut());

        // Use the most recent `Argon2` parameters
        let argon2_params = Argon2Parameters::from_version(None)?;

        // Derive the secondary key from the user's passphrase and a high-entropy salt
        let secondary_key_salt = SaltString::generate(&mut rng).to_string();
        let (secondary_key, secondary_key_hash) =
            Self::derive_secondary_key(passphrase, argon2_params.clone(), &secondary_key_salt)?;

        // Use the secondary key to encrypt the main key
        let encrypted_main_key = Self::encrypt_main_key(&secondary_key, &main_key, argon2_params.id)?;

        Ok(Self {
            secondary_key_version: argon2_params.id,
            secondary_key_salt,
            secondary_key_hash,
            encrypted_main_key,
        })
    }

    pub fn get_cipher(&self, passphrase: &SafePassword) -> WalletResult<XChaCha20Poly1305> {
        let argon2_params = Argon2Parameters::from_version(Some(self.secondary_key_version))?;

        // Derive the secondary key from the user's passphrase and salt
        let (secondary_key, secondary_key_hash) =
            Self::derive_secondary_key(passphrase, argon2_params, &self.secondary_key_salt)?;

        // Attempt to decrypt and return the encrypted main key
        if self.secondary_key_hash != secondary_key_hash {
            return Err(KeyManagementError::InvalidPassphrase.into());
        }
        let main_key = Self::decrypt_main_key(&secondary_key, &self.encrypted_main_key, self.secondary_key_version)?;

        Ok(XChaCha20Poly1305::new(Key::from_slice(main_key.reveal())))
    }

    fn derive_secondary_key(
        passphrase: &SafePassword,
        params: Argon2Parameters,
        salt: &String,
    ) -> WalletResult<(WalletSecondaryEncryptionKey, Vec<u8>)> {
        // Produce the secondary derivation key from the passphrase and salt
        let mut secondary_derivation_key = WalletSecondaryDerivationKey::from(SafeArray::default());
        argon2::Argon2::new(params.algorithm, params.version, params.params)
            .hash_password_into(
                passphrase.reveal(),
                salt.as_bytes(),
                secondary_derivation_key.reveal_mut(),
            )
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // Derive the secondary key
        let mut secondary_key = WalletSecondaryEncryptionKey::from(SafeArray::default());
        DomainSeparatedHasher::<Blake2b<U32>, SecondaryKeyDomain>::new()
            .chain(secondary_derivation_key.reveal())
            .finalize_into(GenericArray::from_mut_slice(secondary_key.reveal_mut()));

        // Produce the associated commitment
        let secondary_key_hash = DomainSeparatedHasher::<Blake2b<U32>, SecondaryKeyDomain>::new()
            .chain(secondary_derivation_key.reveal())
            .finalize()
            .as_ref()
            .to_vec();

        Ok((secondary_key, secondary_key_hash))
    }

    /// Encrypt the main database key using the secondary key
    fn encrypt_main_key(
        secondary_key: &WalletSecondaryEncryptionKey,
        main_key: &WalletMainEncryptionKey,
        version: u8,
    ) -> WalletResult<Vec<u8>> {
        // Set up the authenticated data
        let mut aad = MAIN_KEY_AAD_PREFIX.as_bytes().to_owned();
        aad.push(version);

        // Encrypt the main key
        let cipher = XChaCha20Poly1305::new(Key::from_slice(secondary_key.reveal()));
        let encrypted_main_key = encrypt_bytes_integral_nonce(&cipher, aad, Hidden::hide(main_key.reveal().clone()))
            .map_err(EncryptionError::EncryptionFailed)?;

        Ok(encrypted_main_key)
    }

    /// Decrypt the main database key using the secondary key
    fn decrypt_main_key(
        secondary_key: &WalletSecondaryEncryptionKey,
        encrypted_main_key: &[u8],
        version: u8,
    ) -> WalletResult<WalletMainEncryptionKey> {
        // Set up the authenticated data
        let mut aad = MAIN_KEY_AAD_PREFIX.as_bytes().to_owned();
        aad.push(version);

        // Authenticate and decrypt the main key
        let cipher = XChaCha20Poly1305::new(Key::from_slice(secondary_key.reveal()));

        Ok(WalletMainEncryptionKey::from(
            decrypt_bytes_integral_nonce(&cipher, aad, encrypted_main_key)
                .map_err(|_| KeyManagementError::InvalidPassphrase)?,
        ))
    }
}

impl Default for DatabaseEncryptionFields {
    fn default() -> Self {
        DatabaseEncryptionFields::new(&SafePassword::from_str("").unwrap()).unwrap()
    }
}

/// A structure to hold `Argon2` parameter versions, which may change over time and must be supported
#[derive(Clone)]
pub struct Argon2Parameters {
    id: u8,                       // version identifier
    algorithm: argon2::Algorithm, // algorithm variant
    version: argon2::Version,     // algorithm version
    params: argon2::Params,       // memory, iteration count, parallelism, output length
}

impl Argon2Parameters {
    /// Construct and return `Argon2` parameters by version identifier
    /// If you pass in `None`, you'll get the most recent
    pub fn from_version(id: Option<u8>) -> WalletResult<Self> {
        // Each subsequent version identifier _must_ increase!
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
        match id {
            // Be sure to update the `None` behavior when updating this!
            None | Some(1) => Ok(Argon2Parameters {
                id: 1,
                algorithm: argon2::Algorithm::Argon2id,
                version: argon2::Version::V0x13,
                params: argon2::Params::new(46 * 1024, 1, 1, Some(size_of::<Key>()))
                    .map_err(|e| EncryptionError::InvalidEncryptionParameters(e.to_string()))?,
            }),
            Some(id) => Err(EncryptionError::EncryptionVersionError(id.to_string()).into()),
        }
    }
}
