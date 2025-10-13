pub mod cheetah;
pub mod slip10;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use cheetah::{PrivateKey, PublicKey, Signature};
pub use slip10::{derive_master_key, ExtendedKey};

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;

/// Generate master key from entropy and salt using Argon2 + BIP39 + SLIP-10
pub fn gen_master_key(entropy: &[u8], salt: &[u8]) -> (String, ExtendedKey) {
    let mut argon_output = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2d,
        Version::V0x13,
        Params::new(6 << 17, 6, 4, None).unwrap(),
    )
    .hash_password_into(entropy, salt, &mut argon_output)
    .expect("Invalid entropy and/or salt");

    let mnemonic = Mnemonic::from_entropy(&argon_output).unwrap();
    (
        mnemonic.to_string(),
        derive_master_key(&mnemonic.to_seed("")),
    )
}
