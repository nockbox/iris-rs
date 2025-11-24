#![no_std]

extern crate alloc;
use alloc::string::{String, ToString};

pub mod cheetah;
pub mod slip10;

pub use cheetah::{PrivateKey, PublicKey, Signature};
pub use slip10::{derive_master_key, ExtendedKey};

#[cfg(feature = "mnemonic")]
pub use bip39::Mnemonic;
pub use iris_ztd::{Digest, Hashable};

#[cfg(feature = "argon2")]
use argon2::{Algorithm, Argon2, Params, Version};

/// Generate master key from entropy and salt using Argon2 + BIP39 + SLIP-10
#[cfg(all(feature = "argon2", feature = "mnemonic"))]
pub fn gen_master_key(entropy: &[u8], salt: &[u8]) -> (String, ExtendedKey) {
    let mut argon_output = [0u8; 32];
    let params = Params::new(
        786_432,  // m_cost: 768 MiB in KiB
        6,        // t_cost: 6 iterations
        4,        // p_cost: 4 threads
        Some(32), // output length
    )
    .expect("Invalid Argon2 parameters");

    Argon2::new(Algorithm::Argon2d, Version::V0x13, params)
        .hash_password_into(entropy, salt, &mut argon_output)
        .expect("Invalid entropy and/or salt");

    argon_output.reverse();

    let mnemonic = Mnemonic::from_entropy(&argon_output).unwrap();
    (
        mnemonic.to_string(),
        derive_master_key(&mnemonic.to_seed("")),
    )
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};
    use ibig::UBig;
    use iris_ztd::Hashable;

    use super::*;

    fn parse_byts_decimal(wid: usize, decimal: &str) -> Vec<u8> {
        let cleaned: String = decimal.chars().filter(|c| c.is_ascii_digit()).collect();
        let n = UBig::from_str_radix(&cleaned, 10).expect("Invalid decimal value");
        let bytes_be = n.to_be_bytes();
        let mut res = vec![0u8; wid];
        let mut started = false;
        let mut idx = 0;
        for byte in bytes_be.iter() {
            if *byte != 0 || started {
                started = true;
                if idx < wid {
                    res[idx] = *byte;
                    idx += 1;
                }
            }
        }
        res
    }

    #[test]
    fn test_keygen() {
        const LOG_ENTROPY_DEC: &str =
            "31944036134313954129336387727597658952065175074761089084822804536972439767490";
        const LOG_SALT_DEC: &str = "143851195137845551434793173733272547792";
        const LOG_MNEMONIC: &str = "pass destroy hub reject cricket flight camp garden scale liquid increase pool miracle fly tower file door cage vault tone night zero push crime";

        let entropy = parse_byts_decimal(32, LOG_ENTROPY_DEC);
        let salt = parse_byts_decimal(16, LOG_SALT_DEC);

        let (mnemonic, keypair) = gen_master_key(&entropy, &salt);
        assert_eq!(mnemonic, LOG_MNEMONIC);

        // check private key, chain code and pkh
        assert_eq!(
            hex::encode(keypair.private_key.unwrap().to_be_bytes()),
            "362b4073814e43f427983a83f11efcceb6741082c18f0d64b7e47340ba4485ba"
        );
        assert_eq!(
            hex::encode(keypair.chain_code),
            "95b522320f4dfae7486155b9529c582af3d7898ece606a802c43415786ced8d9"
        );
        assert_eq!(
            keypair.public_key.hash().to_string(),
            "AyzPiJoqcqmdZdjxZ9aGLnVsbYcCphidHERKBWVXyKhNqTirshTmicG"
        );
    }

    #[test]
    fn test_ledger_keygen() {
        // This private key is derived from the default seed and default path for CX_CURVE_Ed25519
        // on ledger devices
        let speculos_default_seed =
            hex::decode("781FB0E232257AE8F9471884436EBC5617E33BF9B8316C35E489052917D40055575003F3D82B18415AE90D24A70FCDE604FF27AD0D8E0FFDF10EF0C41447516D").unwrap();
        let keypair = derive_master_key(&speculos_default_seed);
        assert_eq!(
            keypair.public_key.hash().to_string(),
            "4EUr383qLuCEzejdmCigFhrsoDkHG2crGxBBFhR35zjVfzn5QdhazGb"
        );
    }
}
