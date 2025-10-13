use hmac::{Hmac, Mac};
use ibig::UBig;
use nbx_nockchain_math::crypto::cheetah::{ch_add, ch_scal_big, A_GEN, G_ORDER};
use sha2::Sha512;

use crate::cheetah::{PrivateKey, PublicKey};

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
    mac.update(&data);
    mac.finalize().into_bytes().into()
}

/// SLIP-10 Extended Key (private or public key + chain code)
#[derive(Debug, Clone)]
pub struct ExtendedKey {
    pub private_key: Option<PrivateKey>,
    pub public_key: PublicKey,
    pub chain_code: [u8; 32],
}

impl ExtendedKey {
    /// Derive a child key at the given index using SLIP-10
    pub fn derive_child(&self, index: u32) -> ExtendedKey {
        let hardened = index >= (1 << 31);

        let mut data = Vec::new();
        if hardened {
            let private_key = self
                .private_key
                .as_ref()
                .expect("Cannot derive hardened child without private key");
            data.push(0x00);
            data.extend_from_slice(&private_key.to_be_bytes());
            data.extend_from_slice(&index.to_be_bytes());
        } else {
            data.push(0x01);
            data.extend_from_slice(&self.public_key.to_slip10_bytes());
            data.extend_from_slice(&index.to_be_bytes());
        }
        let mut result = hmac_sha512(&self.chain_code, &data);

        loop {
            let left = UBig::from_be_bytes(&result[..32]);
            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&result[32..]);

            if left < *G_ORDER {
                match self.private_key.as_ref() {
                    Some(pk) => {
                        let s = (&left + &pk.0) % &*G_ORDER;
                        if s != UBig::from(0u64) {
                            let private_key = PrivateKey(s);
                            let public_key = private_key.derive_public_key();
                            return ExtendedKey {
                                private_key: Some(private_key),
                                public_key,
                                chain_code,
                            };
                        }
                    }
                    None => {
                        let mut point = ch_scal_big(&left, &A_GEN).unwrap();
                        point = ch_add(&point, &self.public_key.0).unwrap();
                        if !point.inf {
                            return ExtendedKey {
                                private_key: None,
                                public_key: PublicKey(point),
                                chain_code,
                            };
                        }
                    }
                }
            }
            // Invalid key: rehash 0x01 || right || index
            let mut data = Vec::new();
            data.push(0x01);
            data.extend_from_slice(&chain_code);
            data.extend_from_slice(&index.to_be_bytes());
            result = hmac_sha512(&self.chain_code, &data);
        }
    }
}

pub fn derive_master_key(seed: &[u8]) -> ExtendedKey {
    const DOMAIN_SEPARATOR: &[u8] = b"Nockchain seed";
    let mut result = hmac_sha512(DOMAIN_SEPARATOR, seed);
    loop {
        let s = UBig::from_be_bytes(&result[..32]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..]);
        if s < *G_ORDER && s != UBig::from(0u64) {
            let private_key = PrivateKey(s);
            let public_key = private_key.derive_public_key();
            return ExtendedKey {
                private_key: Some(private_key),
                public_key,
                chain_code,
            };
        }
        result = hmac_sha512(DOMAIN_SEPARATOR, &result[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    fn from_b58(s: &str) -> Vec<u8> {
        bs58::decode(s).into_vec().unwrap()
    }

    #[test]
    fn test_nockchain_wallet_vector() {
        // Test vectors from:
        //   nockchain-wallet keygen
        // and:
        //   nockchain-wallet derive-child 0
        //   nockchain-wallet derive-child --hardened 0
        let mnemonic = Mnemonic::parse("clutch inmate mango seek attract credit illegal popular term loyal fiber output trumpet lucky garbage merge menu certain dynamic aim trip fantasy master unveil").unwrap();
        let key = derive_master_key(&mnemonic.to_seed(""));
        assert_eq!(
            key.private_key.as_ref().unwrap().to_be_bytes().to_vec(),
            from_b58("3MoHxVXWAr9qny12Sw8ZZtrgEBFcZegQQVkwYyePb9LZ")
        );
        assert_eq!(
            key.chain_code[..],
            from_b58("3NhBRdy7vRw8vKQ5RnR3CNcD43WDn5Ky7mhhotqUcaiR")
        );

        let child_key = key.derive_child(0);
        assert_eq!(
            child_key.private_key.unwrap().to_be_bytes().to_vec(),
            from_b58("6AifHLAuT1MxnFsoCwjKNFaBze91DXFDV1rRLefkzPEK")
        );
        assert_eq!(
            child_key.chain_code[..],
            from_b58("8NL75o1uwMpGFcLRrnFt9adTyExwK9MP6RL8h2jAKEVD")
        );

        let hardened_child_key = key.derive_child(1 << 31);
        assert_eq!(
            hardened_child_key
                .private_key
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            from_b58("CpMAmcgN1V6Majtx2HC7ULLXD9psA3Gg3nMye3JpKpH")
        );
        assert_eq!(
            hardened_child_key.chain_code[..],
            from_b58("8x7zh5LQA7tsFQQ3qsPfYGgFzQkoizGhLqLK7iKTGj3R")
        );
    }
}
