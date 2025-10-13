use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::cheetah::{PrivateKey, PublicKey};
use crate::slip10::{derive_master_key as derive_master_key_internal, ExtendedKey};

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct WasmExtendedKey {
    #[wasm_bindgen(skip)]
    pub private_key: Option<Vec<u8>>,
    #[wasm_bindgen(skip)]
    pub public_key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub chain_code: Vec<u8>,
}

#[wasm_bindgen]
impl WasmExtendedKey {
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Option<Vec<u8>> {
        self.private_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn chain_code(&self) -> Vec<u8> {
        self.chain_code.clone()
    }

    /// Derive a child key at the given index
    #[wasm_bindgen(js_name = deriveChild)]
    pub fn derive_child(&self, index: u32) -> Result<WasmExtendedKey, JsValue> {
        let extended_key = self.to_internal().map_err(|e| JsValue::from_str(&e))?;

        let child = extended_key.derive_child(index);
        Ok(WasmExtendedKey::from_internal(&child))
    }

    fn to_internal(&self) -> Result<ExtendedKey, String> {
        let private_key = if let Some(pk_bytes) = &self.private_key {
            if pk_bytes.len() != 32 {
                return Err("Private key must be 32 bytes".to_string());
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(pk_bytes);
            Some(PrivateKey::from_be_bytes(&bytes))
        } else {
            None
        };

        if self.public_key.len() != 97 {
            return Err("Public key must be 97 bytes".to_string());
        }
        let mut pub_bytes = [0u8; 97];
        pub_bytes.copy_from_slice(&self.public_key);
        let public_key = PublicKey::from_be_bytes(&pub_bytes);

        if self.chain_code.len() != 32 {
            return Err("Chain code must be 32 bytes".to_string());
        }
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&self.chain_code);

        Ok(ExtendedKey {
            private_key,
            public_key,
            chain_code,
        })
    }

    fn from_internal(key: &ExtendedKey) -> Self {
        WasmExtendedKey {
            private_key: key.private_key.as_ref().map(|pk| pk.to_be_bytes().to_vec()),
            public_key: key.public_key.to_be_bytes().to_vec(),
            chain_code: key.chain_code.to_vec(),
        }
    }
}

/// Derive master key from seed bytes
#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(seed: &[u8]) -> WasmExtendedKey {
    let key = derive_master_key_internal(seed);
    WasmExtendedKey::from_internal(&key)
}

/// Derive master key from BIP39 mnemonic phrase
#[wasm_bindgen(js_name = deriveMasterKeyFromMnemonic)]
pub fn derive_master_key_from_mnemonic(
    mnemonic: &str,
    passphrase: Option<String>,
) -> Result<WasmExtendedKey, JsValue> {
    use bip39::Mnemonic;

    let mnemonic = Mnemonic::parse(mnemonic)
        .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {}", e)))?;

    let seed = mnemonic.to_seed(passphrase.as_deref().unwrap_or(""));
    Ok(derive_master_key(&seed))
}
