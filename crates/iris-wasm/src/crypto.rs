use iris_ztd::U256;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use iris_crypto::cheetah::{PrivateKey, PublicKey, Signature};
use iris_crypto::slip10::{derive_master_key as derive_master_key_internal, ExtendedKey};

#[wasm_bindgen(js_name = Signature)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmSignature {
    #[wasm_bindgen(skip)]
    pub c: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub s: Vec<u8>,
}

#[wasm_bindgen(js_class = Signature)]
impl WasmSignature {
    #[wasm_bindgen(constructor)]
    pub fn new(c: Vec<u8>, s: Vec<u8>) -> Self {
        Self { c, s }
    }

    #[wasm_bindgen(getter)]
    pub fn c(&self) -> Vec<u8> {
        self.c.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn s(&self) -> Vec<u8> {
        self.s.clone()
    }

    fn from_internal(sig: &Signature) -> Self {
        Self {
            c: sig.c.to_be_bytes().to_vec(),
            s: sig.s.to_be_bytes().to_vec(),
        }
    }

    fn to_internal(&self) -> Signature {
        Signature {
            c: U256::from_be_slice(&self.c),
            s: U256::from_be_slice(&self.s),
        }
    }
}

#[wasm_bindgen(js_name = ExtendedKey)]
#[derive(Serialize, Deserialize)]
pub struct WasmExtendedKey {
    #[wasm_bindgen(skip)]
    pub private_key: Option<Vec<u8>>,
    #[wasm_bindgen(skip)]
    pub public_key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub chain_code: Vec<u8>,
}

#[wasm_bindgen(js_class = ExtendedKey)]
impl WasmExtendedKey {
    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> Option<Vec<u8>> {
        self.private_key.clone()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = chainCode)]
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
            Some(PrivateKey(U256::from_be_slice(pk_bytes)))
        } else {
            None
        };

        if self.public_key.len() != 97 {
            return Err("Public key must be 97 bytes".to_string());
        }
        let mut pub_bytes = [0u8; 97];
        pub_bytes.copy_from_slice(&self.public_key);
        let public_key = PublicKey::from_be_bytes(&self.public_key);

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

/// Hash a public key to get its digest (for use in PKH)
#[wasm_bindgen(js_name = hashPublicKey)]
pub fn hash_public_key(public_key_bytes: &[u8]) -> Result<String, JsValue> {
    use iris_ztd::Hashable;

    if public_key_bytes.len() != 97 {
        return Err(JsValue::from_str("Public key must be 97 bytes"));
    }

    let mut pub_bytes = [0u8; 97];
    pub_bytes.copy_from_slice(public_key_bytes);
    let public_key = PublicKey::from_be_bytes(&pub_bytes);

    let digest = public_key.hash();
    Ok(digest.to_string())
}

/// Hash a u64 value
#[wasm_bindgen(js_name = hashU64)]
pub fn hash_u64(value: u64) -> String {
    use iris_ztd::Hashable;
    let digest = value.hash();
    digest.to_string()
}

/// Hash a noun (jam as input)
#[wasm_bindgen(js_name = hashNoun)]
pub fn hash_noun(noun: &[u8]) -> Result<String, JsValue> {
    use iris_ztd::{cue, Hashable};
    let noun = cue(noun).ok_or("Unable to cue noun")?;
    let digest = noun.hash();
    Ok(digest.to_string())
}

/// Sign a message string with a private key
#[wasm_bindgen(js_name = signMessage)]
pub fn sign_message(private_key_bytes: &[u8], message: &str) -> Result<WasmSignature, JsValue> {
    use iris_ztd::{Belt, Hashable, NounEncode};
    if private_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }
    let private_key = PrivateKey(U256::from_be_slice(private_key_bytes));
    let digest = Belt::from_bytes(message.as_bytes()).to_noun().hash();
    Ok(WasmSignature::from_internal(&private_key.sign(&digest)))
}

/// Verify a signature with a public key
#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(
    public_key_bytes: &[u8],
    signature: &WasmSignature,
    message: &str,
) -> Result<bool, JsValue> {
    use iris_ztd::{Belt, Hashable, NounEncode};
    if public_key_bytes.len() != 97 {
        return Err(JsValue::from_str("Public key must be 97 bytes"));
    }
    let mut pub_bytes = [0u8; 97];
    pub_bytes.copy_from_slice(public_key_bytes);
    let public_key = PublicKey::from_be_bytes(&pub_bytes);
    let digest = Belt::from_bytes(message.as_bytes()).to_noun().hash();
    Ok(public_key.verify(&digest, &signature.to_internal()))
}
