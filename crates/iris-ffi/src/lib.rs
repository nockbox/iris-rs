//! Native (uniffi) bindings for the Iris wallet core.
//!
//! API-parallel to `iris-wasm`: every export mirrors a `@nockbox/iris-wasm`
//! export by name and behavior so the TypeScript adapter on React Native can
//! fulfill the `@nockbox/iris-sdk/wasm` module surface 1:1.
//!
//! Boundary convention: the workspace's tsify is configured in JSON mode, so
//! every complex type already crosses the wasm boundary as serde-JSON. Here
//! the same types cross as **JSON strings** (parsed/serialized with
//! serde_json), producing byte-identical object shapes on the JS side after
//! `JSON.parse`. Scalars and byte buffers cross natively.

mod grpc;
mod tx;

pub use grpc::*;
pub use tx::*;

use iris_crypto::cheetah::{PrivateKey as CryptoPrivateKey, PublicKey, Signature};
use iris_crypto::slip10::{derive_master_key as derive_master_key_internal, ExtendedKey};
use iris_nockchain_types::v1::{Lock, LockRoot, NockchainTx, Pkh, RawTxV1, SpendCondition};
use iris_nockchain_types::{note::Note, tx::RawTx, TxEngineSettings};
use iris_ztd::{Digest, Hashable, NounDecode, NounEncode, U256};
use serde::de::DeserializeOwned;
use serde::Serialize;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{message}")]
    Ffi { message: String },
}

impl FfiError {
    pub fn msg(message: impl Into<String>) -> Self {
        FfiError::Ffi {
            message: message.into(),
        }
    }
}

impl From<serde_json::Error> for FfiError {
    fn from(e: serde_json::Error) -> Self {
        FfiError::msg(format!("JSON error: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, FfiError>;

// ---------------------------------------------------------------------------
// JSON boundary helpers
// ---------------------------------------------------------------------------

pub(crate) fn from_json<T: DeserializeOwned>(s: &str) -> Result<T> {
    Ok(serde_json::from_str(s)?)
}

pub(crate) fn to_json<T: Serialize>(v: &T) -> Result<String> {
    Ok(serde_json::to_string(v)?)
}

/// Digests cross the wasm boundary as bare base58 strings (tsify type
/// `string`); accept/produce the same here.
pub(crate) fn digest_from_str(s: &str) -> Result<Digest> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| FfiError::msg(format!("invalid digest '{s}': {e}")))
}

pub(crate) fn digest_to_string(d: &Digest) -> String {
    d.to_string()
}

// ---------------------------------------------------------------------------
// Key derivation (mirrors iris-wasm crypto.rs)
// ---------------------------------------------------------------------------

/// Mirror of wasm `ExtendedKey` (a data record on this side; the TS adapter
/// wraps it in a class exposing `deriveChild`).
#[derive(uniffi::Record)]
pub struct FfiExtendedKey {
    pub private_key: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

impl FfiExtendedKey {
    fn from_internal(key: &ExtendedKey) -> Self {
        FfiExtendedKey {
            private_key: key.private_key.as_ref().map(|pk| pk.to_be_bytes().to_vec()),
            public_key: key.public_key.to_be_bytes().to_vec(),
            chain_code: key.chain_code.to_vec(),
        }
    }

    fn to_internal(&self) -> Result<ExtendedKey> {
        let private_key = if let Some(pk_bytes) = &self.private_key {
            if pk_bytes.len() != 32 {
                return Err(FfiError::msg("Private key must be 32 bytes"));
            }
            Some(CryptoPrivateKey(U256::from_be_slice(pk_bytes)))
        } else {
            None
        };

        if self.public_key.len() != 97 {
            return Err(FfiError::msg("Public key must be 97 bytes"));
        }
        let public_key = PublicKey::from_be_bytes(&self.public_key);

        if self.chain_code.len() != 32 {
            return Err(FfiError::msg("Chain code must be 32 bytes"));
        }
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&self.chain_code);

        Ok(ExtendedKey {
            private_key,
            public_key,
            chain_code,
        })
    }
}

/// wasm: `deriveMasterKey(seed)`
#[uniffi::export]
pub fn derive_master_key(seed: Vec<u8>) -> FfiExtendedKey {
    FfiExtendedKey::from_internal(&derive_master_key_internal(&seed))
}

/// wasm: `deriveMasterKeyFromMnemonic(mnemonic, passphrase?)`
#[uniffi::export]
pub fn derive_master_key_from_mnemonic(
    mnemonic: String,
    passphrase: Option<String>,
) -> Result<FfiExtendedKey> {
    let mnemonic = bip39::Mnemonic::parse(&mnemonic)
        .map_err(|e| FfiError::msg(format!("Invalid mnemonic: {e}")))?;
    let seed = mnemonic.to_seed(passphrase.as_deref().unwrap_or(""));
    Ok(derive_master_key(seed.to_vec()))
}

/// wasm: `ExtendedKey.deriveChild(index)`
#[uniffi::export]
pub fn derive_child(key: FfiExtendedKey, index: u32) -> Result<FfiExtendedKey> {
    let internal = key.to_internal()?;
    let child = std::thread::Builder::new()
        .name("iris-derive-child".to_string())
        .stack_size(4 * 1024 * 1024)
        .spawn(move || internal.derive_child(index))
        .map_err(|e| FfiError::msg(format!("Failed to spawn derivation thread: {e}")))?
        .join()
        .map_err(|_| FfiError::msg("Child key derivation panicked"))?;
    Ok(FfiExtendedKey::from_internal(&child))
}

/// wasm: `hashPublicKey(bytes)` -> Digest (base58 string)
#[uniffi::export]
pub fn hash_public_key(public_key_bytes: Vec<u8>) -> Result<String> {
    if public_key_bytes.len() != 97 {
        return Err(FfiError::msg("Public key must be 97 bytes"));
    }
    let public_key = PublicKey::from_be_bytes(&public_key_bytes);
    Ok(digest_to_string(&public_key.hash()))
}

/// wasm: `publicKeyFromHex(hex)` -> PublicKey JSON (or None)
#[uniffi::export]
pub fn public_key_from_hex(hex: String) -> Result<Option<String>> {
    match PublicKey::from_hex(&hex) {
        Some(pk) => Ok(Some(to_json(&pk)?)),
        None => Ok(None),
    }
}

/// wasm: `publicKeyToBeBytesVec(publicKey)` (PublicKey JSON in)
#[uniffi::export]
pub fn public_key_to_be_bytes_vec(public_key_json: String) -> Result<Vec<u8>> {
    let pk: PublicKey = from_json(&public_key_json)?;
    Ok(pk.to_be_bytes().to_vec())
}

/// wasm: `signMessage(privateKeyBytes, message)` -> Signature JSON
#[uniffi::export]
pub fn sign_message(private_key_bytes: Vec<u8>, message: String) -> Result<String> {
    use iris_ztd::Belt;
    if private_key_bytes.len() != 32 {
        return Err(FfiError::msg("Private key must be 32 bytes"));
    }
    let private_key = CryptoPrivateKey(U256::from_be_slice(&private_key_bytes));
    let digest = Belt::from_bytes(message.as_bytes()).to_noun().hash();
    to_json(&private_key.sign(&digest))
}

/// wasm: `verifySignature(publicKeyBytes, signature, message)`
#[uniffi::export]
pub fn verify_signature(
    public_key_bytes: Vec<u8>,
    signature_json: String,
    message: String,
) -> Result<bool> {
    use iris_ztd::Belt;
    if public_key_bytes.len() != 97 {
        return Err(FfiError::msg("Public key must be 97 bytes"));
    }
    let public_key = PublicKey::from_be_bytes(&public_key_bytes);
    let signature: Signature = from_json(&signature_json)?;
    let digest = Belt::from_bytes(message.as_bytes()).to_noun().hash();
    Ok(public_key.verify(&digest, &signature))
}

// ---------------------------------------------------------------------------
// Noun utilities (mirrors iris-wasm noun.rs; Noun crosses as JSON)
// ---------------------------------------------------------------------------

/// wasm: `cue(bytes)` -> Noun JSON
#[uniffi::export]
pub fn cue(jam_bytes: Vec<u8>) -> Result<String> {
    let noun = iris_ztd::cue(&jam_bytes).ok_or_else(|| FfiError::msg("unable to parse jam"))?;
    to_json(&noun)
}

/// wasm: `jam(noun)` (Noun JSON in)
#[uniffi::export]
pub fn jam(noun_json: String) -> Result<Vec<u8>> {
    let noun: iris_ztd::Noun = from_json(&noun_json)?;
    Ok(iris_ztd::jam(noun))
}

/// wasm: `tas(string)` -> Noun JSON (atom)
#[uniffi::export]
pub fn tas(s: String) -> Result<String> {
    let a = ibig::UBig::from_le_bytes(s.as_bytes());
    to_json(&iris_ztd::Noun::Atom(a))
}

/// wasm: `untas(noun)` -> string
#[uniffi::export]
pub fn untas(noun_json: String) -> Result<String> {
    let noun: iris_ztd::Noun = from_json(&noun_json)?;
    match noun {
        iris_ztd::Noun::Atom(atom) => {
            String::from_utf8(atom.to_le_bytes()).map_err(|_| FfiError::msg("not valid utf8"))
        }
        _ => Err(FfiError::msg("not an atom")),
    }
}

/// wasm: `atomToBelts(noun)` -> Noun JSON
#[uniffi::export]
pub fn atom_to_belts(noun_json: String) -> Result<String> {
    let noun: iris_ztd::Noun = from_json(&noun_json)?;
    match noun {
        iris_ztd::Noun::Atom(atom) => {
            to_json(&iris_ztd::BeltSeq(iris_ztd::belts_from_ubig(atom)).to_noun())
        }
        _ => Err(FfiError::msg("not an atom")),
    }
}

/// wasm: `beltsToAtom(noun)` -> Noun JSON
#[uniffi::export]
pub fn belts_to_atom(noun_json: String) -> Result<String> {
    let noun: iris_ztd::Noun = from_json(&noun_json)?;
    let iris_ztd::BeltSeq(belts) =
        NounDecode::from_noun(&noun).ok_or_else(|| FfiError::msg("unable to parse belts"))?;
    to_json(&iris_ztd::Noun::Atom(iris_ztd::belts_to_ubig(&belts)))
}

// ---------------------------------------------------------------------------
// Type helpers used by the extension TS layer (lock/spend-condition/note/tx).
// In iris-wasm these are macro-generated exports; here they are explicit.
// ---------------------------------------------------------------------------

/// wasm: `lockHash(lock)` -> Digest
#[uniffi::export]
pub fn lock_hash(lock_json: String) -> Result<String> {
    let lock: Lock = from_json(&lock_json)?;
    Ok(digest_to_string(&lock.hash()))
}

/// wasm: `lockRootHash(lockRoot)` -> Digest
#[uniffi::export]
pub fn lock_root_hash(lock_root_json: String) -> Result<String> {
    let lock_root: LockRoot = from_json(&lock_root_json)?;
    Ok(digest_to_string(&lock_root.hash()))
}

/// wasm: `noteHash(note)` -> Digest
#[uniffi::export]
pub fn note_hash(note_json: String) -> Result<String> {
    let note: Note = from_json(&note_json)?;
    Ok(digest_to_string(&note.hash()))
}

/// wasm: `pkhNew(m, hashes)` -> Pkh JSON
#[uniffi::export]
pub fn pkh_new(m: u64, hashes: Vec<String>) -> Result<String> {
    let digests = hashes
        .iter()
        .map(|h| digest_from_str(h))
        .collect::<Result<Vec<Digest>>>()?;
    to_json(&Pkh::new(m, digests))
}

/// wasm: `pkhSingle(hash)` -> Pkh JSON
#[uniffi::export]
pub fn pkh_single(hash: String) -> Result<String> {
    to_json(&Pkh::single(digest_from_str(&hash)?))
}

/// wasm: `spendConditionNewPkh(pkh)` -> SpendCondition JSON
#[uniffi::export]
pub fn spend_condition_new_pkh(pkh_json: String) -> Result<String> {
    let pkh: Pkh = from_json(&pkh_json)?;
    to_json(&SpendCondition::new_pkh(pkh))
}

/// wasm: `spendConditionHash(sc)` -> Digest
#[uniffi::export]
pub fn spend_condition_hash(spend_condition_json: String) -> Result<String> {
    let sc: SpendCondition = from_json(&spend_condition_json)?;
    Ok(digest_to_string(&sc.hash()))
}

/// wasm: `spendConditionFirstName(sc)` -> Digest
#[uniffi::export]
pub fn spend_condition_first_name(spend_condition_json: String) -> Result<String> {
    let sc: SpendCondition = from_json(&spend_condition_json)?;
    Ok(digest_to_string(&sc.first_name()))
}

/// wasm: `noteToProtobuf(note)` -> PbCom2Note JSON
#[uniffi::export]
pub fn note_to_protobuf(note_json: String) -> Result<String> {
    let note: Note = from_json(&note_json)?;
    let pb: iris_grpc_proto::pb::common::v2::Note = note.into();
    to_json(&pb)
}

/// wasm: `noteFromProtobuf(pbNote)` -> Note JSON
#[uniffi::export]
pub fn note_from_protobuf(pb_note_json: String) -> Result<String> {
    let pb: iris_grpc_proto::pb::common::v2::Note = from_json(&pb_note_json)?;
    let note: Note = pb.try_into().map_err(|e| FfiError::msg(format!("{e}")))?;
    to_json(&note)
}

/// wasm: `spendConditionToProtobuf(sc)` -> pb SpendCondition JSON
#[uniffi::export]
pub fn spend_condition_to_protobuf(spend_condition_json: String) -> Result<String> {
    let sc: SpendCondition = from_json(&spend_condition_json)?;
    let pb: iris_grpc_proto::pb::common::v2::SpendCondition = sc.into();
    to_json(&pb)
}

/// wasm: `spendConditionFromProtobuf(pb)` -> SpendCondition JSON
#[uniffi::export]
pub fn spend_condition_from_protobuf(pb_json: String) -> Result<String> {
    let pb: iris_grpc_proto::pb::common::v2::SpendCondition = from_json(&pb_json)?;
    let sc: SpendCondition = pb.try_into().map_err(|e| FfiError::msg(format!("{e}")))?;
    to_json(&sc)
}

/// wasm: `rawTxToProtobuf(rawTxV1)` -> pb RawTransaction JSON
#[uniffi::export]
pub fn raw_tx_to_protobuf(raw_tx_v1_json: String) -> Result<String> {
    let tx: RawTxV1 = from_json(&raw_tx_v1_json)?;
    let pb: iris_grpc_proto::pb::common::v2::RawTransaction = tx.into();
    to_json(&pb)
}

/// wasm: `rawTxFromProtobuf(pb)` -> RawTx JSON
#[uniffi::export]
pub fn raw_tx_from_protobuf(pb_json: String) -> Result<String> {
    let pb: iris_grpc_proto::pb::common::v2::RawTransaction = from_json(&pb_json)?;
    let tx: RawTx = pb.try_into().map_err(|e| FfiError::msg(format!("{e}")))?;
    to_json(&tx)
}

/// wasm: `nockchainTxToRawTx(tx)` -> RawTxV1 JSON
#[uniffi::export]
pub fn nockchain_tx_to_raw_tx(nockchain_tx_json: String) -> Result<String> {
    let tx: NockchainTx = from_json(&nockchain_tx_json)?;
    to_json(&tx.to_raw_tx())
}

/// wasm: `rawTxV1ToNockchainTx(tx)` -> NockchainTx JSON
#[uniffi::export]
pub fn raw_tx_v1_to_nockchain_tx(raw_tx_v1_json: String) -> Result<String> {
    let tx: RawTxV1 = from_json(&raw_tx_v1_json)?;
    to_json(&tx.to_nockchain_tx())
}

/// wasm: `rawTxOutputs(tx, blockHeight, settings)` -> Note[] JSON
#[uniffi::export]
pub fn raw_tx_outputs(
    raw_tx_json: String,
    block_height: u32,
    tx_engine_settings_json: String,
) -> Result<String> {
    let tx: RawTx = from_json(&raw_tx_json)?;
    let settings: TxEngineSettings = from_json(&tx_engine_settings_json)?;
    to_json(&tx.outputs(block_height, settings))
}

/// wasm: `rawTxV1Outputs(tx, originPage, settings)` -> NoteV1[] JSON
#[uniffi::export]
pub fn raw_tx_v1_outputs(
    raw_tx_v1_json: String,
    origin_page: u32,
    tx_engine_settings_json: String,
) -> Result<String> {
    let tx: RawTxV1 = from_json(&raw_tx_v1_json)?;
    let settings: TxEngineSettings = from_json(&tx_engine_settings_json)?;
    to_json(&tx.outputs(origin_page, settings))
}

/// wasm: `txEngineSettingsV1Default()` -> TxEngineSettings JSON
#[uniffi::export]
pub fn tx_engine_settings_v1_default() -> Result<String> {
    to_json(&TxEngineSettings::v1_default())
}

/// wasm: `txEngineSettingsV1BythosDefault()` -> TxEngineSettings JSON
#[uniffi::export]
pub fn tx_engine_settings_v1_bythos_default() -> Result<String> {
    to_json(&TxEngineSettings::v1_bythos_default())
}

/// wasm: `digestToProtobuf(digest)` -> pb Hash JSON
#[uniffi::export]
pub fn digest_to_protobuf(digest: String) -> Result<String> {
    let d = digest_from_str(&digest)?;
    let pb: iris_grpc_proto::pb::common::v1::Hash = d.into();
    to_json(&pb)
}

/// wasm: `digestFromProtobuf(pbHash)` -> Digest (base58 string)
#[uniffi::export]
pub fn digest_from_protobuf(pb_hash_json: String) -> Result<String> {
    let pb: iris_grpc_proto::pb::common::v1::Hash = from_json(&pb_hash_json)?;
    let d: Digest = pb.try_into().map_err(|e| FfiError::msg(format!("{e:?}")))?;
    Ok(digest_to_string(&d))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors from crates/iris-crypto tests (same as the iris-mobile
    // jest suite — the FFI-parity gate).
    const GOLDEN_MNEMONIC: &str = "pass destroy hub reject cricket flight camp garden scale liquid increase pool miracle fly tower file door cage vault tone night zero push crime";
    const GOLDEN_PKH: &str = "AyzPiJoqcqmdZdjxZ9aGLnVsbYcCphidHERKBWVXyKhNqTirshTmicG";
    const GOLDEN_PRIVATE_KEY_HEX: &str =
        "362b4073814e43f427983a83f11efcceb6741082c18f0d64b7e47340ba4485ba";
    const GOLDEN_CHAIN_CODE_HEX: &str =
        "95b522320f4dfae7486155b9529c582af3d7898ece606a802c43415786ced8d9";
    const LEDGER_SEED_HEX: &str = "781FB0E232257AE8F9471884436EBC5617E33BF9B8316C35E489052917D40055575003F3D82B18415AE90D24A70FCDE604FF27AD0D8E0FFDF10EF0C41447516D";
    const LEDGER_PKH: &str = "4EUr383qLuCEzejdmCigFhrsoDkHG2crGxBBFhR35zjVfzn5QdhazGb";

    #[test]
    fn golden_master_key_from_mnemonic() {
        let key = derive_master_key_from_mnemonic(GOLDEN_MNEMONIC.into(), None).unwrap();
        assert_eq!(
            hex::encode(key.private_key.as_ref().unwrap()),
            GOLDEN_PRIVATE_KEY_HEX
        );
        assert_eq!(hex::encode(&key.chain_code), GOLDEN_CHAIN_CODE_HEX);
        assert_eq!(hash_public_key(key.public_key).unwrap(), GOLDEN_PKH);
    }

    #[test]
    fn golden_master_key_from_seed() {
        let key = derive_master_key(hex::decode(LEDGER_SEED_HEX).unwrap());
        assert_eq!(hash_public_key(key.public_key).unwrap(), LEDGER_PKH);
    }

    #[test]
    fn derive_child_is_deterministic_and_distinct() {
        let master = derive_master_key_from_mnemonic(GOLDEN_MNEMONIC.into(), None).unwrap();
        let clone = derive_master_key_from_mnemonic(GOLDEN_MNEMONIC.into(), None).unwrap();
        let child1 = derive_child(master, 1).unwrap();
        let child1b = derive_child(clone, 1).unwrap();
        assert_eq!(child1.public_key, child1b.public_key);
        assert_ne!(
            hash_public_key(child1.public_key.clone()).unwrap(),
            GOLDEN_PKH
        );
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = derive_master_key_from_mnemonic(GOLDEN_MNEMONIC.into(), None).unwrap();
        let signature =
            sign_message(key.private_key.clone().unwrap(), "hello nockchain".into()).unwrap();
        assert!(verify_signature(
            key.public_key.clone(),
            signature.clone(),
            "hello nockchain".into()
        )
        .unwrap());
        assert!(!verify_signature(key.public_key.clone(), signature, "tampered".into()).unwrap());
    }

    #[test]
    fn tas_untas_round_trip() {
        let metadata = "base:84532:0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let noun = tas(metadata.into()).unwrap();
        assert_eq!(untas(noun).unwrap(), metadata);
    }

    #[test]
    fn atom_belts_round_trip_through_json_boundary() {
        // This is the round-trip that is broken in published iris-wasm 0.2.0
        // (fixed on main, d3a8806). The FFI must keep it working.
        let metadata = "base:84532:0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let atom = tas(metadata.into()).unwrap();
        let belts = atom_to_belts(atom.clone()).unwrap();
        let back = belts_to_atom(belts).unwrap();
        assert_eq!(untas(back).unwrap(), metadata);
    }

    #[test]
    fn jam_cue_round_trip() {
        let noun = tas("hello".into()).unwrap();
        let jammed = jam(noun.clone()).unwrap();
        let cued = cue(jammed).unwrap();
        assert_eq!(cued, noun);
    }

    #[test]
    fn pkh_and_spend_condition_first_name() {
        let pkh = pkh_single(GOLDEN_PKH.into()).unwrap();
        let sc = spend_condition_new_pkh(pkh).unwrap();
        // first_name and hash must be valid digests (base58 strings)
        let first = spend_condition_first_name(sc.clone()).unwrap();
        let hash = spend_condition_hash(sc).unwrap();
        assert!(digest_from_str(&first).is_ok());
        assert!(digest_from_str(&hash).is_ok());
    }

    #[test]
    fn tx_engine_settings_shapes() {
        let v1: serde_json::Value =
            serde_json::from_str(&tx_engine_settings_v1_default().unwrap()).unwrap();
        assert_eq!(v1["tx_engine_version"], 1);
        let bythos: serde_json::Value =
            serde_json::from_str(&tx_engine_settings_v1_bythos_default().unwrap()).unwrap();
        assert_eq!(bythos["tx_engine_patch"], 1);
    }

    #[test]
    fn digest_protobuf_round_trip() {
        let pb = digest_to_protobuf(GOLDEN_PKH.into()).unwrap();
        let back = digest_from_protobuf(pb).unwrap();
        assert_eq!(back, GOLDEN_PKH);
    }
}
