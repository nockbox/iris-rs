use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::collections::BTreeMap;

use iris_crypto::PrivateKey as CryptoPrivateKey;
use iris_grpc_proto::pb::common::v1 as pb_v1;
use iris_grpc_proto::pb::common::v2 as pb;
use iris_nockchain_types::{
    builder::{MissingUnlocks, TxBuilder},
    note::{Name, Note, Version},
    tx::RawTx,
    v0,
    v1::{self, NockchainTx, NoteData, RawTxV1, SeedV1 as Seed, SpendCondition},
    BlockHeight, Nicks, Source, SpendBuilder, TxEngineSettings,
};
use iris_ztd::{cue, Digest, ZSet, U256};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ============================================================================
// Wasm Types - Adapters and Helpers
// ============================================================================

#[wasm_bindgen]
pub fn digest_to_hex(d: Digest) -> String {
    d.to_string()
}

#[wasm_bindgen]
pub fn hex_to_digest(s: &str) -> Result<Digest, JsValue> {
    s.try_into().map_err(|e: &str| JsValue::from_str(e))
}

#[wasm_bindgen]
pub fn digest_to_protobuf(d: Digest) -> pb_v1::Hash {
    d.into()
}

#[wasm_bindgen]
pub fn digest_from_protobuf(value: pb_v1::Hash) -> Result<Digest, JsValue> {
    value
        .try_into()
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
}

#[wasm_bindgen]
pub fn note_hash(note: Note) -> Digest {
    use iris_ztd::Hashable;
    note.hash()
}

/// Return default transaction engine settings for V1 signing.
#[wasm_bindgen(js_name = txEngineSettingsV1Default)]
pub fn tx_engine_settings_v1_default() -> TxEngineSettings {
    TxEngineSettings::v1_default()
}

/// Return default transaction engine settings for V1 Bythos signing.
#[wasm_bindgen(js_name = txEngineSettingsV1BythosDefault)]
pub fn tx_engine_settings_v1_bythos_default() -> TxEngineSettings {
    TxEngineSettings::v1_bythos_default()
}

#[wasm_bindgen]
pub fn note_to_protobuf(note: Note) -> pb::Note {
    note.into()
}

#[wasm_bindgen]
pub fn note_from_protobuf(value: pb::Note) -> Result<Note, JsValue> {
    value
        .try_into()
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
}

/// Convert NockchainTx into RawTx by recombining witness_data with the transaction, and
/// recalculating the transaction ID.
#[wasm_bindgen(js_name = nockchainTxToRaw)]
pub fn nockchain_tx_to_raw(tx: NockchainTx) -> RawTx {
    RawTx::V1(tx.to_raw_tx())
}

/// Lossily convert raw transaction into a nockchain transaction, splitting witness away.
#[wasm_bindgen(js_name = rawTxToNockchainTx)]
pub fn raw_tx_to_nockchain_tx(tx: RawTxV1) -> NockchainTx {
    tx.to_nockchain_tx()
}

/// Convert raw transaction into protobuf format.
///
/// Protobuf format is the one used by the Nockchain's gRPC interface, and the initial iris
/// extension format. The new iris transaction signing API moves away from this format to use
/// `NockchainTx`, as it includes the necessary spend condition and note information.
#[wasm_bindgen(js_name = rawTxToProtobuf)]
pub fn raw_tx_to_protobuf(tx: RawTxV1) -> pb::RawTransaction {
    tx.into()
}

#[wasm_bindgen(js_name = rawTxFromProtobuf)]
pub fn raw_tx_from_protobuf(tx: pb::RawTransaction) -> Result<RawTx, JsValue> {
    tx.try_into()
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
}

#[wasm_bindgen(js_name = rawTxOutputs)]
pub fn raw_tx_outputs(tx: RawTx) -> Vec<Note> {
    tx.outputs()
}

// Helper to create V1 note
#[wasm_bindgen]
pub fn create_note_v1(
    version: Version,
    origin_page: BlockHeight,
    name: Name,
    note_data: NoteData,
    assets: Nicks,
) -> Result<Note, JsValue> {
    let internal = Note::V1(v1::NoteV1::new(
        version,
        origin_page,
        name,
        note_data,
        assets,
    ));
    Ok(internal)
}

// Helper to create V0 note
#[wasm_bindgen]
pub fn create_note_v0(
    origin_page: BlockHeight,
    sig_m: u64,
    sig_pubkeys: Vec<js_sys::Uint8Array>,
    source_hash: Digest,
    is_coinbase: bool,
    timelock: Option<v0::Timelock>,
    assets: Nicks,
) -> Result<Note, JsValue> {
    use iris_crypto::PublicKey;
    // use iris_ztd::Hashable; // import Hashable trait if needed? No, Name::new_v0 needs traits probably.

    // Parse public keys from byte arrays
    let pubkeys: Result<ZSet<PublicKey>, JsValue> = sig_pubkeys
        .iter()
        .map(|arr| {
            let bytes = arr.to_vec();
            if bytes.len() != 97 {
                return Err(JsValue::from_str(&format!(
                    "Public key must be 97 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 97];
            arr.copy_from_slice(&bytes);
            Ok(PublicKey::from_be_bytes(&arr))
        })
        .collect();
    let pubkeys = pubkeys?;

    let sig = v0::Sig { m: sig_m, pubkeys };

    let source = Source {
        hash: source_hash,
        is_coinbase,
    };

    let timelock_intent = v0::TimelockIntent { tim: timelock };

    let name = Name::new_v0(sig.clone(), source, timelock_intent);

    let internal = Note::V0(v0::NoteV0::new(
        Version::V0,
        origin_page,
        timelock_intent,
        name,
        sig,
        source,
        assets,
    ));
    Ok(internal)
}

#[derive(Serialize, Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct TxNotes {
    pub notes: Vec<Note>,
    pub spend_conditions: Vec<SpendCondition>,
}

// ============================================================================
// Wasm Transaction Builder
// ============================================================================

enum PrivateKeyBackend {
    Bytes(BytesPrivateKeyBackend),
}

struct BytesPrivateKeyBackend {
    signing_key: CryptoPrivateKey,
    public_key_bytes: [u8; 97],
}

#[wasm_bindgen(js_name = PrivateKey)]
pub struct WasmPrivateKey {
    backend: PrivateKeyBackend,
}

#[wasm_bindgen(js_class = PrivateKey)]
impl WasmPrivateKey {
    /// Construct a wasm `PrivateKey` from 32-byte private key material.
    ///
    /// This object is created in JavaScript and then passed into Rust signing APIs.
    ///
    /// # JavaScript example
    ///
    /// ```javascript
    /// import init, { PrivateKey, TxBuilder } from "iris-wasm";
    ///
    /// await init();
    ///
    /// const keyBytes = Uint8Array.from([
    ///   // 32 bytes
    /// ]);
    ///
    /// const key = PrivateKey.fromBytes(keyBytes);
    ///
    /// const builder = new TxBuilder(settings);
    /// // ... configure builder ...
    /// await builder.sign(key);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(signing_key_bytes: &[u8]) -> Result<Self, JsValue> {
        Self::from_bytes(signing_key_bytes)
    }

    /// Construct a bytes-backed key.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(signing_key_bytes: &[u8]) -> Result<Self, JsValue> {
        if signing_key_bytes.len() != 32 {
            return Err(JsValue::from_str("Private key must be 32 bytes"));
        }

        let signing_key = CryptoPrivateKey(U256::from_be_slice(signing_key_bytes));
        let public_key_bytes = signing_key.public_key().to_be_bytes();

        Ok(Self {
            backend: PrivateKeyBackend::Bytes(BytesPrivateKeyBackend {
                signing_key,
                public_key_bytes,
            }),
        })
    }

    /// Return this key's public key as 97-byte uncompressed bytes.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        match &self.backend {
            PrivateKeyBackend::Bytes(bytes_backend) => bytes_backend.public_key_bytes.to_vec(),
        }
    }

    /// Return the derivation path for this key backend, if available.
    ///
    /// Bytes-backed keys return `undefined` in JavaScript.
    #[wasm_bindgen(getter, js_name = derivationPath)]
    pub fn derivation_path(&self) -> Option<String> {
        match &self.backend {
            PrivateKeyBackend::Bytes(_) => None,
        }
    }

    /// Return the backend kind for debugging and feature checks.
    #[wasm_bindgen(js_name = backendKind)]
    pub fn backend_kind(&self) -> String {
        match &self.backend {
            PrivateKeyBackend::Bytes(_) => "bytes".to_string(),
        }
    }
}

impl WasmPrivateKey {
    fn signing_key(&self) -> &CryptoPrivateKey {
        match &self.backend {
            PrivateKeyBackend::Bytes(bytes_backend) => &bytes_backend.signing_key,
        }
    }
}

#[wasm_bindgen(js_name = TxBuilder)]
pub struct WasmTxBuilder {
    builder: TxBuilder,
}

#[wasm_bindgen(js_class = TxBuilder)]
impl WasmTxBuilder {
    /// Create an empty transaction builder
    #[wasm_bindgen(constructor)]
    pub fn new(settings: TxEngineSettings) -> Self {
        Self {
            builder: TxBuilder::new(settings),
        }
    }

    /// Reconstruct a builder from raw transaction and its input notes.
    #[wasm_bindgen(js_name = fromTx)]
    pub fn from_tx(
        tx: RawTx,
        notes: Vec<Note>,
        spend_conditions: Vec<SpendCondition>,
        settings: TxEngineSettings,
    ) -> Result<Self, JsValue> {
        if notes.len() != spend_conditions.len() {
            return Err(JsValue::from_str(
                "notes and spend_conditions must have the same length",
            ));
        }

        let internal_notes: Result<BTreeMap<Name, (Note, Option<SpendCondition>)>, String> = notes
            .into_iter()
            .zip(spend_conditions)
            .map(|(n, sc)| Ok((n.name(), (n, Some(sc)))))
            .collect();
        let internal_notes = internal_notes.map_err(|e| JsValue::from_str(&e))?;

        let builder =
            TxBuilder::from_tx(tx, internal_notes, settings).map_err(|e| e.to_string())?;

        Ok(Self { builder })
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = simpleSpend)]
    pub fn simple_spend(
        &mut self,
        notes: Vec<Note>,
        spend_conditions: Vec<SpendCondition>,
        recipient: Digest,
        gift: Nicks,
        fee_override: Option<Nicks>,
        refund_pkh: Digest,
        include_lock_data: bool,
    ) -> Result<(), JsValue> {
        if notes.len() != spend_conditions.len() {
            return Err(JsValue::from_str(
                "notes and spend_conditions must have the same length",
            ));
        }

        let internal_notes: Vec<(Note, Option<SpendCondition>)> = notes
            .into_iter()
            .zip(spend_conditions)
            .map(|(n, sc)| (n, Some(sc)))
            .collect();

        self.builder
            .simple_spend_base(
                internal_notes,
                recipient,
                gift,
                refund_pkh,
                include_lock_data,
            )
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

        if let Some(fee) = fee_override {
            self.builder
                .set_fee_and_balance_refund(fee, false, include_lock_data)
        } else {
            self.builder.recalc_and_set_fee(include_lock_data)
        }
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

        Ok(())
    }

    /// Append a `SpendBuilder` to this transaction
    pub fn spend(&mut self, spend: WasmSpendBuilder) -> Option<WasmSpendBuilder> {
        self.builder.spend(spend.into()).map(|v| v.into())
    }

    #[wasm_bindgen(js_name = setFeeAndBalanceRefund)]
    pub fn set_fee_and_balance_refund(
        &mut self,
        fee: Nicks,
        adjust_fee: bool,
        include_lock_data: bool,
    ) -> Result<(), JsValue> {
        self.builder
            .set_fee_and_balance_refund(fee, adjust_fee, include_lock_data)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[wasm_bindgen(js_name = recalcAndSetFee)]
    pub fn recalc_and_set_fee(&mut self, include_lock_data: bool) -> Result<(), JsValue> {
        self.builder
            .recalc_and_set_fee(include_lock_data)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[wasm_bindgen(js_name = addPreimage)]
    pub fn add_preimage(&mut self, preimage_jam: &[u8]) -> Result<Option<Digest>, JsValue> {
        let preimage = cue(preimage_jam).ok_or("Unable to cue preimage jam")?;
        Ok(self.builder.add_preimage(preimage))
    }

    #[wasm_bindgen]
    pub async fn sign(&mut self, signing_key: &WasmPrivateKey) -> Result<(), JsValue> {
        self.builder.sign(signing_key.signing_key());

        Ok(())
    }

    #[wasm_bindgen]
    pub fn validate(&mut self) -> Result<(), JsValue> {
        self.builder
            .validate()
            .map_err(|v| JsValue::from_str(&v.to_string()))?;

        Ok(())
    }

    #[wasm_bindgen(js_name = curFee)]
    pub fn cur_fee(&self) -> Nicks {
        self.builder.cur_fee()
    }

    #[wasm_bindgen(js_name = calcFee)]
    pub fn calc_fee(&self) -> Nicks {
        self.builder.calc_fee()
    }

    #[wasm_bindgen(js_name = allNotes)]
    pub fn all_notes(&self) -> Result<TxNotes, JsValue> {
        let mut ret = TxNotes {
            notes: vec![],
            spend_conditions: vec![],
        };
        for (note, spend_condition) in self.builder.all_notes().into_values() {
            ret.notes.push(note);
            if let Some(sc) = spend_condition {
                ret.spend_conditions.push(sc);
            }
        }
        Ok(ret)
    }

    #[wasm_bindgen]
    pub fn build(&self) -> Result<NockchainTx, JsValue> {
        Ok(self.builder.build())
    }

    #[wasm_bindgen(js_name = allSpends)]
    pub fn all_spends(&self) -> Vec<WasmSpendBuilder> {
        self.builder
            .all_spends()
            .values()
            .map(WasmSpendBuilder::from_internal)
            .collect()
    }
}

// ============================================================================
// Wasm Spend Builder
// ============================================================================

#[wasm_bindgen(js_name = SpendBuilder)]
pub struct WasmSpendBuilder {
    builder: SpendBuilder,
}

#[wasm_bindgen(js_class = SpendBuilder)]
impl WasmSpendBuilder {
    /// Create a new `SpendBuilder` with a given note and spend condition
    #[wasm_bindgen(constructor)]
    pub fn new(
        note: Note,
        spend_condition: Option<SpendCondition>,
        refund_lock: Option<SpendCondition>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            builder: SpendBuilder::new(note, spend_condition, refund_lock)
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
        })
    }

    pub fn fee(&mut self, fee: Nicks) {
        self.builder.fee(fee);
    }

    #[wasm_bindgen(js_name = computeRefund)]
    pub fn compute_refund(&mut self, include_lock_data: bool) {
        self.builder.compute_refund(include_lock_data);
    }

    #[wasm_bindgen(js_name = curRefund)]
    pub fn cur_refund(&self) -> Option<Seed> {
        self.builder.cur_refund().cloned()
    }

    #[wasm_bindgen(js_name = isBalanced)]
    pub fn is_balanced(&self) -> bool {
        self.builder.is_balanced()
    }

    pub fn seed(&mut self, seed: Seed) -> Result<(), JsValue> {
        self.builder.seed(seed);
        Ok(())
    }

    #[wasm_bindgen(js_name = invalidateSigs)]
    pub fn invalidate_sigs(&mut self) {
        self.builder.invalidate_sigs();
    }

    #[wasm_bindgen(js_name = missingUnlocks)]
    pub fn missing_unlocks(&self) -> Result<Vec<MissingUnlocks>, JsValue> {
        // MissingUnlocks is now Tsify, so we can return Vec<MissingUnlocks>
        Ok(self.builder.missing_unlocks())
    }

    #[wasm_bindgen(js_name = addPreimage)]
    pub fn add_preimage(&mut self, preimage_jam: &[u8]) -> Result<Option<Digest>, JsValue> {
        let preimage = cue(preimage_jam).ok_or("Unable to cue preimage jam")?;
        Ok(self.builder.add_preimage(preimage))
    }

    pub async fn sign(&mut self, signing_key: &WasmPrivateKey) -> Result<bool, JsValue> {
        Ok(self.builder.sign(signing_key.signing_key()))
    }

    fn from_internal(internal: &SpendBuilder) -> Self {
        Self {
            builder: internal.clone(),
        }
    }
}

impl From<SpendBuilder> for WasmSpendBuilder {
    fn from(builder: SpendBuilder) -> Self {
        Self { builder }
    }
}

impl From<WasmSpendBuilder> for SpendBuilder {
    fn from(value: WasmSpendBuilder) -> Self {
        value.builder
    }
}
