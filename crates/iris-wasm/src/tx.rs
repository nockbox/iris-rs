use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use iris_crypto::{PrivateKey as CryptoPrivateKey, PublicKey, Signature, SigningKey};
use iris_grpc_proto::pb::common::v1 as pb_v1;
use iris_grpc_proto::pb::common::v2 as pb;
use iris_nockchain_types::{
    builder::{MissingUnlocks, TxBuilder},
    note::Note,
    tx::RawTx,
    v1::{Lock, LockRoot, NockchainTx, RawTxV1, SeedV1 as Seed, SpendCondition},
    Nicks, SigningError, SpendBuilder, TxEngineSettings,
};
use iris_ztd::{cue, Digest, U256};
use js_sys::{Array, Function, Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

// ============================================================================
// Wasm Types - Adapters and Helpers
// ============================================================================

#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(js_name = digestToProtobuf)]
pub fn digest_to_protobuf(d: Digest) -> pb_v1::Hash {
    d.into()
}

#[wasm_bindgen(js_name = digestFromProtobuf)]
pub fn digest_from_protobuf(value: pb_v1::Hash) -> Result<Digest, JsValue> {
    value
        .try_into()
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
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

/// Convert protobuf spend condition to native SpendCondition.
/// Accepts the protobuf format used by the Nockchain gRPC interface and external dApps
#[wasm_bindgen(js_name = spendConditionFromProtobuf)]
pub fn spend_condition_from_protobuf(value: pb::SpendCondition) -> Result<SpendCondition, JsValue> {
    value
        .try_into()
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
}

/// Convert native SpendCondition to protobuf format.
/// Returns the protobuf format used by the Nockchain gRPC interface and external dApps.
#[wasm_bindgen(js_name = spendConditionToProtobuf)]
pub fn spend_condition_to_protobuf(value: SpendCondition) -> pb::SpendCondition {
    value.into()
}

#[wasm_bindgen(js_name = noteToProtobuf)]
pub fn note_to_protobuf(note: Note) -> pb::Note {
    note.into()
}

#[wasm_bindgen(js_name = noteFromProtobuf)]
pub fn note_from_protobuf(value: pb::Note) -> Result<Note, JsValue> {
    value
        .try_into()
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
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

#[derive(Serialize, Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct TxNotes {
    pub notes: Vec<Note>,
    pub refund_locks: Vec<Option<LockRoot>>,
}

#[derive(Serialize, Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum TxLock {
    None,
    Some { lock: Lock, lock_sp_index: usize },
}

impl TxLock {
    fn into_tuple(self) -> Option<(Lock, usize)> {
        match self {
            TxLock::None => None,
            TxLock::Some {
                lock,
                lock_sp_index,
            } => Some((lock, lock_sp_index)),
        }
    }
}

// ============================================================================
// Wasm Transaction Builder
// ============================================================================

enum PrivateKeyBackend {
    Bytes(BytesPrivateKeyBackend),
    Callback(CallbackPrivateKeyBackend),
}

struct BytesPrivateKeyBackend {
    signing_key: CryptoPrivateKey,
}

struct CallbackPrivateKeyBackend {
    // Keep the original callbacks object so method-style callbacks receive it as `this`.
    callbacks: js_sys::Object,
    get_public_key: Function,
    sign_digests: Function,
}

fn get_callback_fn(obj: &js_sys::Object, key: &str) -> Result<Function, JsValue> {
    let v = Reflect::get(obj, &JsValue::from_str(key)).map_err(|_| {
        JsValue::from_str("fromCallbacks: failed to read property from callbacks object")
    })?;
    if let Ok(f) = v.dyn_into::<Function>() {
        return Ok(f);
    }

    Err(JsValue::from_str(&format!(
        "fromCallbacks: expected a function at `{key}`"
    )))
}

async fn await_resolved_promise(v: JsValue) -> Result<JsValue, JsValue> {
    JsFuture::from(js_sys::Promise::resolve(&v)).await
}

async fn callback_fetch_public_key(cb: &CallbackPrivateKeyBackend) -> Result<PublicKey, JsValue> {
    let v = await_resolved_promise(cb.get_public_key.call0(&cb.callbacks)?).await?;
    let arr = v
        .dyn_into::<Uint8Array>()
        .map_err(|_| JsValue::from_str("getPublicKey must return Uint8Array of length 97"))?;
    if arr.length() as usize != 97 {
        return Err(JsValue::from_str("getPublicKey: expected 97 bytes"));
    }
    let mut b = [0u8; 97];
    arr.copy_to(&mut b);
    Ok(PublicKey::from_be_bytes(&b))
}

async fn callback_sign_digests(
    cb: &CallbackPrivateKeyBackend,
    digests: &[Digest],
) -> Result<Vec<Signature>, JsValue> {
    let args = Array::new();
    for digest in digests {
        let digest_bytes = digest.to_bytes();
        args.push(&Uint8Array::from(digest_bytes.as_slice()));
    }

    let v = await_resolved_promise(cb.sign_digests.call1(&cb.callbacks, &args)?).await?;
    let arr = v
        .dyn_into::<Array>()
        .map_err(|_| JsValue::from_str("signDigests must return an Array<Uint8Array>"))?;

    if arr.length() as usize != digests.len() {
        return Err(JsValue::from_str(
            "signDigests: expected one signature per digest",
        ));
    }

    let mut out = Vec::with_capacity(arr.length() as usize);
    for (i, item) in arr.iter().enumerate() {
        let sig_bytes = item
            .dyn_into::<Uint8Array>()
            .map_err(|_| JsValue::from_str("signDigests must return an Array<Uint8Array>"))?;

        if sig_bytes.length() as usize != Signature::BYTE_LEN {
            return Err(JsValue::from_str(
                "signDigests: expected Uint8Array(64) for each signature",
            ));
        }

        let mut buf = [0u8; Signature::BYTE_LEN];
        sig_bytes.copy_to(&mut buf);
        let sig = Signature::from_bytes_le(&buf)
            .ok_or_else(|| JsValue::from_str("signDigests: expected 64 bytes (32 c + 32 s LE)"))?;
        out.push(sig);

        debug_assert!(i < digests.len());
    }

    Ok(out)
}

fn signing_error_to_js(error: SigningError<JsValue>) -> JsValue {
    match error {
        SigningError::Signer(error) => error,
        SigningError::InvalidSignature => JsValue::from_str("signer returned an invalid signature"),
        SigningError::SignatureRejected => JsValue::from_str("signature was rejected by spend"),
    }
}

/// Holds raw key bytes in WASM; [`Drop`] zeroizes the scalar so the secret does not linger
/// after the JS handle is released.
#[wasm_bindgen(js_name = PrivateKey)]
pub struct WasmPrivateKey {
    backend: PrivateKeyBackend,
}

impl SigningKey for WasmPrivateKey {
    type Error = JsValue;

    fn public_key(
        &self,
    ) -> impl core::future::Future<Output = Result<PublicKey, Self::Error>> + '_ {
        async move {
            match &self.backend {
                PrivateKeyBackend::Bytes(bytes_backend) => {
                    Ok(bytes_backend.signing_key.public_key())
                }
                PrivateKeyBackend::Callback(callback_backend) => {
                    callback_fetch_public_key(callback_backend).await
                }
            }
        }
    }

    fn sign_digests<'a>(
        &'a self,
        digests: &'a [Digest],
    ) -> impl core::future::Future<Output = Result<Vec<Signature>, Self::Error>> + 'a {
        async move {
            match &self.backend {
                PrivateKeyBackend::Bytes(bytes_backend) => {
                    let mut out = Vec::with_capacity(digests.len());
                    for digest in digests {
                        out.push(bytes_backend.signing_key.sign(digest));
                    }
                    Ok(out)
                }
                PrivateKeyBackend::Callback(callback_backend) => {
                    callback_sign_digests(callback_backend, digests).await
                }
            }
        }
    }
}

impl Drop for WasmPrivateKey {
    fn drop(&mut self) {
        match &mut self.backend {
            PrivateKeyBackend::Bytes(b) => {
                unsafe {
                    core::ptr::write_volatile(&mut b.signing_key.0, U256::ZERO);
                }
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }
            PrivateKeyBackend::Callback(_) => {}
        }
    }
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
        Ok(Self {
            backend: PrivateKeyBackend::Bytes(BytesPrivateKeyBackend { signing_key }),
        })
    }

    /// External signer: JavaScript object with async (or sync) functions:
    /// - `getPublicKey` -> `Uint8Array(97)` uncompressed pubkey
    /// - `signDigests` -> `(digests: Uint8Array[])` -> `Uint8Array(64)[]` (`c`||`s` LE)
    ///
    /// Return values may be Promises; they are always awaited.
    #[wasm_bindgen(js_name = fromCallbacks)]
    pub fn from_callbacks(callbacks: &JsValue) -> Result<WasmPrivateKey, JsValue> {
        let obj = callbacks
            .dyn_ref::<js_sys::Object>()
            .ok_or_else(|| JsValue::from_str("fromCallbacks: expected a plain object"))?;
        let get_public_key = get_callback_fn(obj, "getPublicKey")?;
        let sign_digests = get_callback_fn(obj, "signDigests")?;
        Ok(Self {
            backend: PrivateKeyBackend::Callback(CallbackPrivateKeyBackend {
                callbacks: obj.clone(),
                get_public_key,
                sign_digests,
            }),
        })
    }

    /// Return this key's public key as 97-byte uncompressed bytes.
    #[wasm_bindgen(js_name = publicKey)]
    pub async fn public_key(&self) -> Result<Vec<u8>, JsValue> {
        let public_key = <Self as SigningKey>::public_key(self).await?;
        Ok(public_key.to_be_bytes().to_vec())
    }

    /// Return the derivation path for this key backend, if available.
    ///
    /// Bytes-backed keys return `undefined` in JavaScript.
    #[wasm_bindgen(getter, js_name = derivationPath)]
    pub fn derivation_path(&self) -> Option<String> {
        match &self.backend {
            PrivateKeyBackend::Bytes(_) => None,
            PrivateKeyBackend::Callback(_) => None,
        }
    }

    /// Return the backend kind for debugging and feature checks.
    #[wasm_bindgen(js_name = backendKind)]
    pub fn backend_kind(&self) -> String {
        match &self.backend {
            PrivateKeyBackend::Bytes(_) => "bytes".to_string(),
            PrivateKeyBackend::Callback(_) => "callback".to_string(),
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

    /// Reconstruct a builder from raw transaction.
    #[wasm_bindgen(js_name = fromRawTx)]
    pub fn from_raw_tx(tx: RawTx, settings: TxEngineSettings) -> Result<Self, JsValue> {
        let builder = TxBuilder::from_raw_tx(tx, settings).map_err(|e| e.to_string())?;
        Ok(Self { builder })
    }

    /// Reconstruct a builder from Nockchain transaction.
    #[wasm_bindgen(js_name = fromNockchainTx)]
    pub fn from_nockchain_tx(tx: NockchainTx, settings: TxEngineSettings) -> Result<Self, JsValue> {
        let builder = TxBuilder::from_nockchain_tx(tx, settings).map_err(|e| e.to_string())?;
        Ok(Self { builder })
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = simpleSpend)]
    pub fn simple_spend(
        &mut self,
        notes: Vec<Note>,
        locks: Vec<TxLock>,
        recipient: Digest,
        gift: Nicks,
        fee_override: Option<Nicks>,
        refund_pkh: Digest,
        include_lock_data: bool,
    ) -> Result<(), JsValue> {
        if notes.len() != locks.len() {
            return Err(JsValue::from_str(
                "notes and locks must have the same length",
            ));
        }

        let internal_notes: Vec<(Note, Option<(Lock, usize)>)> = notes
            .into_iter()
            .zip(locks)
            .map(|(n, lck)| (n, lck.into_tuple()))
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
        self.builder
            .sign(signing_key)
            .await
            .map_err(signing_error_to_js)?;
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
        lock: Option<Lock>,
        lock_sp_index: Option<usize>,
        refund_lock: Option<LockRoot>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            builder: SpendBuilder::new(note, lock.zip(lock_sp_index), refund_lock)
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
        self.builder
            .sign(signing_key)
            .await
            .map_err(signing_error_to_js)
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
