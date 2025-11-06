use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ibig::UBig;
use nbx_crypto::PrivateKey;
use nbx_ztd::{Digest, Hashable as HashableTrait};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{
    builder::TxBuilder,
    note::{Name, Note, Pkh, TimelockRange, Version},
    tx::{LockPrimitive, LockTim, RawTx, Seed, SpendCondition},
    Nicks,
};

// ============================================================================
// Wasm Types - Core Types
// ============================================================================

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmDigest {
    #[wasm_bindgen(skip)]
    pub value: String,
}

#[wasm_bindgen]
impl WasmDigest {
    #[wasm_bindgen(constructor)]
    pub fn new(value: String) -> Self {
        Self { value }
    }

    #[wasm_bindgen(getter)]
    pub fn value(&self) -> String {
        self.value.clone()
    }

    fn to_internal(&self) -> Digest {
        self.value.as_str().into()
    }

    fn from_internal(digest: &Digest) -> Self {
        Self {
            value: digest.to_string(),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmVersion {
    version: u32,
}

#[wasm_bindgen]
impl WasmVersion {
    #[wasm_bindgen(constructor)]
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    #[wasm_bindgen(js_name = V0)]
    pub fn v0() -> Self {
        Self { version: 0 }
    }

    #[wasm_bindgen(js_name = V1)]
    pub fn v1() -> Self {
        Self { version: 1 }
    }

    #[wasm_bindgen(js_name = V2)]
    pub fn v2() -> Self {
        Self { version: 2 }
    }

    fn to_internal(&self) -> Version {
        self.version.into()
    }

    fn from_internal(version: &Version) -> Self {
        Self {
            version: version.clone().into(),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmName {
    #[wasm_bindgen(skip)]
    pub first: String,
    #[wasm_bindgen(skip)]
    pub last: String,
}

#[wasm_bindgen]
impl WasmName {
    #[wasm_bindgen(constructor)]
    pub fn new(first: String, last: String) -> Self {
        Self { first, last }
    }

    #[wasm_bindgen(getter)]
    pub fn first(&self) -> String {
        self.first.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn last(&self) -> String {
        self.last.clone()
    }

    fn to_internal(&self) -> Name {
        Name::new(self.first.as_str().into(), self.last.as_str().into())
    }

    #[allow(dead_code)]
    fn from_internal(_name: &Name) -> Self {
        // We need to access Name fields via hash since they are private
        // For now, we'll only support construction, not reading back
        Self {
            first: "".to_string(),
            last: "".to_string(),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmTimelockRange {
    #[wasm_bindgen(skip)]
    pub min: Option<usize>,
    #[wasm_bindgen(skip)]
    pub max: Option<usize>,
}

#[wasm_bindgen]
impl WasmTimelockRange {
    #[wasm_bindgen(constructor)]
    pub fn new(min: Option<usize>, max: Option<usize>) -> Self {
        Self { min, max }
    }

    #[wasm_bindgen(getter)]
    pub fn min(&self) -> Option<usize> {
        self.min
    }

    #[wasm_bindgen(getter)]
    pub fn max(&self) -> Option<usize> {
        self.max
    }

    fn to_internal(&self) -> TimelockRange {
        TimelockRange::new(self.min, self.max)
    }
}

// ============================================================================
// Wasm Types - Note Types
// ============================================================================

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmNote {
    #[wasm_bindgen(skip)]
    pub version: WasmVersion,
    #[wasm_bindgen(skip)]
    pub origin_page: usize,
    #[wasm_bindgen(skip)]
    pub name: WasmName,
    #[wasm_bindgen(skip)]
    pub note_data_hash: WasmDigest,
    #[wasm_bindgen(skip)]
    pub assets: Nicks,
}

#[wasm_bindgen]
impl WasmNote {
    #[wasm_bindgen(constructor)]
    pub fn new(
        version: WasmVersion,
        origin_page: usize,
        name: WasmName,
        note_data_hash: WasmDigest,
        assets: Nicks,
    ) -> Self {
        Self {
            version,
            origin_page,
            name,
            note_data_hash,
            assets,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> WasmVersion {
        self.version.clone()
    }

    #[wasm_bindgen(getter, js_name = originPage)]
    pub fn origin_page(&self) -> usize {
        self.origin_page
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> WasmName {
        self.name.clone()
    }

    #[wasm_bindgen(getter, js_name = noteDataHash)]
    pub fn note_data_hash(&self) -> WasmDigest {
        self.note_data_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn assets(&self) -> Nicks {
        self.assets
    }

    #[wasm_bindgen]
    pub fn hash(&self) -> WasmDigest {
        WasmDigest::from_internal(&self.to_internal().hash())
    }

    fn to_internal(&self) -> Note {
        Note::new(
            self.version.to_internal(),
            self.origin_page,
            self.name.to_internal(),
            self.note_data_hash.to_internal(),
            self.assets,
        )
    }
}

// ============================================================================
// Wasm Types - Transaction Types
// ============================================================================

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmPkh {
    #[wasm_bindgen(skip)]
    pub m: u64,
    #[wasm_bindgen(skip)]
    pub hashes: Vec<String>,
}

#[wasm_bindgen]
impl WasmPkh {
    #[wasm_bindgen(constructor)]
    pub fn new(m: u64, hashes: Vec<String>) -> Self {
        Self { m, hashes }
    }

    #[wasm_bindgen]
    pub fn single(hash: String) -> Self {
        Self {
            m: 1,
            hashes: alloc::vec![hash],
        }
    }

    #[wasm_bindgen(getter)]
    pub fn m(&self) -> u64 {
        self.m
    }

    #[wasm_bindgen(getter)]
    pub fn hashes(&self) -> Vec<String> {
        self.hashes.clone()
    }

    fn to_internal(&self) -> Pkh {
        let hashes: Vec<Digest> = self.hashes.iter().map(|s| s.as_str().into()).collect();
        Pkh::new(self.m, hashes)
    }
}

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmLockTim {
    #[wasm_bindgen(skip)]
    pub rel: WasmTimelockRange,
    #[wasm_bindgen(skip)]
    pub abs: WasmTimelockRange,
}

#[wasm_bindgen]
impl WasmLockTim {
    #[wasm_bindgen(constructor)]
    pub fn new(rel: WasmTimelockRange, abs: WasmTimelockRange) -> Self {
        Self { rel, abs }
    }

    #[wasm_bindgen]
    pub fn coinbase() -> Self {
        let tim = LockTim::coinbase();
        Self {
            rel: WasmTimelockRange {
                min: tim.rel.min,
                max: tim.rel.max,
            },
            abs: WasmTimelockRange {
                min: tim.abs.min,
                max: tim.abs.max,
            },
        }
    }

    #[wasm_bindgen(getter)]
    pub fn rel(&self) -> WasmTimelockRange {
        self.rel.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn abs(&self) -> WasmTimelockRange {
        self.abs.clone()
    }

    fn to_internal(&self) -> LockTim {
        LockTim {
            rel: self.rel.to_internal(),
            abs: self.abs.to_internal(),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmLockPrimitive {
    variant: String,
    #[wasm_bindgen(skip)]
    pub pkh_data: Option<WasmPkh>,
    #[wasm_bindgen(skip)]
    pub tim_data: Option<WasmLockTim>,
}

#[wasm_bindgen]
impl WasmLockPrimitive {
    #[wasm_bindgen(js_name = newPkh)]
    pub fn new_pkh(pkh: WasmPkh) -> WasmLockPrimitive {
        Self {
            variant: "pkh".to_string(),
            pkh_data: Some(pkh),
            tim_data: None,
        }
    }

    #[wasm_bindgen(js_name = newTim)]
    pub fn new_tim(tim: WasmLockTim) -> WasmLockPrimitive {
        Self {
            variant: "tim".to_string(),
            pkh_data: None,
            tim_data: Some(tim),
        }
    }

    #[wasm_bindgen(js_name = newBrn)]
    pub fn new_brn() -> Self {
        Self {
            variant: "brn".to_string(),
            pkh_data: None,
            tim_data: None,
        }
    }

    fn to_internal(&self) -> Result<LockPrimitive, String> {
        match self.variant.as_str() {
            "pkh" => {
                if let Some(ref pkh) = self.pkh_data {
                    Ok(LockPrimitive::Pkh(pkh.to_internal()))
                } else {
                    Err("Missing pkh data".to_string())
                }
            }
            "tim" => {
                if let Some(ref tim) = self.tim_data {
                    Ok(LockPrimitive::Tim(tim.to_internal()))
                } else {
                    Err("Missing tim data".to_string())
                }
            }
            "brn" => Ok(LockPrimitive::Brn),
            _ => Err("Invalid lock primitive variant".to_string()),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmSpendCondition {
    #[wasm_bindgen(skip)]
    pub primitives: Vec<WasmLockPrimitive>,
}

#[wasm_bindgen]
impl WasmSpendCondition {
    #[wasm_bindgen(constructor)]
    pub fn new(primitives: Vec<WasmLockPrimitive>) -> Self {
        Self { primitives }
    }

    #[wasm_bindgen(js_name = newPkh)]
    pub fn new_pkh(pkh: WasmPkh) -> WasmSpendCondition {
        let primitive = WasmLockPrimitive::new_pkh(pkh);
        Self {
            primitives: alloc::vec![primitive],
        }
    }

    #[wasm_bindgen]
    pub fn hash(&self) -> Result<WasmDigest, JsValue> {
        let condition = self
            .to_internal()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmDigest::from_internal(&condition.hash()))
    }

    fn to_internal(&self) -> Result<SpendCondition, String> {
        let mut primitives = Vec::new();
        for prim in &self.primitives {
            primitives.push(prim.to_internal()?);
        }
        Ok(SpendCondition(primitives))
    }
}

#[wasm_bindgen]
pub struct WasmSeed {
    #[wasm_bindgen(skip)]
    pub lock_root: WasmDigest,
    #[wasm_bindgen(skip)]
    pub gift: Nicks,
    #[wasm_bindgen(skip)]
    pub parent_hash: WasmDigest,
}

#[wasm_bindgen]
impl WasmSeed {
    #[wasm_bindgen(js_name = newSinglePkh)]
    pub fn new_single_pkh(pkh: WasmDigest, gift: Nicks, parent_hash: WasmDigest) -> Self {
        let seed = Seed::new_single_pkh(pkh.to_internal(), gift, parent_hash.to_internal());
        Self {
            lock_root: WasmDigest::from_internal(&seed.lock_root),
            gift,
            parent_hash,
        }
    }

    #[wasm_bindgen(getter, js_name = lockRoot)]
    pub fn lock_root(&self) -> WasmDigest {
        self.lock_root.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn gift(&self) -> Nicks {
        self.gift
    }

    #[wasm_bindgen(getter, js_name = parentHash)]
    pub fn parent_hash(&self) -> WasmDigest {
        self.parent_hash.clone()
    }
}

// ============================================================================
// Wasm Transaction Builder
// ============================================================================

#[wasm_bindgen]
pub struct WasmTxBuilder {
    builder: Option<TxBuilder>,
}

#[wasm_bindgen]
impl WasmTxBuilder {
    /// Create a simple transaction builder
    #[wasm_bindgen(js_name = newSimple)]
    pub fn new_simple(
        notes: Vec<WasmNote>,
        spend_condition: &WasmSpendCondition,
        recipient: WasmDigest,
        gift: Nicks,
        fee: Nicks,
        refund_pkh: WasmDigest,
    ) -> Result<WasmTxBuilder, JsValue> {
        let internal_notes: Vec<Note> = notes.iter().map(|n| n.to_internal()).collect();

        let builder = TxBuilder::new_simple(
            internal_notes,
            spend_condition
                .to_internal()
                .map_err(|e| JsValue::from_str(&format!("{}", e)))?,
            recipient.to_internal(),
            gift,
            fee,
            refund_pkh.to_internal(),
        )
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

        Ok(Self {
            builder: Some(builder),
        })
    }

    /// Sign the transaction with a private key
    #[wasm_bindgen]
    pub fn sign(&mut self, signing_key_bytes: &[u8]) -> Result<WasmRawTx, JsValue> {
        if signing_key_bytes.len() != 32 {
            return Err(JsValue::from_str("Private key must be 32 bytes"));
        }
        let signing_key = PrivateKey(UBig::from_be_bytes(signing_key_bytes));

        let builder = self
            .builder
            .take()
            .ok_or_else(|| JsValue::from_str("Builder already consumed"))?;

        let tx = builder
            .sign(&signing_key)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

        Ok(WasmRawTx::from_internal(&tx))
    }
}

// ============================================================================
// Wasm Raw Transaction
// ============================================================================

#[wasm_bindgen]
pub struct WasmRawTx {
    #[wasm_bindgen(skip)]
    pub version: WasmVersion,
    #[wasm_bindgen(skip)]
    pub id: WasmDigest,
}

#[wasm_bindgen]
impl WasmRawTx {
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> WasmVersion {
        self.version.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> WasmDigest {
        self.id.clone()
    }

    fn from_internal(tx: &RawTx) -> Self {
        Self {
            version: WasmVersion::from_internal(&tx.version),
            id: WasmDigest::from_internal(&tx.id),
        }
    }
}
