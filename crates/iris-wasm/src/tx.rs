use std::collections::{BTreeMap, BTreeSet};

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use iris_crypto::PrivateKey;
use iris_grpc_proto::pb::common::v1 as pb_v1;
use iris_grpc_proto::pb::common::v2 as pb;
use iris_nockchain_types::{
    builder::TxBuilder,
    note::{Name, Note, NoteData, NoteDataEntry, Pkh, TimelockRange, Version},
    tx::{LockPrimitive, LockRoot, NockchainTx, RawTx, Seed, SpendCondition},
    Nicks,
};
use iris_nockchain_types::{Hax, LockTim, MissingUnlocks, Source, SpendBuilder};
use iris_ztd::U256;
use iris_ztd::{cue, jam, Digest, Hashable as HashableTrait, NounDecode, NounEncode};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ============================================================================
// Wasm Types - Core Types
// ============================================================================

#[wasm_bindgen(js_name = Digest)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WasmDigest {
    #[wasm_bindgen(skip)]
    pub value: String,
}

#[wasm_bindgen(js_class = Digest)]
impl WasmDigest {
    #[wasm_bindgen(constructor)]
    pub fn new(value: String) -> Self {
        Self { value }
    }

    #[wasm_bindgen(getter)]
    pub fn value(&self) -> String {
        self.value.clone()
    }

    fn to_internal(&self) -> Result<Digest, &'static str> {
        self.value.as_str().try_into()
    }

    fn from_internal(digest: &Digest) -> Self {
        Self {
            value: digest.to_string(),
        }
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let digest = self.to_internal().map_err(JsValue::from_str)?;
        let pb = pb_v1::Hash::from(digest);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmDigest, JsValue> {
        let pb: pb_v1::Hash = serde_wasm_bindgen::from_value(value)?;
        let digest: Digest = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmDigest::from_internal(&digest))
    }
}

#[wasm_bindgen(js_name = Version)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmVersion {
    version: u32,
}

#[wasm_bindgen(js_class = Version)]
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

#[wasm_bindgen(js_name = Name)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmName {
    #[wasm_bindgen(skip)]
    pub first: Digest,
    #[wasm_bindgen(skip)]
    pub last: Digest,
}

#[wasm_bindgen(js_class = Name)]
impl WasmName {
    #[wasm_bindgen(constructor)]
    pub fn new(first: String, last: String) -> Result<Self, JsValue> {
        let first = Digest::try_from(&*first)?;
        let last = Digest::try_from(&*last)?;
        Ok(Self { first, last })
    }

    #[wasm_bindgen(getter)]
    pub fn first(&self) -> String {
        self.first.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn last(&self) -> String {
        self.last.to_string()
    }

    fn to_internal(&self) -> Name {
        Name::new(self.first, self.last)
    }

    #[allow(dead_code)]
    fn from_internal(name: &Name) -> Self {
        // We need to access Name fields via hash since they are private
        // For now, we'll only support construction, not reading back
        Self {
            first: name.first,
            last: name.last,
        }
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let name = self.to_internal();
        let pb = pb_v1::Name::from(name);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmName, JsValue> {
        let pb: pb_v1::Name = serde_wasm_bindgen::from_value(value)?;
        let name: Name = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmName::from_internal(&name))
    }
}

#[wasm_bindgen(js_name = TimelockRange)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmTimelockRange {
    #[wasm_bindgen(skip)]
    pub min: Option<u64>,
    #[wasm_bindgen(skip)]
    pub max: Option<u64>,
}

#[wasm_bindgen(js_class = TimelockRange)]
impl WasmTimelockRange {
    #[wasm_bindgen(constructor)]
    pub fn new(min: Option<u64>, max: Option<u64>) -> Self {
        Self { min, max }
    }

    #[wasm_bindgen(getter)]
    pub fn min(&self) -> Option<u64> {
        self.min
    }

    #[wasm_bindgen(getter)]
    pub fn max(&self) -> Option<u64> {
        self.max
    }

    fn to_internal(&self) -> TimelockRange {
        TimelockRange::new(self.min, self.max)
    }

    fn from_internal(internal: TimelockRange) -> WasmTimelockRange {
        WasmTimelockRange {
            min: internal.min,
            max: internal.max,
        }
    }
}

#[wasm_bindgen(js_name = Source)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmSource {
    #[wasm_bindgen(skip)]
    pub hash: WasmDigest,
    #[wasm_bindgen(skip)]
    pub is_coinbase: bool,
}

#[wasm_bindgen(js_class = Source)]
impl WasmSource {
    #[wasm_bindgen(getter, js_name = hash)]
    pub fn hash(&self) -> WasmDigest {
        self.hash.clone()
    }

    #[wasm_bindgen(getter, js_name = isCoinbase)]
    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }

    fn to_internal(&self) -> Result<Source, String> {
        Ok(Source {
            hash: self.hash.to_internal()?,
            is_coinbase: self.is_coinbase,
        })
    }

    fn from_internal(internal: &Source) -> Self {
        Self {
            hash: WasmDigest::from_internal(&internal.hash),
            is_coinbase: internal.is_coinbase,
        }
    }
}

// ============================================================================
// Wasm Types - Note Types
// ============================================================================

#[wasm_bindgen(js_name = NoteDataEntry)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmNoteDataEntry {
    #[wasm_bindgen(skip)]
    pub key: String,
    #[wasm_bindgen(skip)]
    pub blob: Vec<u8>,
}

#[wasm_bindgen(js_class = NoteDataEntry)]
impl WasmNoteDataEntry {
    #[wasm_bindgen(constructor)]
    pub fn new(key: String, blob: Vec<u8>) -> Self {
        Self { key, blob }
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> String {
        self.key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn blob(&self) -> Vec<u8> {
        self.blob.clone()
    }

    fn to_internal(&self) -> Result<NoteDataEntry, String> {
        let val = cue(&self.blob).ok_or_else(|| "Failed to deserialize noun".to_string())?;
        Ok(NoteDataEntry {
            key: self.key.clone(),
            val,
        })
    }

    fn from_internal(entry: &NoteDataEntry) -> Self {
        Self {
            key: entry.key.clone(),
            blob: jam(entry.val.clone()),
        }
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let entry = self.to_internal().map_err(|e| JsValue::from_str(&e))?;
        let pb = pb::NoteDataEntry::from(entry);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmNoteDataEntry, JsValue> {
        let pb: pb::NoteDataEntry = serde_wasm_bindgen::from_value(value)?;
        let entry: NoteDataEntry = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmNoteDataEntry::from_internal(&entry))
    }
}

#[wasm_bindgen(js_name = NoteData)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmNoteData {
    #[wasm_bindgen(skip)]
    pub entries: Vec<WasmNoteDataEntry>,
}

#[wasm_bindgen(js_class = NoteData)]
impl WasmNoteData {
    #[wasm_bindgen(constructor)]
    pub fn new(entries: Vec<WasmNoteDataEntry>) -> Self {
        Self { entries }
    }

    #[wasm_bindgen]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    #[wasm_bindgen(js_name = fromPkh)]
    pub fn from_pkh(pkh: WasmPkh) -> Result<Self, JsValue> {
        let note_data = NoteData::from_pkh(pkh.to_internal()?);
        Ok(Self::from_internal(&note_data))
    }

    #[wasm_bindgen(getter)]
    pub fn entries(&self) -> Vec<WasmNoteDataEntry> {
        self.entries.clone()
    }

    fn to_internal(&self) -> Result<NoteData, String> {
        let entries: Result<Vec<NoteDataEntry>, String> =
            self.entries.iter().map(|e| e.to_internal()).collect();
        Ok(NoteData(entries?))
    }

    fn from_internal(note_data: &NoteData) -> Self {
        Self {
            entries: note_data
                .0
                .iter()
                .map(WasmNoteDataEntry::from_internal)
                .collect(),
        }
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let data = self.to_internal().map_err(|e| JsValue::from_str(&e))?;
        let pb = pb::NoteData::from(data);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmNoteData, JsValue> {
        let pb: pb::NoteData = serde_wasm_bindgen::from_value(value)?;
        let data: NoteData = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmNoteData::from_internal(&data))
    }
}

#[wasm_bindgen(js_name = Note)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmNote {
    #[wasm_bindgen(skip)]
    pub version: WasmVersion,
    #[wasm_bindgen(skip)]
    pub origin_page: u64,
    #[wasm_bindgen(skip)]
    pub name: WasmName,
    #[wasm_bindgen(skip)]
    pub note_data: WasmNoteData,
    #[wasm_bindgen(skip)]
    pub assets: Nicks,
}

#[wasm_bindgen(js_class = Note)]
impl WasmNote {
    #[wasm_bindgen(constructor)]
    pub fn new(
        version: WasmVersion,
        origin_page: u64,
        name: WasmName,
        note_data: WasmNoteData,
        assets: Nicks,
    ) -> Self {
        Self {
            version,
            origin_page,
            name,
            note_data,
            assets,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> WasmVersion {
        self.version.clone()
    }

    #[wasm_bindgen(getter, js_name = originPage)]
    pub fn origin_page(&self) -> u64 {
        self.origin_page
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> WasmName {
        self.name.clone()
    }

    #[wasm_bindgen(getter, js_name = noteData)]
    pub fn note_data(&self) -> WasmNoteData {
        self.note_data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn assets(&self) -> Nicks {
        self.assets
    }

    #[wasm_bindgen]
    pub fn hash(&self) -> Result<WasmDigest, JsValue> {
        let note = self
            .to_internal()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmDigest::from_internal(&note.hash()))
    }

    /// Create a WasmNote from a protobuf Note object (from get_balance response)
    /// Expects response.notes[i].note (handles version internally)
    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(pb_note: JsValue) -> Result<WasmNote, JsValue> {
        let pb: pb::Note = serde_wasm_bindgen::from_value(pb_note)?;
        let note: Note = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmNote::from_internal(note))
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let note = self
            .to_internal()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let pb = pb::Note::from(note);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    fn to_internal(&self) -> Result<Note, String> {
        Ok(Note::new(
            self.version.to_internal(),
            self.origin_page,
            self.name.to_internal(),
            self.note_data.to_internal()?,
            self.assets,
        ))
    }

    fn from_internal(internal: Note) -> Self {
        Self {
            version: WasmVersion::from_internal(&internal.version),
            origin_page: internal.origin_page,
            name: WasmName::from_internal(&internal.name),
            note_data: WasmNoteData::from_internal(&internal.note_data),
            assets: internal.assets,
        }
    }
}

// ============================================================================
// Wasm Types - Transaction Types
// ============================================================================

#[wasm_bindgen(js_name = Pkh)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmPkh {
    #[wasm_bindgen(skip)]
    pub m: u64,
    #[wasm_bindgen(skip)]
    pub hashes: Vec<String>,
}

#[wasm_bindgen(js_class = Pkh)]
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

    fn to_internal(&self) -> Result<Pkh, String> {
        let hashes: Result<Vec<Digest>, _> =
            self.hashes.iter().map(|s| s.as_str().try_into()).collect();
        Ok(Pkh::new(self.m, hashes?))
    }

    fn from_internal(internal: Pkh) -> Self {
        Self::new(
            internal.m,
            internal.hashes.into_iter().map(|v| v.to_string()).collect(),
        )
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let pkh = self.to_internal().map_err(|e| JsValue::from_str(&e))?;
        let pb = pb::PkhLock::from(pkh);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmPkh, JsValue> {
        let pb: pb::PkhLock = serde_wasm_bindgen::from_value(value)?;
        let pkh: Pkh = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmPkh::from_internal(pkh))
    }
}

#[wasm_bindgen(js_name = LockTim)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmLockTim {
    #[wasm_bindgen(skip)]
    pub rel: WasmTimelockRange,
    #[wasm_bindgen(skip)]
    pub abs: WasmTimelockRange,
}

#[wasm_bindgen(js_class = LockTim)]
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

    fn from_internal(internal: LockTim) -> WasmLockTim {
        WasmLockTim {
            rel: WasmTimelockRange::from_internal(internal.rel),
            abs: WasmTimelockRange::from_internal(internal.abs),
        }
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let tim = self.to_internal();
        let pb = pb::LockTim::from(tim);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmLockTim, JsValue> {
        let pb: pb::LockTim = serde_wasm_bindgen::from_value(value)?;
        let tim: LockTim = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmLockTim::from_internal(tim))
    }
}

#[wasm_bindgen(js_name = Hax)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmHax {
    #[wasm_bindgen(skip)]
    pub digests: Vec<WasmDigest>,
}

#[wasm_bindgen(js_class = Hax)]
impl WasmHax {
    #[wasm_bindgen(constructor)]
    pub fn new(digests: Vec<WasmDigest>) -> Self {
        Self { digests }
    }

    #[wasm_bindgen(getter)]
    pub fn digests(&self) -> Vec<WasmDigest> {
        self.digests.clone()
    }

    fn to_internal(&self) -> Result<Hax, String> {
        Ok(Hax(self
            .digests
            .iter()
            .map(WasmDigest::to_internal)
            .collect::<Result<Vec<_>, _>>()?))
    }

    fn from_internal(internal: Hax) -> Self {
        Self::new(internal.0.iter().map(WasmDigest::from_internal).collect())
    }
}

#[wasm_bindgen(js_name = LockPrimitive)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmLockPrimitive {
    variant: String,
    #[wasm_bindgen(skip)]
    pub pkh_data: Option<WasmPkh>,
    #[wasm_bindgen(skip)]
    pub tim_data: Option<WasmLockTim>,
    #[wasm_bindgen(skip)]
    pub hax_data: Option<WasmHax>,
}

#[wasm_bindgen(js_class = LockPrimitive)]
impl WasmLockPrimitive {
    #[wasm_bindgen(js_name = newPkh)]
    pub fn new_pkh(pkh: WasmPkh) -> WasmLockPrimitive {
        Self {
            variant: "pkh".to_string(),
            pkh_data: Some(pkh),
            tim_data: None,
            hax_data: None,
        }
    }

    #[wasm_bindgen(js_name = newTim)]
    pub fn new_tim(tim: WasmLockTim) -> WasmLockPrimitive {
        Self {
            variant: "tim".to_string(),
            pkh_data: None,
            tim_data: Some(tim),
            hax_data: None,
        }
    }

    #[wasm_bindgen(js_name = newHax)]
    pub fn new_hax(hax: WasmHax) -> Self {
        Self {
            variant: "hax".to_string(),
            pkh_data: None,
            tim_data: None,
            hax_data: Some(hax),
        }
    }

    #[wasm_bindgen(js_name = newBrn)]
    pub fn new_brn() -> Self {
        Self {
            variant: "brn".to_string(),
            pkh_data: None,
            tim_data: None,
            hax_data: None,
        }
    }

    fn to_internal(&self) -> Result<LockPrimitive, String> {
        match self.variant.as_str() {
            "pkh" => {
                if let Some(ref pkh) = self.pkh_data {
                    Ok(LockPrimitive::Pkh(pkh.to_internal()?))
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
            "hax" => {
                if let Some(ref hax) = self.hax_data {
                    Ok(LockPrimitive::Hax(hax.to_internal()?))
                } else {
                    Err("Missing hax data".to_string())
                }
            }
            "brn" => Ok(LockPrimitive::Brn),
            _ => Err("Invalid lock primitive variant".to_string()),
        }
    }

    fn from_internal(internal: LockPrimitive) -> Self {
        match internal {
            LockPrimitive::Pkh(p) => Self::new_pkh(WasmPkh::from_internal(p)),
            LockPrimitive::Tim(t) => Self::new_tim(WasmLockTim::from_internal(t)),
            LockPrimitive::Hax(h) => Self::new_hax(WasmHax::from_internal(h)),
            LockPrimitive::Brn => Self::new_brn(),
        }
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let prim = self.to_internal().map_err(|e| JsValue::from_str(&e))?;
        let pb = pb::LockPrimitive::from(prim);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmLockPrimitive, JsValue> {
        let pb: pb::LockPrimitive = serde_wasm_bindgen::from_value(value)?;
        let prim: LockPrimitive = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmLockPrimitive::from_internal(prim))
    }
}

#[wasm_bindgen(js_name = SpendCondition)]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmSpendCondition {
    #[wasm_bindgen(skip)]
    pub primitives: Vec<WasmLockPrimitive>,
}

#[wasm_bindgen(js_class = SpendCondition)]
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
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmDigest::from_internal(&condition.hash()))
    }

    #[wasm_bindgen(js_name = firstName)]
    pub fn first_name(&self) -> Result<WasmDigest, JsValue> {
        let condition = self
            .to_internal()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmDigest::from_internal(&condition.first_name()))
    }

    fn to_internal(&self) -> Result<SpendCondition, String> {
        let mut primitives = Vec::new();
        for prim in &self.primitives {
            primitives.push(prim.to_internal()?);
        }
        Ok(SpendCondition(primitives))
    }

    fn from_internal(internal: SpendCondition) -> Self {
        Self::new(
            internal
                .0
                .into_iter()
                .map(WasmLockPrimitive::from_internal)
                .collect(),
        )
    }

    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let cond = self.to_internal().map_err(|e| JsValue::from_str(&e))?;
        let pb = pb::SpendCondition::from(cond);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmSpendCondition, JsValue> {
        let pb: pb::SpendCondition = serde_wasm_bindgen::from_value(value)?;
        let cond: SpendCondition = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmSpendCondition::from_internal(cond))
    }
}

#[wasm_bindgen(js_name = LockRoot)]
#[derive(Clone, Debug)]
pub struct WasmLockRoot {
    #[wasm_bindgen(skip)]
    pub internal: LockRoot,
}

#[wasm_bindgen(js_class = LockRoot)]
impl WasmLockRoot {
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(hash: WasmDigest) -> Result<Self, JsValue> {
        Ok(Self {
            internal: LockRoot::Hash(hash.to_internal()?),
        })
    }

    #[wasm_bindgen(js_name = fromSpendCondition)]
    pub fn from_spend_condition(cond: WasmSpendCondition) -> Result<Self, JsValue> {
        Ok(Self {
            internal: LockRoot::Lock(cond.to_internal()?),
        })
    }

    #[wasm_bindgen(getter, js_name = hash)]
    pub fn hash(&self) -> WasmDigest {
        WasmDigest::from_internal(&self.internal.hash())
    }

    #[wasm_bindgen(getter, js_name = lock)]
    pub fn lock(&self) -> Option<WasmSpendCondition> {
        match &self.internal {
            LockRoot::Lock(cond) => Some(WasmSpendCondition::from_internal(cond.clone())),
            _ => None,
        }
    }

    fn to_internal(&self) -> LockRoot {
        self.internal.clone()
    }

    fn from_internal(internal: LockRoot) -> Self {
        Self { internal }
    }
}

#[wasm_bindgen(js_name = Seed)]
pub struct WasmSeed {
    #[wasm_bindgen(skip)]
    pub output_source: Option<WasmSource>,
    #[wasm_bindgen(skip)]
    pub lock_root: WasmLockRoot,
    #[wasm_bindgen(skip)]
    pub gift: Nicks,
    #[wasm_bindgen(skip)]
    pub note_data: WasmNoteData,
    #[wasm_bindgen(skip)]
    pub parent_hash: WasmDigest,
}

#[wasm_bindgen(js_class = Seed)]
impl WasmSeed {
    #[wasm_bindgen(constructor)]
    pub fn new(
        output_source: Option<WasmSource>,
        lock_root: WasmLockRoot,
        gift: Nicks,
        note_data: WasmNoteData,
        parent_hash: WasmDigest,
    ) -> Self {
        Self {
            output_source,
            lock_root,
            gift,
            note_data,
            parent_hash,
        }
    }

    #[wasm_bindgen(js_name = newSinglePkh)]
    pub fn new_single_pkh(
        pkh: WasmDigest,
        gift: Nicks,
        parent_hash: WasmDigest,
        include_lock_data: bool,
    ) -> Result<Self, JsValue> {
        let seed = Seed::new_single_pkh(
            pkh.to_internal()?,
            gift,
            parent_hash.to_internal()?,
            include_lock_data,
        );
        Ok(seed.into())
    }

    #[wasm_bindgen(getter, js_name = outputSource)]
    pub fn output_source(&self) -> Option<WasmSource> {
        self.output_source.clone()
    }

    #[wasm_bindgen(setter, js_name = outputSource)]
    pub fn set_output_source(&mut self, output_source: Option<WasmSource>) {
        self.output_source = output_source;
    }

    #[wasm_bindgen(getter, js_name = lockRoot)]
    pub fn lock_root(&self) -> WasmLockRoot {
        self.lock_root.clone()
    }

    #[wasm_bindgen(setter, js_name = lockRoot)]
    pub fn set_lock_root(&mut self, lock_root: WasmLockRoot) {
        self.lock_root = lock_root;
    }

    #[wasm_bindgen(getter)]
    pub fn gift(&self) -> Nicks {
        self.gift
    }

    #[wasm_bindgen(setter)]
    pub fn set_gift(&mut self, gift: Nicks) {
        self.gift = gift;
    }

    #[wasm_bindgen(getter, js_name = noteData)]
    pub fn note_data(&self) -> WasmNoteData {
        self.note_data.clone()
    }

    #[wasm_bindgen(setter, js_name = noteData)]
    pub fn set_note_data(&mut self, note_data: WasmNoteData) {
        self.note_data = note_data;
    }

    #[wasm_bindgen(getter, js_name = parentHash)]
    pub fn parent_hash(&self) -> WasmDigest {
        self.parent_hash.clone()
    }

    #[wasm_bindgen(setter, js_name = parentHash)]
    pub fn set_parent_hash(&mut self, parent_hash: WasmDigest) {
        self.parent_hash = parent_hash;
    }

    fn to_internal(&self) -> Result<Seed, String> {
        Ok(Seed {
            output_source: self
                .output_source
                .as_ref()
                .map(WasmSource::to_internal)
                .transpose()?,
            lock_root: self.lock_root.to_internal(),
            gift: self.gift,
            note_data: self.note_data.to_internal()?,
            parent_hash: self.parent_hash.to_internal()?,
        })
    }
}

impl From<Seed> for WasmSeed {
    fn from(value: Seed) -> Self {
        Self {
            output_source: value.output_source.as_ref().map(WasmSource::from_internal),
            lock_root: WasmLockRoot::from_internal(value.lock_root),
            gift: value.gift,
            note_data: WasmNoteData::from_internal(&value.note_data),
            parent_hash: WasmDigest::from_internal(&value.parent_hash),
        }
    }
}

#[wasm_bindgen]
impl WasmSeed {
    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let seed = self.to_internal().map_err(|e| JsValue::from_str(&e))?;
        let pb = pb::Seed::from(seed);
        serde_wasm_bindgen::to_value(&pb).map_err(|e| e.into())
    }

    fn from_internal(seed: Seed) -> Self {
        seed.into()
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmSeed, JsValue> {
        let pb: pb::Seed = serde_wasm_bindgen::from_value(value)?;
        let seed: Seed = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        Ok(WasmSeed::from_internal(seed))
    }
}

// ============================================================================
// Wasm Transaction Builder
// ============================================================================

#[wasm_bindgen(js_name = TxBuilder)]
pub struct WasmTxBuilder {
    builder: TxBuilder,
}

#[wasm_bindgen(js_class = TxBuilder)]
impl WasmTxBuilder {
    /// Create an empty transaction builder
    #[wasm_bindgen(constructor)]
    pub fn new(fee_per_word: Nicks) -> Self {
        Self {
            builder: TxBuilder::new(fee_per_word),
        }
    }

    /// Reconstruct a builder from raw transaction and its input notes.
    ///
    /// To get the builder back, you must pass the notes and their corresponding spend conditions.
    /// If serializing the builder, call `WasmTxBuilder::all_notes`.
    #[wasm_bindgen(js_name = fromTx)]
    pub fn from_tx(
        tx: WasmRawTx,
        notes: Vec<WasmNote>,
        spend_conditions: Vec<WasmSpendCondition>,
    ) -> Result<Self, JsValue> {
        if notes.len() != spend_conditions.len() {
            return Err(JsValue::from_str(
                "notes and spend_conditions must have the same length",
            ));
        }

        let internal_notes: Result<BTreeMap<Name, (Note, SpendCondition)>, String> = notes
            .iter()
            .zip(spend_conditions.iter())
            .map(|(n, sc)| Ok((n.to_internal()?, sc.to_internal()?)))
            .map(|v| v.map(|(a, b)| (a.name.clone(), (a, b))))
            .collect();
        let internal_notes = internal_notes.map_err(|e| JsValue::from_str(&e.to_string()))?;

        let builder = TxBuilder::from_tx(tx.internal, internal_notes).map_err(|e| e.to_string())?;

        Ok(Self { builder })
    }

    /// Perform a simple-spend on this builder.
    ///
    /// It is HIGHLY recommended to not mix `simpleSpend` with other types of spends.
    ///
    /// This performs a fairly complex set of operations, in order to mimic behavior of nockchain
    /// CLI wallet's create-tx option. Note that we do not do 1-1 mapping of that functionality,
    /// most notably - if `recipient` is the same as `refund_pkh`, we will create 1 seed, while the
    /// CLI wallet will create 2.
    ///
    /// Another difference is that you should call `sign` and `validate` after calling this method.
    ///
    /// Internally, the transaction builder takes ALL of the `notes` provided, and stores them for
    /// fee adjustments. If there are multiple notes being used, our fee setup also differs from
    /// the CLI, because we first greedily spend the notes out, and then take fees from any
    /// remaining refunds.
    ///
    /// This function prioritizes using the least number of notes possible, because that lowers the
    /// fee used.
    ///
    /// You may choose to override the fee with `fee_override`, but do note that `validate` will
    /// fail, in case this fee is too small.
    ///
    /// `include_lock_data` can be used to include `%lock` key in note-data, with the
    /// `SpendCondition` used. However, note-data costs 1 << 15 nicks, which means, it can get
    /// expensive.
    ///
    /// Optional parameter `remove_unused_notes`, if set to false, will keep the notes in the
    /// transaction builder. This is meant to be used whenever additional operations are performed
    /// on the builder, such as additional spends, or `addPreimage` calls. All of these increase
    /// the required fee (which can be checked with `calcFee`), and unused notes can then be used
    /// to adjust fees with `setFeeAndBalanceRefund` or `recalcAndSetFee`. Once all operations are
    /// done, one should call `removeUnusedNotes` to ensure these notes are not used within the
    /// transaction.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = simpleSpend)]
    pub fn simple_spend(
        &mut self,
        notes: Vec<WasmNote>,
        spend_conditions: Vec<WasmSpendCondition>,
        recipient: WasmDigest,
        gift: Nicks,
        fee_override: Option<Nicks>,
        refund_pkh: WasmDigest,
        include_lock_data: bool,
    ) -> Result<(), JsValue> {
        if notes.len() != spend_conditions.len() {
            return Err(JsValue::from_str(
                "notes and spend_conditions must have the same length",
            ));
        }

        let internal_notes: Result<Vec<(Note, SpendCondition)>, String> = notes
            .iter()
            .zip(spend_conditions.iter())
            .map(|(n, sc)| Ok((n.to_internal()?, sc.to_internal()?)))
            .collect();
        let internal_notes = internal_notes.map_err(|e| JsValue::from_str(&e.to_string()))?;

        self.builder
            .simple_spend_base(
                internal_notes,
                recipient.to_internal()?,
                gift,
                refund_pkh.to_internal()?,
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

    /// Distributes `fee` across builder's spends, and balances refunds out
    ///
    /// `adjust_fee` parameter allows the fee to be slightly tweaked, whenever notes are added or
    /// removed to/from the builder's fee note pool. This is because using more or less notes
    /// impacts the exact fee being required. If the caller estimates fee and sets it, adding more
    /// notes will change the exact fee needed, and setting this parameter to true will allow one
    /// to not have to call this function multiple times.
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

    /// Recalculate fee and set it, balancing things out with refunds
    #[wasm_bindgen(js_name = recalcAndSetFee)]
    pub fn recalc_and_set_fee(&mut self, include_lock_data: bool) -> Result<(), JsValue> {
        self.builder
            .recalc_and_set_fee(include_lock_data)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Appends `preimage_jam` to all spend conditions that expect this preimage.
    #[wasm_bindgen(js_name = addPreimage)]
    pub fn add_preimage(&mut self, preimage_jam: &[u8]) -> Result<Option<WasmDigest>, JsValue> {
        let preimage = cue(preimage_jam).ok_or("Unable to cue preimage jam")?;
        Ok(self
            .builder
            .add_preimage(preimage)
            .map(|v| WasmDigest::from_internal(&v)))
    }

    /// Sign the transaction with a private key.
    ///
    /// This will sign all spends that are still missing signature from
    #[wasm_bindgen]
    pub fn sign(&mut self, signing_key_bytes: &[u8]) -> Result<(), JsValue> {
        if signing_key_bytes.len() != 32 {
            return Err(JsValue::from_str("Private key must be 32 bytes"));
        }
        let signing_key = PrivateKey(U256::from_be_slice(signing_key_bytes));

        self.builder.sign(&signing_key);

        Ok(())
    }

    /// Validate the transaction.
    #[wasm_bindgen]
    pub fn validate(&mut self) -> Result<(), JsValue> {
        self.builder
            .validate()
            .map_err(|v| JsValue::from_str(&v.to_string()))?;

        Ok(())
    }

    /// Gets the current fee set on all spends.
    #[wasm_bindgen(js_name = curFee)]
    pub fn cur_fee(&self) -> Nicks {
        self.builder.cur_fee()
    }

    /// Calculates the fee needed for the transaction.
    ///
    /// NOTE: if the transaction is unsigned, this function will estimate the fee needed, supposing
    /// all signatures are added. However, this heuristic is only accurate for one signature. In
    /// addition, this fee calculation does not estimate the size of missing preimages.
    ///
    /// So, first, add missing preimages, and only then calc the fee. If you're building a multisig
    /// transaction, this value might be incorrect.
    #[wasm_bindgen(js_name = calcFee)]
    pub fn calc_fee(&self) -> Nicks {
        self.builder.calc_fee()
    }

    #[wasm_bindgen(js_name = allNotes)]
    pub fn all_notes(&self) -> WasmTxNotes {
        let mut ret = WasmTxNotes {
            notes: vec![],
            spend_conditions: vec![],
        };
        self.builder
            .all_notes()
            .into_values()
            .for_each(|(note, spend_condition)| {
                ret.notes.push(WasmNote::from_internal(note));
                ret.spend_conditions
                    .push(WasmSpendCondition::from_internal(spend_condition));
            });
        ret
    }

    #[wasm_bindgen]
    pub fn build(&self) -> Result<WasmNockchainTx, JsValue> {
        let tx = self.builder.build();
        Ok(WasmNockchainTx::from_internal(&tx))
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

#[wasm_bindgen(js_name = TxNotes)]
pub struct WasmTxNotes {
    #[wasm_bindgen(skip)]
    pub notes: Vec<WasmNote>,
    #[wasm_bindgen(skip)]
    pub spend_conditions: Vec<WasmSpendCondition>,
}

#[wasm_bindgen(js_class = TxNotes)]
impl WasmTxNotes {
    #[wasm_bindgen(getter)]
    pub fn notes(&self) -> Vec<WasmNote> {
        self.notes.clone()
    }

    #[wasm_bindgen(getter, js_name = spendConditions)]
    pub fn spend_conditions(&self) -> Vec<WasmSpendCondition> {
        self.spend_conditions.clone()
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
        note: WasmNote,
        spend_condition: WasmSpendCondition,
        refund_lock: Option<WasmSpendCondition>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            builder: SpendBuilder::new(
                note.to_internal()?,
                spend_condition.to_internal()?,
                refund_lock.map(|v| v.to_internal()).transpose()?,
            ),
        })
    }

    /// Set the fee of this spend
    pub fn fee(&mut self, fee: Nicks) {
        self.builder.fee(fee);
    }

    /// Compute refund from any spare assets, given `refund_lock` was passed
    #[wasm_bindgen(js_name = computeRefund)]
    pub fn compute_refund(&mut self, include_lock_data: bool) {
        self.builder.compute_refund(include_lock_data);
    }

    /// Get current refund
    #[wasm_bindgen(js_name = curRefund)]
    pub fn cur_refund(&self) -> Option<WasmSeed> {
        self.builder.cur_refund().map(|v| WasmSeed::from(v.clone()))
    }

    /// Checks whether note.assets = seeds + fee
    ///
    /// This function needs to return true for `TxBuilder::validate` to pass
    #[wasm_bindgen(js_name = isBalanced)]
    pub fn is_balanced(&self) -> bool {
        self.builder.is_balanced()
    }

    /// Add seed to this spend
    ///
    /// Seed is an output with a recipient (as defined by the spend condition).
    ///
    /// Nockchain transaction engine will take all seeds with matching lock from all spends in the
    /// transaction, and merge them into one output note.
    pub fn seed(&mut self, seed: WasmSeed) -> Result<(), JsValue> {
        self.builder.seed(seed.to_internal()?);
        Ok(())
    }

    /// Manually invalidate signatures
    ///
    /// Each spend's fee+seeds are bound to one or more signatures. If they get changed, the
    /// signature becomes invalid. This builder automatically invalidates signatures upon relevant
    /// modifications, but this functionality is provided nonetheless.
    #[wasm_bindgen(js_name = invalidateSigs)]
    pub fn invalidate_sigs(&mut self) {
        self.builder.invalidate_sigs();
    }

    /// Get the list of missing "unlocks"
    ///
    /// An unlock is a spend condition to be satisfied. For instance, for a `Pkh` spend condition,
    /// if the transaction is unsigned, this function will return a Pkh type missing unlock, with
    /// the list of valid PKH's and number of signatures needed. This will not return PKHs that are
    /// already attatched to the spend (relevant for multisigs). For `Hax` spend condition, this
    /// will return any missing preimages. This function will return a list of not-yet-validated
    /// spend conditions.
    #[wasm_bindgen(js_name = missingUnlocks)]
    pub fn missing_unlocks(&self) -> Result<Vec<JsValue>, JsValue> {
        self.builder
            .missing_unlocks()
            .into_iter()
            .map(|v| serde_wasm_bindgen::to_value(&WasmMissingUnlocks::from_internal(&v)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }

    /// Attatch a preimage to this spend
    #[wasm_bindgen(js_name = addPreimage)]
    pub fn add_preimage(&mut self, preimage_jam: &[u8]) -> Result<Option<WasmDigest>, JsValue> {
        let preimage = cue(preimage_jam).ok_or("Unable to cue preimage jam")?;
        Ok(self
            .builder
            .add_preimage(preimage)
            .map(|v| WasmDigest::from_internal(&v)))
    }

    /// Sign the transaction with a given private key
    pub fn sign(&mut self, signing_key_bytes: &[u8]) -> Result<bool, JsValue> {
        if signing_key_bytes.len() != 32 {
            return Err(JsValue::from_str("Private key must be 32 bytes"));
        }
        let signing_key = PrivateKey(U256::from_be_slice(signing_key_bytes));
        Ok(self.builder.sign(&signing_key))
    }

    fn from_internal(internal: &SpendBuilder) -> Self {
        Self {
            builder: internal.clone(),
        }
    }

    #[allow(unused)]
    fn to_internal(&self) -> SpendBuilder {
        self.builder.clone()
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

#[derive(Serialize, Deserialize)]
pub enum WasmMissingUnlocks {
    Pkh {
        num_sigs: u64,
        sig_of: BTreeSet<String>,
    },
    Hax {
        preimages_for: BTreeSet<String>,
    },
    Brn,
}

impl WasmMissingUnlocks {
    fn from_internal(internal: &MissingUnlocks) -> Self {
        match internal {
            MissingUnlocks::Pkh { num_sigs, sig_of } => Self::Pkh {
                num_sigs: *num_sigs,
                sig_of: sig_of
                    .iter()
                    .map(|v| WasmDigest::from_internal(v).value)
                    .collect(),
            },
            MissingUnlocks::Hax { preimages_for } => Self::Hax {
                preimages_for: preimages_for
                    .iter()
                    .map(|v| WasmDigest::from_internal(v).value)
                    .collect(),
            },
            MissingUnlocks::Brn => Self::Brn,
        }
    }
}

// ============================================================================
// Wasm Raw Transaction
// ============================================================================

#[wasm_bindgen(js_name = RawTx)]
pub struct WasmRawTx {
    // Store the full RawTx internally so we can convert to protobuf
    #[wasm_bindgen(skip)]
    pub(crate) internal: RawTx,
}

#[wasm_bindgen(js_class = RawTx)]
impl WasmRawTx {
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> WasmVersion {
        WasmVersion::from_internal(&self.internal.version)
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> WasmDigest {
        WasmDigest::from_internal(&self.internal.id)
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.internal.id.to_string()
    }

    fn from_internal(tx: &RawTx) -> Self {
        Self {
            internal: tx.clone(),
        }
    }

    /// Convert to protobuf RawTransaction for sending via gRPC
    #[wasm_bindgen(js_name = toProtobuf)]
    pub fn to_protobuf(&self) -> Result<JsValue, JsValue> {
        let pb_tx = pb::RawTransaction::from(self.internal.clone());
        serde_wasm_bindgen::to_value(&pb_tx)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    #[wasm_bindgen(js_name = fromProtobuf)]
    pub fn from_protobuf(value: JsValue) -> Result<WasmRawTx, JsValue> {
        let pb: pb::RawTransaction = serde_wasm_bindgen::from_value(value)?;
        let tx: RawTx = pb
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        //web_sys::console::log_1(&JsValue::from_str(&format!("{tx:?}")));
        Ok(WasmRawTx::from_internal(&tx))
    }

    /// Convert to jammed transaction file for inspecting through CLI
    #[wasm_bindgen(js_name = toJam)]
    pub fn to_jam(&self) -> js_sys::Uint8Array {
        let n = self.internal.to_noun();
        js_sys::Uint8Array::from(&jam(n)[..])
    }

    #[wasm_bindgen(js_name = fromJam)]
    pub fn from_jam(jam: &[u8]) -> Result<Self, JsValue> {
        let n = cue(jam).ok_or("Unable to decode jam")?;
        let tx: RawTx = NounDecode::from_noun(&n).ok_or("Unable to decode noun")?;
        Ok(Self::from_internal(&tx))
    }

    /// Calculate output notes from the transaction spends.
    #[wasm_bindgen]
    pub fn outputs(&self) -> Vec<WasmNote> {
        self.internal
            .outputs()
            .into_iter()
            .map(WasmNote::from_internal)
            .collect()
    }

    #[wasm_bindgen(js_name = toNockchainTx)]
    pub fn to_nockchain_tx(&self) -> WasmNockchainTx {
        WasmNockchainTx::from_internal(&self.internal.to_nockchain_tx())
    }
}

#[wasm_bindgen(js_name = NockchainTx)]
pub struct WasmNockchainTx {
    #[wasm_bindgen(skip)]
    pub(crate) internal: NockchainTx,
}

#[wasm_bindgen(js_class = NockchainTx)]
impl WasmNockchainTx {
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> WasmVersion {
        WasmVersion::from_internal(&self.internal.version)
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> WasmDigest {
        WasmDigest::from_internal(&self.internal.id)
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.internal.id.to_string()
    }

    fn from_internal(tx: &NockchainTx) -> Self {
        Self {
            internal: tx.clone(),
        }
    }

    /// Convert to jammed transaction file for inspecting through CLI
    #[wasm_bindgen(js_name = toJam)]
    pub fn to_jam(&self) -> js_sys::Uint8Array {
        let n = self.internal.to_noun();
        js_sys::Uint8Array::from(&jam(n)[..])
    }

    /// Convert from CLI-compatible jammed transaction file
    #[wasm_bindgen(js_name = fromJam)]
    pub fn from_jam(jam: &[u8]) -> Result<Self, JsValue> {
        let n = cue(jam).ok_or("Unable to decode jam")?;
        let tx: NockchainTx = NounDecode::from_noun(&n).ok_or("Unable to decode noun")?;
        Ok(Self::from_internal(&tx))
    }

    #[wasm_bindgen]
    pub fn outputs(&self) -> Vec<WasmNote> {
        self.internal
            .outputs()
            .into_iter()
            .map(WasmNote::from_internal)
            .collect()
    }

    #[wasm_bindgen(js_name = toRawTx)]
    pub fn to_raw_tx(&self) -> WasmRawTx {
        WasmRawTx::from_internal(&self.internal.to_raw_tx())
    }
}
