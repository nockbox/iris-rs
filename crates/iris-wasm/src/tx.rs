use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use iris_crypto::PrivateKey as CryptoPrivateKey;
use iris_grpc_proto::pb::common::v1 as pb_v1;
use iris_grpc_proto::pb::common::v2 as pb;
use iris_nockchain_types::{
    builder::{MissingUnlocks, TxBuilder},
    note::Note,
    tx::RawTx,
    v1::{Lock, LockRoot, NockchainTx, RawTxV1, SeedV1 as Seed, SpendCondition},
    Nicks, SpendBuilder, TxEngineSettings,
};
use iris_ztd::{cue, Digest, U256};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::memo::memo_from_js;

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
        Ok(NoteData { entries: entries? })
    }

    fn from_internal(note_data: &NoteData) -> Self {
        Self {
            entries: note_data
                .entries
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
        memo: Option<JsValue>,
    ) -> Result<Self, JsValue> {
        let memo = memo_from_js(memo)?;
        let seed = Seed::new_single_pkh(
            pkh.to_internal()?,
            gift,
            parent_hash.to_internal()?,
            include_lock_data,
            memo,
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
=======
>>>>>>> upstream/main
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
=======
>>>>>>> upstream/main
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
        memo: Option<JsValue>,
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
        let internal_notes = internal_notes.map_err(|e| JsValue::from_str(&e.to_string()))?;
        let memo = memo_from_js(memo)?;

        self.builder
            .simple_spend_base(
                internal_notes,
                recipient,
                gift,
                refund_pkh,
                include_lock_data,
                memo,
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
