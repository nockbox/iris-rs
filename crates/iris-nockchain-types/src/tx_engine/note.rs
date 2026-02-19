use alloc::vec::Vec;
use alloc::{boxed::Box, format, string::ToString};
use core::convert::TryFrom;
use iris_ztd::{Digest, Hashable, Noun, NounDecode, NounEncode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type Nicks = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
pub enum Note {
    V0(super::v0::NoteV0),
    V1(super::v1::NoteV1),
}

impl Note {
    pub fn version(&self) -> Version {
        match self {
            Note::V0(_) => Version::V0,
            Note::V1(_) => Version::V1,
        }
    }

    pub fn name(&self) -> Name {
        match self {
            Note::V0(n) => n.name,
            Note::V1(n) => n.name,
        }
    }

    pub fn assets(&self) -> Nicks {
        match self {
            Note::V0(n) => n.assets,
            Note::V1(n) => n.assets,
        }
    }

    pub fn origin_page(&self) -> BlockHeight {
        match self {
            Note::V0(n) => n.inner.origin_page,
            Note::V1(n) => n.origin_page,
        }
    }
}

impl Hashable for Note {
    fn hash(&self) -> Digest {
        match self {
            Note::V0(n) => n.hash(),
            Note::V1(n) => n.hash(),
        }
    }
}

impl NounDecode for Note {
    fn from_noun(noun: &Noun) -> Option<Self> {
        if let Some(n) = super::v0::NoteV0::from_noun(noun) {
            return Some(Note::V0(n));
        }

        let v: u32 = NounDecode::from_noun(noun)?;

        Some(match v {
            1 => Note::V1(super::v1::NoteV1::from_noun(noun)?),
            _ => return None,
        })
    }
}

impl NounEncode for Note {
    fn to_noun(&self) -> Noun {
        match self {
            Note::V0(n) => n.to_noun(),
            Note::V1(n) => n.to_noun(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Balance(pub Vec<(Name, Note)>);

pub type BlockHeight = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct BalanceUpdate {
    pub height: BlockHeight,
    pub block_id: Digest,
    pub notes: Balance,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedVersion<const V: u32>;

impl<const V: u32> Serialize for ExpectedVersion<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(V)
    }
}

impl<'de, const V: u32> Deserialize<'de> for ExpectedVersion<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = u32::deserialize(deserializer)?;
        if v != V {
            return Err(serde::de::Error::custom("Invalid version"));
        }
        Ok(ExpectedVersion)
    }
}

impl<const V: u32> NounEncode for ExpectedVersion<V> {
    fn to_noun(&self) -> Noun {
        u32::from(V).to_noun()
    }
}

impl<const V: u32> NounDecode for ExpectedVersion<V> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let v: u32 = NounDecode::from_noun(noun)?;

        if v != V {
            return None;
        }

        Some(ExpectedVersion)
    }
}

impl<const V: u32> TryFrom<Version> for ExpectedVersion<V> {
    type Error = ();

    fn try_from(value: Version) -> Result<Self, Self::Error> {
        if value as u32 != V {
            return Err(());
        }
        Ok(ExpectedVersion)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "wasm", tsify(type = "0 | 1 | 2"))]
#[repr(u32)]
pub enum Version {
    V0 = 0,
    V1 = 1,
    V2 = 2,
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(*self as u32)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = u32::deserialize(deserializer)?;
        TryFrom::try_from(v).map_err(|_| serde::de::Error::custom("Invalid version"))
    }
}

impl NounEncode for Version {
    fn to_noun(&self) -> Noun {
        u32::from(*self).to_noun()
    }
}

impl NounDecode for Version {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let v: u32 = NounDecode::from_noun(noun)?;

        Some(match v {
            0 => Version::V0,
            1 => Version::V1,
            2 => Version::V2,
            _ => return None,
        })
    }
}

impl Hashable for Version {
    fn hash(&self) -> Digest {
        (*self as u32 as u64).hash()
    }
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self {
        version as u32
    }
}

impl TryFrom<u32> for Version {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V0),
            1 => Ok(Version::V1),
            2 => Ok(Version::V2),
            _ => Err(()),
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Hashable,
    NounEncode,
    NounDecode,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Name {
    pub first: Digest,
    pub last: Digest,
    _sig: u64, // end-of-list marker
}

impl Name {
    pub fn new(first: Digest, last: Digest) -> Self {
        Self {
            first,
            last,
            _sig: 0,
        }
    }

    pub fn new_v1(lock: Digest, source: Source) -> Self {
        let first = (true, lock).hash();
        let last = (true, source.hash(), 0).hash();
        Self::new(first, last)
    }

    pub fn new_v0(
        owners: super::v0::Sig,
        source: Source,
        timelock: super::v0::TimelockIntent,
    ) -> Self {
        let first = (true, timelock.tim.is_some(), &owners, 0).hash();
        let last = (true, &source, &timelock, 0).hash();
        Self::new(first, last)
    }
}

#[derive(
    Debug, Clone, Copy, Hashable, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq,
)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Source {
    pub hash: Digest,
    pub is_coinbase: bool,
}

/// Timelock range (for both absolute and relative constraints)
#[derive(
    Debug, Clone, Copy, Hashable, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq,
)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct TimelockRange {
    pub min: Option<BlockHeight>,
    pub max: Option<BlockHeight>,
}

impl TimelockRange {
    pub fn new(min: Option<BlockHeight>, max: Option<BlockHeight>) -> Self {
        let min = min.filter(|&height| height != 0);
        let max = max.filter(|&height| height != 0);
        Self { min, max }
    }

    pub fn none() -> Self {
        Self {
            min: None,
            max: None,
        }
    }
}
