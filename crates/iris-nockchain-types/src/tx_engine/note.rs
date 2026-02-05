use alloc::vec::Vec;
use iris_ztd::{Digest, Hashable, Noun, NounDecode, NounEncode};
use serde::{Deserialize, Serialize};

pub type Nicks = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Note {
    V0(super::v0::Note),
    V1(super::v1::Note),
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
        if let Some(n) = super::v0::Note::from_noun(noun) {
            return Some(Note::V0(n));
        }

        let v: u32 = NounDecode::from_noun(noun)?;

        Some(match v {
            1 => Note::V1(super::v1::Note::from_noun(noun)?),
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

#[derive(Debug, Clone)]
pub struct Balance(pub Vec<(Name, Note)>);

pub type BlockHeight = u64;

#[derive(Debug, Clone)]
pub struct BalanceUpdate {
    pub height: BlockHeight,
    pub block_id: Digest,
    pub notes: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    V0,
    V1,
    V2,
}

impl NounEncode for Version {
    fn to_noun(&self) -> Noun {
        u32::from(self.clone()).to_noun()
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
        match self {
            Version::V0 => 0,
            Version::V1 => 1,
            Version::V2 => 2,
        }
        .hash()
    }
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self {
        match version {
            Version::V0 => 0,
            Version::V1 => 1,
            Version::V2 => 2,
        }
    }
}

impl From<u32> for Version {
    fn from(version: u32) -> Self {
        match version {
            0 => Version::V0,
            1 => Version::V1,
            2 => Version::V2,
            _ => panic!("Invalid version"),
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
pub struct Source {
    pub hash: Digest,
    pub is_coinbase: bool,
}

/// Timelock range (for both absolute and relative constraints)
#[derive(
    Debug, Clone, Copy, Hashable, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq,
)]
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
