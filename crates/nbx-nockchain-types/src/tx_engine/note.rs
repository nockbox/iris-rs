use alloc::vec;
use alloc::vec::Vec;
use nbx_ztd::{hs, jam, Digest, Hashable, HashableString, Noun, NounDecode, NounEncode, ZMap, ZSet};
use nbx_ztd_derive::{Hashable, NounEncode};

use super::SpendCondition;

#[derive(Debug, Clone)]
pub struct Pkh {
    pub m: u64,
    pub hashes: Vec<Digest>,
}

impl Pkh {
    pub fn new(m: u64, hashes: Vec<Digest>) -> Self {
        Self { m, hashes }
    }

    pub fn single(hash: Digest) -> Self {
        Self {
            m: 1,
            hashes: vec![hash],
        }
    }
}

impl Hashable for Pkh {
    fn hash(&self) -> Digest {
        (self.m, ZSet::from_iter(self.hashes.iter())).hash()
    }
}

impl NounEncode for Pkh {
    fn to_noun(&self) -> Noun {
        (self.m, ZSet::from_iter(self.hashes.iter())).to_noun()
    }
}

impl NounDecode for Pkh {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (m, hashes) = NounDecode::from_noun(noun)?;
        Some(Self {
            m,
            hashes,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NoteData(pub ZMap<HashableString, Noun>);

impl NoteData {
    pub fn new() -> Self {
        Self(ZMap::new())
    }

    pub fn blob(&self) -> Vec<u8> {
        jam(self.0.to_noun())
    }

    pub fn lock(&self) -> Option<Vec<SpendCondition>> {
        let pkh_noun = self.0.get(hs("lock"))?;
        // TODO: finish implementing this
        None
    }

    pub fn push_lock(&mut self, lock: &[SpendCondition]) {
        self.0.insert(hs("lock").into(), lock.to_noun());
    }
}

impl NounEncode for NoteData {
    fn to_noun(&self) -> Noun {
        self.0.to_noun()
    }
}

impl Hashable for NoteData {
    fn hash(&self) -> Digest {
        self.0.hash()
    }
}

#[derive(Debug, Clone, Hashable)]
pub struct Note {
    pub version: Version,
    pub origin_page: BlockHeight,
    pub name: Name,
    pub note_data: ZMap<HashableString, Noun>,
    pub assets: Nicks,
}

impl Note {
    pub fn new(
        version: Version,
        origin_page: BlockHeight,
        name: Name,
        note_data: ZMap<HashableString, Noun>,
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
}

pub type Nicks = u64;

#[derive(Debug, Clone)]
pub struct Balance(pub Vec<(Name, Note)>);

pub type BlockHeight = u64;

#[derive(Debug, Clone)]
pub struct BalanceUpdate {
    pub height: BlockHeight,
    pub block_id: Digest,
    pub notes: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    V0,
    V1,
    V2,
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

#[derive(Clone, Debug, Hashable, NounEncode)]
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
}

#[derive(Debug, Clone, Hashable, NounEncode)]
pub struct Source {
    pub hash: Digest,
    pub is_coinbase: bool,
}

/// Timelock range (for both absolute and relative constraints)
#[derive(Debug, Clone, Hashable, NounEncode)]
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
