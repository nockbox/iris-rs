use alloc::{string::String, vec::Vec};
use nbx_ztd::{Belt, Digest, Hashable as HashableTrait, ZSet};
use nbx_ztd_derive::{Hashable, NounHashable};

#[derive(Debug, Clone, Hashable)]
pub struct Pkh {
    pub m: u64,
    pub hashes: ZSet<Digest>,
}

impl Pkh {
    pub fn new(m: u64, hashes: Vec<Digest>) -> Self {
        Self {
            m,
            hashes: ZSet::from_iter(hashes),
        }
    }
}

#[derive(Debug, Clone, Hashable)]
pub struct NoteData(pub ZMap<(String, HashableTrait)>);

#[derive(Debug, Clone, Hashable)]
pub struct Note {
    pub version: Version,
    pub origin_page: BlockHeight,
    pub name: Name,
    pub note_data: NoteData,
    pub assets: Nicks,
}

impl Note {
    pub fn new(
        version: Version,
        origin_page: BlockHeight,
        name: Name,
        note_data: NoteData,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hashable, NounHashable)]
pub struct Nicks(pub usize);

#[derive(Debug, Clone)]
pub struct Balance(pub Vec<(Name, Note)>);

#[derive(Debug, Clone, PartialEq, Eq, Hashable, NounHashable)]
pub struct BlockHeight(pub Belt);

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

impl HashableTrait for Version {
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

#[derive(Clone, Debug, Hashable)]
pub struct Name {
    pub first: Digest,
    pub last: Digest,
}

#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct Source {
    pub hash: Digest,
    pub is_coinbase: bool,
}

/// Timelock range (for both absolute and relative constraints)
#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct TimelockRange {
    pub min: Option<BlockHeight>,
    pub max: Option<BlockHeight>,
}

impl TimelockRange {
    pub fn new(min: Option<BlockHeight>, max: Option<BlockHeight>) -> Self {
        let min = min.filter(|height| (height.0).0 != 0);
        let max = max.filter(|height| (height.0).0 != 0);
        Self { min, max }
    }

    pub fn none() -> Self {
        Self {
            min: None,
            max: None,
        }
    }
}
