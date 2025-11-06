use alloc::vec;
use alloc::vec::Vec;
use nbx_ztd::{Belt, Digest, Hashable as HashableTrait, NounHashable, ZSet};
use nbx_ztd_derive::{Hashable, NounHashable};

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

impl HashableTrait for Pkh {
    fn hash(&self) -> Digest {
        (self.m, ZSet::from_iter(self.hashes.iter())).hash()
    }
}

impl NounHashable for Pkh {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        (self.m, ZSet::from_iter(self.hashes.iter())).write_noun_parts(leaves, dyck)
    }
}

#[derive(Debug, Clone)]
pub struct NoteData(pub Pkh); // TODO: make more generic

impl HashableTrait for NoteData {
    fn hash(&self) -> Digest {
        let z = ZSet::from_iter(self.0.hashes.iter().map(|d| &d.0[..]));
        (("lock", (0, (("pkh", (self.0.m, z)), 0))), (0, 0)).hash()
    }
}

impl NounHashable for NoteData {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        let z = ZSet::from_iter(self.0.hashes.iter().map(|d| &d.0[..]));
        (("lock", (0, (("pkh", (self.0.m, z)), 0))), (0, 0)).write_noun_parts(leaves, dyck);
    }
}

#[derive(Debug, Clone, Hashable)]
pub struct Note {
    pub version: Version,
    pub origin_page: BlockHeight,
    pub name: Name,
    pub note_data_hash: Digest,
    pub assets: Nicks,
}

impl Note {
    pub fn new(
        version: Version,
        origin_page: BlockHeight,
        name: Name,
        note_data_hash: Digest,
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
}

pub type Nicks = usize;

#[derive(Debug, Clone)]
pub struct Balance(pub Vec<(Name, Note)>);

pub type BlockHeight = usize;

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

#[derive(Clone, Debug, Hashable, NounHashable)]
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
