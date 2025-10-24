use alloc::vec::Vec;
use nbx_crypto::PublicKey;
use nbx_ztd::{Belt, Digest, Hashable as HashableTrait, ZSet};
use nbx_ztd_derive::{Hashable, NounHashable};

#[derive(Debug, Clone, NounHashable)]
pub struct Lock {
    pub keys_required: u64,
    pub pubkeys: Vec<PublicKey>,
}

impl Lock {
    pub fn new(keys_required: u64, pubkeys: Vec<PublicKey>) -> Self {
        Self {
            keys_required,
            pubkeys,
        }
    }
}

impl HashableTrait for Lock {
    fn hash(&self) -> Digest {
        let pubkey_hashes = self.pubkeys.iter().map(PublicKey::hash);
        (self.keys_required, pubkey_hashes.collect::<ZSet<_>>()).hash()
    }
}

#[derive(Debug, Clone)]
pub struct Note {
    pub head: NoteHead,
    pub tail: NoteTail,
}

#[derive(Debug, Clone)]
pub struct NoteHead {
    pub version: Version,
    pub origin_page: BlockHeight,
    pub timelock: Timelock,
}

#[derive(Debug, Clone)]
pub struct NoteTail {
    pub name: Name,
    pub lock: Lock,
    pub source: Source,
    pub assets: Nicks,
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

#[derive(Clone, Debug)]
pub struct Name {
    pub first: Digest,
    pub last: Digest,
}

#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct Source {
    pub hash: Digest,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Hashable)]
pub struct Timelock(pub Option<TimelockIntent>);

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

#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct TimelockIntent {
    pub absolute: TimelockRange,
    pub relative: TimelockRange,
}

impl TimelockIntent {
    pub fn none() -> Self {
        Self {
            absolute: TimelockRange::none(),
            relative: TimelockRange::none(),
        }
    }
}
