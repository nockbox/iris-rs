use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{string::String, vec};
use iris_ztd::{Digest, Hashable, Noun, NounDecode, NounEncode, ZSet};
use iris_ztd_derive::{Hashable, NounDecode, NounEncode};
use serde::{Deserialize, Serialize};

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
        (self.m, ZSet::from_iter(&self.hashes)).hash()
    }
}

impl NounEncode for Pkh {
    fn to_noun(&self) -> Noun {
        (self.m, ZSet::from_iter(&self.hashes)).to_noun()
    }
}

impl NounDecode for Pkh {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (m, hashes): (u64, ZSet<Digest>) = NounDecode::from_noun(noun)?;

        Some(Pkh {
            m,
            hashes: hashes.into_iter().collect(),
        })
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize)]
pub struct NoteDataEntry {
    pub key: String,
    pub val: Noun,
}

impl Hashable for NoteDataEntry {
    fn hash(&self) -> Digest {
        fn hash_noun(noun: &Noun) -> Digest {
            match noun {
                Noun::Atom(a) => {
                    let u: u64 = a.try_into().unwrap();
                    u.hash()
                }
                Noun::Cell(left, right) => (hash_noun(left), hash_noun(right)).hash(),
            }
        }
        (self.key.as_str(), hash_noun(&self.val)).hash()
    }
}

pub const MEMO_KEY: &str = "memo";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteData {
    pub entries: Vec<NoteDataEntry>
}

impl NoteData {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new()
        }
    }

    pub fn push_pkh(&mut self, pkh: Pkh) {
        self.entries.push(NoteDataEntry {
            key: "lock".to_string(),
            val: (0, ("pkh", &pkh), 0).to_noun(),
        });
    }

    // TODO: support 2,4,8,16-way spend conditions.
    pub fn push_lock(&mut self, spend_condition: SpendCondition) {
        self.entries.push(NoteDataEntry {
            key: "lock".to_string(),
            val: (0, spend_condition).to_noun(),
        });
    }

    pub fn from_pkh(pkh: Pkh) -> Self {
        let mut ret = Self::empty();
        ret.push_pkh(pkh);
        ret
    }

    pub fn set_memo(&mut self, memo: Noun) {
        self.entries.push(NoteDataEntry {
            key: MEMO_KEY.to_string(),
            val: memo.clone(),
        });
    }
}

impl NounEncode for NoteData {
    fn to_noun(&self) -> Noun {
        ZSet::from_iter(&self.entries).to_noun()
    }
}
impl NounDecode for NoteData {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let set = ZSet::<NoteDataEntry>::from_noun(noun)?;
        let entries: Vec<NoteDataEntry> = set.into_iter().collect();
        Some(Self { entries })
    }
}

impl Hashable for NoteData {
    fn hash(&self) -> Digest {
        ZSet::from_iter(&self.entries).hash()
    }
}

#[derive(Debug, Clone, Hashable, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode)]
pub struct Source {
    pub hash: Digest,
    pub is_coinbase: bool,
}

/// Timelock range (for both absolute and relative constraints)
#[derive(Debug, Clone, Hashable, NounEncode, NounDecode)]
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
