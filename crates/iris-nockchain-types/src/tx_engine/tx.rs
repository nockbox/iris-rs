use super::note::{Note, Version};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use iris_crypto::{PrivateKey, PublicKey, Signature};
use iris_ztd::{Digest, Hashable as HashableTrait, Noun, NounDecode, NounEncode, ZMap, ZSet};
use iris_ztd_derive::{Hashable, NounDecode, NounEncode};

use crate::Nicks;

pub type TxId = Digest;

#[derive(Debug, Clone)]
pub enum RawTx {
    V0(super::v0::RawTx),
    V1(super::v1::RawTx),
}

impl RawTx {
    pub fn id(&self) -> TxId {
        match self {
            RawTx::V0(tx) => tx.id,
            RawTx::V1(tx) => tx.id,
        }
    }

    pub fn version(&self) -> Version {
        match self {
            RawTx::V0(_) => Version::V0,
            RawTx::V1(_) => Version::V1,
        }
    }

    pub fn outputs(&self) -> Vec<Note> {
        match self {
            RawTx::V0(tx) => tx.outputs().into_iter().map(Note::V0).collect(),
            RawTx::V1(tx) => tx.outputs().into_iter().map(Note::V1).collect(),
        }
    }
}

impl NounEncode for RawTx {
    fn to_noun(&self) -> Noun {
        match self {
            RawTx::V0(tx) => tx.to_noun(),
            RawTx::V1(tx) => (1u32, tx).to_noun(),
        }
    }
}

impl NounDecode for RawTx {
    fn from_noun(noun: &Noun) -> Option<Self> {
        // TODO: instead check whether head is a cell or an atom
        if let Some(tx) = super::v0::RawTx::from_noun(noun) {
            return Some(RawTx::V0(tx));
        }
        let (version, tx): (u32, super::v1::RawTx) = NounDecode::from_noun(noun)?;
        match version {
            1 => Some(RawTx::V1(tx)),
            _ => None,
        }
    }
}
