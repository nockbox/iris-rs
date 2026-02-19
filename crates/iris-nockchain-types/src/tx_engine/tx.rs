use super::note::{Note, Version};
use alloc::vec::Vec;
use iris_ztd::{Digest, Noun, NounDecode, NounEncode};

#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};

pub type TxId = Digest;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
pub enum RawTx {
    V0(super::v0::RawTxV0),
    V1(super::v1::RawTxV1),
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
        if let Some(tx) = super::v0::RawTxV0::from_noun(noun) {
            return Some(RawTx::V0(tx));
        }
        let (version, tx): (u32, super::v1::RawTxV1) = NounDecode::from_noun(noun)?;
        match version {
            1 => Some(RawTx::V1(tx)),
            _ => None,
        }
    }
}
