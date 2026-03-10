use super::note::{Note, Version};
use crate::Nicks;
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

#[iris_ztd_derive::wasm_member_methods]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct TxEngineSettings {
    pub tx_engine_version: Version,
    pub tx_engine_patch: u64,
    pub min_fee: Nicks,
    pub cost_per_word: Nicks,
    pub witness_word_div: u64,
}

impl TxEngineSettings {
    pub fn v1_with_word_cost(cost_per_word: Nicks) -> Self {
        Self {
            tx_engine_version: Version::V1,
            tx_engine_patch: 0,
            min_fee: 256u64.into(),
            cost_per_word,
            witness_word_div: 1,
        }
    }

    pub fn v1_default() -> Self {
        Self::v1_with_word_cost((1 << 15).into())
    }

    pub fn v1_bythos_with_word_cost(cost_per_word: Nicks) -> Self {
        Self {
            tx_engine_version: Version::V1,
            tx_engine_patch: 1,
            min_fee: 256u64.into(),
            cost_per_word,
            witness_word_div: 4,
        }
    }

    pub fn v1_bythos_default() -> Self {
        Self::v1_bythos_with_word_cost((1 << 14).into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct BlockchainConstants {
    pub first_month_coinbase_min: u32,
    pub coinbase_timelock_min: u32,
}

impl Default for BlockchainConstants {
    fn default() -> Self {
        Self::mainnet()
    }
}

#[iris_ztd_derive::wasm_member_methods]
impl BlockchainConstants {
    pub const fn mainnet() -> Self {
        Self {
            first_month_coinbase_min: 4383,
            coinbase_timelock_min: 100,
        }
    }
}

/// A Nockchain Block
///
/// This includes necessary information about a block, but does not include transactions (only their IDs are provided).
#[iris_ztd::noun_derive(
    Debug,
    Clone,
    NounEncode,
    NounDecode,
    Hashable,
    Serialize,
    Deserialize,
    tsify_wasm
)]
#[iris_ztd::wasm_noun_codec(with_prove, no_derive, noun_tag = "version")]
pub enum Page {
    #[noun(cell)]
    V0(crate::v0::PageV0),
    #[noun(tag = 1)]
    V1(crate::v1::PageV1),
}

#[cfg_attr(feature = "wasm", iris_ztd::wasm_member_methods)]
impl Page {
    /// Compute coinbase notes of this block
    pub fn coinbase(&self, consts: BlockchainConstants) -> Vec<Note> {
        match self {
            Self::V0(p) => p.coinbase(consts),
            Self::V1(p) => p.coinbase(consts),
        }
    }

    pub fn block_commitment(&self) -> Digest {
        match self {
            Self::V0(p) => p.block_commitment(),
            Self::V1(p) => p.block_commitment(),
        }
    }
}
