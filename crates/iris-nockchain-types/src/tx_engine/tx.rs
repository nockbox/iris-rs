use super::note::{BlockHeight, Name, Note, Version};
use crate::Nicks;
use alloc::vec::Vec;
use iris_ztd::{Bignum, Digest, Noun, ZSet};

#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};

pub type TxId = Digest;

use serde::{Deserialize, Serialize};

#[iris_ztd::noun_derive(
    Debug,
    Clone,
    NounEncode,
    NounDecode,
    Serialize,
    Deserialize,
    tsify_wasm
)]
#[iris_ztd::wasm_noun_codec(no_derive, no_hash, noun_tag = "version")]
pub enum Tx {
    #[noun(tag = 0)]
    V0(crate::v0::TxV0),
    #[noun(tag = 1)]
    V1(crate::v1::TxV1),
}

impl Tx {
    pub fn version(&self) -> Version {
        match self {
            Tx::V0(_) => Version::V0,
            Tx::V1(_) => Version::V1,
        }
    }

    pub fn total_size(&self) -> u64 {
        match self {
            Tx::V0(tx) => tx.total_size,
            Tx::V1(tx) => tx.total_size,
        }
    }

    pub fn outputs(&self) -> Outputs {
        match self {
            Tx::V0(tx) => Outputs::V0(tx.outputs.clone()),
            Tx::V1(tx) => Outputs::V1(tx.outputs.clone()),
        }
    }

    pub fn raw(&self) -> RawTx {
        match self {
            Tx::V0(tx) => RawTx::V0(tx.raw.clone()),
            Tx::V1(tx) => RawTx::V1(tx.raw.clone()),
        }
    }
}

#[iris_ztd::noun_derive(Debug, Clone, Serialize, Deserialize, tsify_wasm)]
pub enum Outputs {
    #[noun(tag = 0)]
    V0(crate::v0::OutputsV0),
    #[noun(tag = 1)]
    V1(crate::v1::OutputsV1),
}

impl Outputs {
    pub fn notes(&self) -> Vec<Note> {
        match self {
            Self::V0(o) => o.0.iter().map(|e| Note::V0(e.1.note.clone())).collect(),
            Self::V1(o) => o.0.iter().map(|e| Note::V1(e.note.clone())).collect(),
        }
    }
}

#[iris_ztd::noun_derive(
    Debug,
    Clone,
    NounEncode,
    NounDecode,
    Serialize,
    Deserialize,
    tsify_wasm
)]
#[iris_ztd::wasm_noun_codec(no_derive, no_hash, noun_tag = "version")]
pub enum RawTx {
    #[noun(cell)]
    V0(crate::v0::RawTxV0),
    #[noun(embedded_tag)]
    V1(crate::v1::RawTxV1),
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

    pub fn outputs(
        &self,
        block_height: BlockHeight,
        tx_engine_settings: TxEngineSettings,
    ) -> Vec<Note> {
        match self {
            RawTx::V0(tx) => tx.outputs(block_height).into_iter().map(Note::V0).collect(),
            RawTx::V1(tx) => tx
                .outputs(block_height, tx_engine_settings)
                .into_iter()
                .map(Note::V1)
                .collect(),
        }
    }

    pub fn input_names(&self) -> Vec<Name> {
        match self {
            RawTx::V0(tx) => tx.input_names(),
            RawTx::V1(tx) => tx.input_names(),
        }
    }

    pub fn total_fees(&self) -> Nicks {
        match self {
            RawTx::V0(tx) => tx.total_fees,
            RawTx::V1(tx) => tx.spends.total_fees(),
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

    pub fn v0_default() -> Self {
        Self {
            tx_engine_version: Version::V0,
            tx_engine_patch: 0,
            min_fee: 0u64.into(),
            cost_per_word: 0u64.into(),
            witness_word_div: 0,
        }
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

impl Page {
    pub fn pow_mut(&mut self) -> &mut Option<Noun> {
        match self {
            Self::V0(p) => &mut p.pow,
            Self::V1(p) => &mut p.pow,
        }
    }

    pub fn version(&self) -> Version {
        match self {
            Self::V0(_) => Version::V0,
            Self::V1(_) => Version::V1,
        }
    }

    pub fn parent(&self) -> Digest {
        match self {
            Page::V0(p) => p.parent,
            Page::V1(p) => p.parent,
        }
    }

    pub fn tx_ids(&self) -> &ZSet<Digest> {
        match self {
            Page::V0(p) => &p.tx_ids,
            Page::V1(p) => &p.tx_ids,
        }
    }

    pub fn timestamp(&self) -> crate::v0::ChainTimestamp {
        match self {
            Page::V0(p) => p.timestamp,
            Page::V1(p) => p.timestamp,
        }
    }

    pub fn epoch_counter(&self) -> u32 {
        match self {
            Page::V0(p) => p.epoch_counter,
            Page::V1(p) => p.epoch_counter,
        }
    }

    pub fn target(&self) -> &Bignum {
        match self {
            Page::V0(p) => &p.target,
            Page::V1(p) => &p.target,
        }
    }

    pub fn accumulated_work(&self) -> &Bignum {
        match self {
            Page::V0(p) => &p.accumulated_work,
            Page::V1(p) => &p.accumulated_work,
        }
    }

    pub fn height(&self) -> &crate::BlockHeight {
        match self {
            Page::V0(p) => &p.height,
            Page::V1(p) => &p.height,
        }
    }

    pub fn msg(&self) -> &crate::v0::PageMsg {
        match self {
            Page::V0(p) => &p.msg,
            Page::V1(p) => &p.msg,
        }
    }
}
