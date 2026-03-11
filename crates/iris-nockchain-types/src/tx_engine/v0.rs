use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use alloc::{boxed::Box, format, string::ToString};
use core::fmt;
use iris_crypto::{PublicKey, Signature};
use iris_ztd::{Belt, Bignum, Digest, Hashable, Noun, NounDecode, NounEncode, ZMap, ZSet};
use serde::{Deserialize, Serialize};

use super::note::{BlockHeight, Name, Note, Source, TimelockRange, Version};
use super::{BlockchainConstants, TxId};
use crate::Nicks;

#[derive(
    Debug, Clone, Copy, Hashable, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq,
)]
#[iris_ztd::wasm_noun_codec]
pub struct NoteInner {
    pub version: Version,
    pub origin_page: BlockHeight,
    // NOTE: not really intent, but timelock is just intent without double null case, which we can accept.
    pub timelock: TimelockIntent,
}

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq)]
#[iris_ztd::wasm_noun_codec]
pub struct NoteV0 {
    pub inner: NoteInner,
    pub name: Name,
    pub sig: Sig,
    pub source: Source,
    pub assets: Nicks,
}

impl NoteV0 {
    pub fn new(
        version: Version,
        origin_page: BlockHeight,
        timelock: TimelockIntent,
        name: Name,
        sig: Sig,
        source: Source,
        assets: Nicks,
    ) -> Self {
        Self {
            inner: NoteInner {
                version,
                origin_page,
                timelock,
            },
            name,
            sig,
            source,
            assets,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, Hashable, NounDecode, NounEncode)]
#[iris_ztd::wasm_noun_codec]
pub struct LegacySignature(pub ZMap<PublicKey, Signature>);

impl LegacySignature {
    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn add_entry(&mut self, pubkey: PublicKey, signature: Signature) {
        self.0.insert(pubkey, signature);
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hashable,
    NounDecode,
    NounEncode,
    Serialize,
    Deserialize,
)]
#[iris_ztd::wasm_noun_codec]
pub struct Sig {
    pub m: u64,
    pub pubkeys: ZSet<PublicKey>,
}

impl Sig {
    pub fn new_single_pk(pk: PublicKey) -> Self {
        Self {
            m: 1,
            pubkeys: ZSet::from([pk]),
        }
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct Input {
    pub note: NoteV0,
    pub spend: SpendV0,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct SpendV0 {
    pub signature: Option<LegacySignature>,
    pub seeds: SeedsV0,
    pub fee: Nicks,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec(no_hash)]
pub struct RawTxV0 {
    pub id: TxId,
    pub inputs: Inputs,
    pub timelock_range: TimelockRange,
    pub total_fees: Nicks,
}

impl RawTxV0 {
    pub fn version(&self) -> Version {
        Version::V0
    }

    /// Calculate output notes from the transaction inputs.
    ///
    /// This function combines seeds across multiple inputs into one output note per-recipient-sig.
    pub fn outputs(&self) -> Vec<NoteV0> {
        let inps = &self.inputs.0;

        let mut output_base: BTreeMap<Sig, (TimelockIntent, Nicks, ZSet<SeedV0>)> = BTreeMap::new();

        for (_, input) in inps {
            for seed in &input.spend.seeds.0 {
                // NOTE: we are not checking if we're adding duplicate seed or not. Not necessary when processing valid txs.
                let sig = seed.recipient.clone();
                let child = output_base
                    .entry(sig)
                    .or_insert_with(|| (TimelockIntent::default(), Nicks(0), ZSet::new()));
                // NOTE: in hoon, we see:
                //
                // =?  timelock.note.chi  !=(~ timelock-intent.seed)
                //  (reconcile timelock.note.child timelock-intent.seed)
                //
                // Note that it's reconciling timelock.note.child, not timelock.note.chi.
                // This effectively means, that the reconcile code is useless - it will just
                // keep timelock intent of the last seed.
                if let Some(tl) = seed.timelock_intent.tim.filter(|v| *v != Timelock::none()) {
                    child.0.tim = Some(tl);
                }
                child.1 += seed.gift;
                child.2.insert(seed.clone());
            }
        }

        let mut outputs = vec![];

        for (sig, (timelock, assets, seeds)) in output_base {
            let source = Source {
                hash: seeds.hash(),
                is_coinbase: false,
            };
            outputs.push(NoteV0 {
                name: Name::new_v0(sig.clone(), source, timelock),
                sig,
                source,
                assets,
                inner: NoteInner {
                    version: Version::V0,
                    origin_page: BlockHeight::default(),
                    timelock,
                },
            });
        }

        outputs
    }

    pub fn calc_id(&self) -> TxId {
        (&self.inputs, &self.timelock_range, &self.total_fees).hash()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Hashable, NounDecode, NounEncode)]
#[iris_ztd::wasm_noun_codec]
pub struct Inputs(pub ZMap<Name, Input>);

#[derive(
    Debug, Clone, Copy, NounEncode, Hashable, NounDecode, Serialize, Deserialize, PartialEq, Eq,
)]
#[iris_ztd::wasm_noun_codec]
pub struct Timelock {
    pub abs: TimelockRange,
    pub rel: TimelockRange,
}

impl Timelock {
    pub fn coinbase() -> Self {
        Self {
            rel: TimelockRange {
                min: Some(100),
                max: None,
            },
            abs: TimelockRange::none(),
        }
    }

    pub fn none() -> Self {
        Self {
            rel: TimelockRange::none(),
            abs: TimelockRange::none(),
        }
    }
}

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    NounEncode,
    NounDecode,
    Hashable,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
)]
#[iris_ztd::wasm_noun_codec]
pub struct TimelockIntent {
    pub tim: Option<Timelock>,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq)]
#[iris_ztd::wasm_noun_codec]
pub struct SeedV0 {
    pub output_source: Option<Source>,
    pub recipient: Sig,
    pub timelock_intent: TimelockIntent,
    pub gift: Nicks,
    pub parent_hash: Digest,
}

impl SeedV0 {
    pub fn new_single_pk(pk: PublicKey, gift: Nicks, parent_hash: Digest) -> Self {
        let recipient = Sig::new_single_pk(pk);
        Self {
            output_source: None,
            recipient,
            timelock_intent: TimelockIntent { tim: None },
            gift,
            parent_hash,
        }
    }
}

impl Hashable for SeedV0 {
    fn hash(&self) -> Digest {
        // output source is omitted
        (
            &self.recipient,
            &self.timelock_intent,
            &self.gift,
            &self.parent_hash,
        )
            .hash()
    }

    fn leaf_count(&self) -> usize {
        (
            &self.recipient,
            (&self.timelock_intent, &self.gift, &self.parent_hash),
        )
            .leaf_count()
    }

    fn hashable_pair<'a>(&'a self) -> Option<(impl Hashable + 'a, impl Hashable + 'a)> {
        Some((
            &self.recipient,
            (&self.timelock_intent, &self.gift, &self.parent_hash),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SigHashSeedV0<'a>(&'a SeedV0);

impl Hashable for SigHashSeedV0<'_> {
    fn hash(&self) -> Digest {
        // output source is included
        (
            &self.0.output_source,
            &self.0.recipient,
            &self.0.timelock_intent,
            &self.0.gift,
            &self.0.parent_hash,
        )
            .hash()
    }

    fn leaf_count(&self) -> usize {
        (
            &self.0.output_source,
            (
                &self.0.recipient,
                &self.0.timelock_intent,
                &self.0.gift,
                &self.0.parent_hash,
            ),
        )
            .leaf_count()
    }

    fn hashable_pair<'a>(&'a self) -> Option<(impl Hashable + 'a, impl Hashable + 'a)> {
        Some((
            &self.0.output_source,
            (
                &self.0.recipient,
                &self.0.timelock_intent,
                &self.0.gift,
                &self.0.parent_hash,
            ),
        ))
    }
}

impl<'a> NounEncode for SigHashSeedV0<'a> {
    fn to_noun(&self) -> Noun {
        self.0.to_noun()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hashable, NounDecode, NounEncode)]
#[iris_ztd::wasm_noun_codec]
pub struct SeedsV0(pub ZSet<SeedV0>);

impl SeedsV0 {
    pub fn sig_hash(&self) -> Digest {
        ZSet::from_iter(self.0.iter().map(SigHashSeedV0)).hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hashable, NounDecode, NounEncode)]
#[iris_ztd::wasm_noun_codec(no_hash, no_noun)]
pub struct PageV0 {
    digest: Digest,
    pow: Option<Noun>,
    parent: Digest,
    tx_ids: ZSet<Digest>,
    coinbase: CoinbaseSplitV0,
    timestamp: u64,
    epoch_counter: u32,
    target: Bignum,
    accumulated_work: Bignum,
    height: BlockHeight,
    msg: PageMsg,
}

impl PageV0 {
    pub fn coinbase(&self, consts: BlockchainConstants) -> Vec<Note> {
        let mut notes = vec![];

        let timelock = if self.height < consts.first_month_coinbase_min {
            Timelock {
                rel: TimelockRange {
                    // Hoon hardcodes 4383 even if the first month period can be changed.
                    min: Some(4383),
                    max: None,
                },
                abs: TimelockRange::none(),
            }
        } else {
            Timelock {
                rel: TimelockRange {
                    min: Some(consts.coinbase_timelock_min),
                    max: None,
                },
                abs: TimelockRange::none(),
            }
        };

        let timelock = TimelockIntent {
            tim: Some(timelock),
        };

        for (sig, assets) in self.coinbase.0.clone() {
            let inner = NoteInner {
                version: Version::V0,
                origin_page: self.height,
                timelock,
            };
            let source = Source {
                hash: self.parent,
                is_coinbase: true,
            };
            let name = Name::new_v0(sig.clone(), source, timelock);
            notes.push(Note::V0(NoteV0 {
                inner,
                name,
                sig,
                source,
                assets,
            }))
        }

        notes
    }

    pub fn block_commitment(&self) -> Digest {
        let Self {
            parent,
            tx_ids,
            coinbase,
            timestamp,
            epoch_counter,
            target,
            accumulated_work,
            height,
            msg,
            ..
        } = self;

        (
            parent,
            tx_ids,
            coinbase,
            timestamp,
            epoch_counter,
            target,
            accumulated_work,
            height,
            msg,
        )
            .hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hashable, NounDecode, NounEncode)]
#[iris_ztd::wasm_noun_codec]
pub struct CoinbaseSplitV0(ZMap<Sig, Nicks>);

#[derive(Debug, Clone, Hashable, NounDecode, NounEncode, PartialEq, Eq)]
#[iris_ztd::wasm_noun_codec]
#[cfg_attr(
    feature = "wasm",
    tsify(type = "string | number[] | { __tag_page_msg: undefined }")
)]
pub struct PageMsg(pub Vec<Belt>);

impl<'a> From<&'a [u8]> for PageMsg {
    fn from(other: &'a [u8]) -> Self {
        let mut belts = vec![];

        for c in other.chunks(8) {
            let mut b = [0u8; 8];
            b[..c.len()].copy_from_slice(c);
            belts.push(Belt(u64::from_le_bytes(b)));
        }

        PageMsg(belts)
    }
}

impl<'a> From<&'a str> for PageMsg {
    fn from(other: &'a str) -> Self {
        let mut belts = vec![];

        for c in other.as_bytes().chunks(4) {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            belts.push(Belt(u32::from_le_bytes(b) as u64));
        }

        PageMsg(belts)
    }
}

impl core::fmt::Display for PageMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if b.0 >= (1 << 32) {
                return Err(fmt::Error);
            }
            let b = (b.0 as u32).to_le_bytes();
            let mut len = 4;
            while i == self.0.len() - 1 && len > 0 && b[len - 1] == 0 {
                len -= 1;
            }
            let Ok(s) = core::str::from_utf8(&b[..len]) else {
                return Err(fmt::Error);
            };
            f.write_str(s)?;
        }
        Ok(())
    }
}

impl Serialize for PageMsg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        let mut no_string = false;

        for (i, b) in self.0.iter().enumerate() {
            if b.0 >= (1 << 32) {
                no_string = true;
                break;
            }
            let b = (b.0 as u32).to_le_bytes();
            let mut len = 4;
            while i == self.0.len() - 1 && len > 0 && b[len - 1] == 0 {
                len -= 1;
            }
            bytes.extend(b[..len].iter().copied());
        }

        if let (Ok(s), false) = (core::str::from_utf8(&bytes), no_string) {
            serializer.serialize_str(s)
        } else {
            let mut bytes = vec![];

            for b in self.0.iter() {
                let b = b.0.to_le_bytes();
                bytes.extend(b);
            }

            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for PageMsg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PageMsgVisitor;

        impl<'de> serde::de::Visitor<'de> for PageMsgVisitor {
            type Value = PageMsg;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or sequence of belt bytes (64-bit little endian)")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.into())
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.into())
            }
        }

        deserializer.deserialize_str(PageMsgVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    use iris_ztd::Hashable;

    fn check_hash(name: &str, h: &impl Hashable, exp: &str) {
        assert_eq!(h.hash().to_string(), exp, "hash mismatch for {}", name);
    }

    // Computed with, from .tx file:
    // /. tx |=  [a=@tas b=inputs:v0:transact]  (new:raw-tx:v0:transact b)
    const TX1: &[u8] = include_bytes!(
        "../../test_vectors/BAXmnxFoApbXBwzBPEPoNwcbtGa8UHS4gxBWDsATP1mrRq8PoKbLQJU.txr"
    );
    // Computed with (txr being the raw-tx from TX1):
    // /| txo txr |=  [a=raw-tx:v0:transact]  =/  outs  (new:outputs:v0:transact inputs.a 0)  =/  g  |=  [s=sig:v0:transact [n=nnote:v0:transact b=seeds:v0:transact]]  n  =/  ol  ~(tap z-by outs)  (turn ol g)
    const TX1_OUTPUTS: &[u8] = include_bytes!(
        "../../test_vectors/BAXmnxFoApbXBwzBPEPoNwcbtGa8UHS4gxBWDsATP1mrRq8PoKbLQJU.txo"
    );
    // /( b block/7pR2bvzoMvfFcxXaHv4ERm8AgEnExcZLuEsjNgLkJziBkqBLidLg39Y
    // /j b crates/iris-nockchain-types/test_vectors/0.block
    const BLOCK_0: &[u8] = include_bytes!("../../test_vectors/0.block");
    // /( b block/A7YEzGRmb2mpyhv3eaxMaCjL5LiYmHx2HUfnZ36wvALVgY43pf7Sad3
    // /j b crates/iris-nockchain-types/test_vectors/1123.block
    const BLOCK_1123: &[u8] = include_bytes!("../../test_vectors/1123.block");

    #[test]
    fn check_tx_id() {
        let noun = iris_ztd::cue(TX1).unwrap();

        let (_a, _b, _c, _d): (Noun, Noun, Noun, Noun) = NounDecode::from_noun(&noun).unwrap();

        let tx = RawTxV0::from_noun(&noun).unwrap();
        check_hash(
            "tx_id",
            &tx.id,
            "BAXmnxFoApbXBwzBPEPoNwcbtGa8UHS4gxBWDsATP1mrRq8PoKbLQJU",
        );
        check_hash(
            "tx_id",
            &tx.calc_id(),
            "BAXmnxFoApbXBwzBPEPoNwcbtGa8UHS4gxBWDsATP1mrRq8PoKbLQJU",
        );
    }

    #[test]
    fn check_tx_outputs() {
        let noun = iris_ztd::cue(TX1).unwrap();

        let tx = RawTxV0::from_noun(&noun).unwrap();

        let out_noun = iris_ztd::cue(TX1_OUTPUTS).unwrap();
        let mut outs: Vec<NoteV0> = NounDecode::from_noun(&out_noun).unwrap();
        outs.sort_by_key(|note| note.name);

        let mut tx_outs = tx.outputs();
        tx_outs.sort_by_key(|note| note.name);

        assert_eq!(outs, tx_outs);
    }

    #[test]
    fn parse_page_msg() {
        let str_msg = "QUIDQUID CORRUMPI POTEST, CORRUMPETUR";
        let page_msg = PageMsg::from(str_msg);
        let s = serde_json::to_string(&page_msg).unwrap();
        assert_eq!(format!("\"{str_msg}\""), s);
    }

    #[test]
    fn parse_block_0() {
        let noun = iris_ztd::cue(BLOCK_0).unwrap();
        let Some(Some(block)): Option<Option<PageV0>> = NounDecode::from_noun(&noun).unwrap()
        else {
            panic!("Invalid page decoding");
        };

        let str_msg = "QUIDQUID CORRUMPI POTEST, CORRUMPETUR";
        let page_msg = PageMsg::from(str_msg);

        assert_eq!(page_msg, block.msg);
        assert_eq!(block.coinbase(Default::default()), &[]);
    }

    #[test]
    fn parse_block_1123() {
        let noun = iris_ztd::cue(BLOCK_1123).unwrap();
        let Some(Some(block)): Option<Option<PageV0>> = NounDecode::from_noun(&noun).unwrap()
        else {
            panic!("Invalid page decoding");
        };

        let str_msg = "took zero knowledge";
        let page_msg = PageMsg::from(str_msg);

        assert_eq!(page_msg, block.msg);
        let coinbase = block.coinbase(Default::default());
        assert_eq!(
            coinbase.iter().map(|v| v.name()).collect::<Vec<_>>(),
            &[Name::new(
                "5xfojQpojJ979vtvd8fdh2j57mgay42GLzj1njzSknSi2j9jtj3JMPR"
                    .try_into()
                    .unwrap(),
                "2tik85koe7esbRTygnCRdBA8ykGthwdSqgLCn1mutjgi9Wj1wqVYMzq"
                    .try_into()
                    .unwrap()
            )],
            "{coinbase:?}",
        );
    }
}
