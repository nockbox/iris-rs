use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use iris_crypto::{PublicKey, Signature};
use iris_ztd::{Digest, Hashable as HashableTrait, Noun, NounDecode, NounEncode, ZMap, ZSet};
use iris_ztd_derive::{Hashable, NounDecode, NounEncode};
use serde::{Deserialize, Serialize};

use super::note::{BlockHeight, Name, Source, TimelockRange, Version};
use super::TxId;
use crate::Nicks;

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoteInner {
    pub version: Version,
    pub origin_page: BlockHeight,
    // NOTE: not really intent, but timelock is just intent without double null case, which we can accept.
    pub timelock: TimelockIntent,
}

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq)]
pub struct Note {
    pub inner: NoteInner,
    pub name: Name,
    pub sig: Sig,
    pub source: Source,
    pub assets: Nicks,
}

impl Note {
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LegacySignature(pub Vec<(PublicKey, Signature)>);

impl HashableTrait for LegacySignature {
    fn hash(&self) -> Digest {
        ZMap::from_iter(self.0.iter().cloned()).hash()
    }
}

impl NounEncode for LegacySignature {
    fn to_noun(&self) -> Noun {
        ZMap::from_iter(self.0.iter().cloned()).to_noun()
    }
}

impl NounDecode for LegacySignature {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let m: ZMap<PublicKey, Signature> = NounDecode::from_noun(noun)?;
        Some(Self(m.into_iter().collect::<Vec<_>>()))
    }
}

impl LegacySignature {
    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn add_entry(&mut self, pubkey: PublicKey, signature: Signature) {
        self.0.push((pubkey, signature));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
pub struct Sig {
    pub m: u64,
    pub pubkeys: Vec<PublicKey>,
}

impl Sig {
    pub fn new_single_pk(pk: PublicKey) -> Self {
        Self {
            m: 1,
            pubkeys: vec![pk],
        }
    }
}

impl NounEncode for Sig {
    fn to_noun(&self) -> Noun {
        (self.m, self.pubkeys.iter().collect::<ZSet<_>>()).to_noun()
    }
}

impl NounDecode for Sig {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (m, pubkeys): (u64, ZSet<PublicKey>) = NounDecode::from_noun(noun)?;
        Some(Self {
            m,
            pubkeys: pubkeys.into_iter().collect(),
        })
    }
}

impl HashableTrait for Sig {
    fn hash(&self) -> Digest {
        (self.m, self.pubkeys.iter().collect::<ZSet<_>>()).hash()
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
pub struct Input {
    pub note: Note,
    pub spend: Spend,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
pub struct Spend {
    pub signature: Option<LegacySignature>,
    pub seeds: Seeds,
    pub fee: Nicks,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize)]
pub struct RawTx {
    pub id: TxId,
    pub inputs: Inputs,
    pub timelock_range: TimelockRange,
    pub total_fees: Nicks,
}

impl RawTx {
    pub fn version(&self) -> Version {
        Version::V0
    }

    /// Calculate output notes from the transaction inputs.
    ///
    /// This function combines seeds across multiple inputs into one output note per-recipient-sig.
    pub fn outputs(&self) -> Vec<Note> {
        let inps = self.inputs.0.iter().cloned().collect::<ZMap<_, _>>();

        let mut output_base: BTreeMap<Sig, (TimelockIntent, Nicks, ZSet<Seed>)> = BTreeMap::new();

        for (_, input) in inps {
            for seed in input.spend.seeds.0 {
                // NOTE: we are not checking if we're adding duplicate seed or not. Not necessary when processing valid txs.
                let sig = seed.recipient.clone();
                let child = output_base
                    .entry(sig)
                    .or_insert_with(|| (TimelockIntent::default(), 0, ZSet::new()));
                // NOTE: in hoon, we see:
                //
                // =?  timelock.note.chi  !=(~ timelock-intent.seed)
                //  (reconcile timelock.note.child timelock-intent.seed)
                //
                // Note that it's reconciling timelock.note.child, not timelock.note.chi.
                // This effectively means, that the reconcile code is useless - it will just
                // keep timelock intent of the last seed.
                if let Some(tl) = seed
                    .timelock_intent
                    .tim
                    .clone()
                    .filter(|v| *v != Timelock::none())
                {
                    child.0.tim = Some(tl);
                }
                child.1 += seed.gift;
                child.2.insert(seed);
            }
        }

        let mut outputs = vec![];

        for (sig, (timelock, assets, seeds)) in output_base {
            let source = Source {
                hash: seeds.hash(),
                is_coinbase: false,
            };
            outputs.push(Note {
                name: Name::new_v0(sig.clone(), source.clone(), timelock.clone()),
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inputs(pub Vec<(Name, Input)>);

impl NounEncode for Inputs {
    fn to_noun(&self) -> Noun {
        self.0.iter().cloned().collect::<ZMap<_, _>>().to_noun()
    }
}

impl NounDecode for Inputs {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let inputs: ZMap<Name, Input> = NounDecode::from_noun(noun)?;
        Some(Self(inputs.into_iter().collect()))
    }
}

impl HashableTrait for Inputs {
    fn hash(&self) -> Digest {
        self.0.iter().cloned().collect::<ZMap<_, _>>().hash()
    }
}

#[derive(Debug, Clone, NounEncode, Hashable, NounDecode, Serialize, Deserialize, PartialEq, Eq)]
pub struct Timelock {
    pub rel: TimelockRange,
    pub abs: TimelockRange,
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
    Debug, Default, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize, PartialEq, Eq,
)]
pub struct TimelockIntent {
    pub tim: Option<Timelock>,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seed {
    pub output_source: Option<Source>,
    pub recipient: Sig,
    pub timelock_intent: TimelockIntent,
    pub gift: Nicks,
    pub parent_hash: Digest,
}

impl Seed {
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

impl HashableTrait for Seed {
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
}

#[derive(Debug, Clone)]
pub struct SigHashSeed<'a>(&'a Seed);

impl<'a> HashableTrait for SigHashSeed<'a> {
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
}

impl<'a> NounEncode for SigHashSeed<'a> {
    fn to_noun(&self) -> Noun {
        self.0.to_noun()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seeds(pub Vec<Seed>);

impl Seeds {
    pub fn sig_hash(&self) -> Digest {
        ZSet::from_iter(self.0.iter().map(SigHashSeed)).hash()
    }
}

impl HashableTrait for Seeds {
    fn hash(&self) -> Digest {
        ZSet::from_iter(&self.0).hash()
    }
}

impl NounEncode for Seeds {
    fn to_noun(&self) -> Noun {
        ZSet::from_iter(&self.0).to_noun()
    }
}

impl NounDecode for Seeds {
    fn from_noun(noun: &Noun) -> Option<Self> {
        Some(Seeds(
            ZSet::from_noun(noun)?.into_iter().collect::<Vec<_>>(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use bip39::Mnemonic;
    use iris_crypto::derive_master_key;
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

    #[test]
    fn check_tx_id() {
        let noun = iris_ztd::cue(TX1).unwrap();

        let (a, b, c, d): (Noun, Noun, Noun, Noun) = NounDecode::from_noun(&noun).unwrap();

        let tx = RawTx::from_noun(&noun).unwrap();
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

        let tx = RawTx::from_noun(&noun).unwrap();

        let out_noun = iris_ztd::cue(TX1_OUTPUTS).unwrap();
        let mut outs: Vec<Note> = NounDecode::from_noun(&out_noun).unwrap();
        outs.sort_by_key(|note| note.name);

        let mut tx_outs = tx.outputs();
        tx_outs.sort_by_key(|note| note.name);

        assert_eq!(outs, tx_outs);
    }
}
