use super::note::{BlockHeight, Name, Note, NoteData, Source, TimelockRange, Version};
use crate::{Nicks, Pkh};
use alloc::vec::Vec;
use iris_ztd::{Bignum, Digest, Noun, ZSet};

fn noun_words(n: &Noun) -> u64 {
    match n {
        Noun::Atom(_) => 1,
        Noun::Cell(l, r) => noun_words(l) + noun_words(r),
    }
}

#[derive(Debug, Clone)]
pub enum LockRoot {
    Hash(Digest),
    Lock(SpendCondition),
}

impl NounEncode for LockRoot {
    fn to_noun(&self) -> Noun {
        match self {
            LockRoot::Hash(d) => d.to_noun(),
            LockRoot::Lock(l) => l.hash().to_noun(),
        }
    }
}

impl NounDecode for LockRoot {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let d = Digest::from_noun(noun)?;
        Some(Self::Hash(d))
    }
}

impl From<Digest> for LockRoot {
    fn from(value: Digest) -> Self {
        Self::Hash(value)
    }
}

impl From<LockRoot> for Digest {
    fn from(value: LockRoot) -> Self {
        match value {
            LockRoot::Hash(d) => d,
            LockRoot::Lock(l) => l.hash(),
        }
    }
}

impl HashableTrait for LockRoot {
    fn hash(&self) -> Digest {
        match self {
            LockRoot::Hash(d) => *d,
            LockRoot::Lock(l) => l.hash(),
        }
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct Seed {
    pub output_source: Option<Source>,
    pub lock_root: LockRoot,
    pub note_data: NoteData,
    pub gift: Nicks,
    pub parent_hash: Digest,
}

impl Seed {
    pub fn new_single_pkh(
        pkh: Digest,
        gift: Nicks,
        parent_hash: Digest,
        include_lock_data: bool,
        memo: Option<Noun>,
    ) -> Self {
        let lock_root = LockRoot::Lock(SpendCondition::new_pkh(Pkh::single(pkh)));
        let mut note_data = NoteData::empty();
        if include_lock_data {
            note_data.push_pkh(Pkh::single(pkh));
        }
        if let Some(memo) = memo {
            note_data.push_memo(memo);
        }
        Self {
            output_source: None,
            lock_root,
            note_data,
            gift,
            parent_hash,
        }
    }

    pub fn note_data_words(&self) -> u64 {
        noun_words(&self.note_data.to_noun())
    }
}

impl HashableTrait for Seed {
    fn hash(&self) -> Digest {
        // output source is omitted
        (
            &self.lock_root,
            &self.note_data,
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
            &self.0.lock_root,
            &self.0.note_data,
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Spend {
    pub witness: Witness,
    pub seeds: Seeds,
    pub fee: Nicks,
}

impl NounEncode for Spend {
    fn to_noun(&self) -> Noun {
        (Version::V1, &self.witness, &self.seeds, &self.fee).to_noun()
    }
}

impl NounDecode for Spend {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (v, witness, seeds, fee): (Version, _, _, _) = NounDecode::from_noun(noun)?;

        if v != Version::V1 {
            return None;
        }

        Some(Self {
            witness,
            seeds,
            fee,
        })
    }
}

impl AsRef<Spend> for Spend {
    fn as_ref(&self) -> &Spend {
        self
    }
}

impl Spend {
    pub const MIN_FEE: u64 = 256;

    pub fn fee_for_many<T: AsRef<Spend>>(
        spends: impl Iterator<Item = T>,
        per_word: Nicks,
    ) -> Nicks {
        let fee = spends
            .map(|v| v.as_ref().unclamped_fee(per_word))
            .sum::<u64>();
        fee.max(Self::MIN_FEE)
    }

    pub fn unclamped_fee(&self, per_word: Nicks) -> Nicks {
        let (a, b) = self.calc_words();
        (a + b) * per_word
    }

    pub fn calc_words(&self) -> (u64, u64) {
        let seed_words: u64 = self.seeds.0.iter().map(|seed| seed.note_data_words()).sum();
        let witness_words = noun_words(&self.witness.to_noun());

        (seed_words, witness_words)
    }

    pub fn new(witness: Witness, seeds: Seeds, fee: Nicks) -> Self {
        Self {
            witness,
            seeds,
            fee,
        }
    }

    pub fn sig_hash(&self) -> Digest {
        (&self.seeds.sig_hash(), self.fee).hash()
    }

    pub fn add_signature(&mut self, key: PublicKey, signature: Signature) {
        self.witness
            .pkh_signature
            .0
            .push((key.hash(), key, signature));
    }

    pub fn add_preimage(&mut self, preimage: Noun) -> Digest {
        let digest = preimage.hash();
        self.witness.hax_map.insert(digest, preimage);
        digest
    }
}

impl HashableTrait for Spend {
    fn hash(&self) -> Digest {
        (Version::V1, &self.witness, &self.seeds, &self.fee).hash()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PkhSignature(pub Vec<(Digest, PublicKey, Signature)>);

impl HashableTrait for PkhSignature {
    fn hash(&self) -> Digest {
        ZMap::from_iter(
            self.0
                .iter()
                .cloned()
                .map(|(digest, pk, sig)| (digest, (pk, sig)))
                .collect::<Vec<_>>(),
        )
        .hash()
    }
}

impl NounEncode for PkhSignature {
    fn to_noun(&self) -> Noun {
        ZMap::from_iter(
            self.0
                .iter()
                .cloned()
                .map(|(digest, pk, sig)| (digest, (pk, sig)))
                .collect::<Vec<_>>(),
        )
        .to_noun()
    }
}

impl NounDecode for PkhSignature {
    fn from_noun(noun: &Noun) -> Option<Self> {
        Some(Self(
            ZMap::from_noun(noun)?
                .into_iter()
                .map(|(digest, (pk, sig))| (digest, pk, sig))
                .collect::<Vec<_>>(),
        ))
    }
}

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode)]
pub struct Witness {
    pub lock_merkle_proof: LockMerkleProof,
    pub pkh_signature: PkhSignature,
    pub hax_map: ZMap<Digest, Noun>,
    pub tim: (),
}

impl Witness {
    pub fn new(spend_condition: SpendCondition) -> Self {
        let root = spend_condition.hash();
        Self {
            lock_merkle_proof: LockMerkleProof {
                spend_condition,
                axis: 1,
                proof: MerkleProof { root, path: vec![] },
            },
            pkh_signature: PkhSignature(vec![]),
            hax_map: ZMap::new(),
            tim: (),
        }
    }

    pub fn take_data(&mut self) -> Self {
        let pkh_signature = core::mem::take(&mut self.pkh_signature);
        let hax_map = core::mem::take(&mut self.hax_map);
        Self {
            lock_merkle_proof: self.lock_merkle_proof.clone(),
            pkh_signature,
            hax_map,
            tim: (),
        }
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct LockMerkleProof {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub proof: MerkleProof,
}

impl HashableTrait for LockMerkleProof {
    fn hash(&self) -> Digest {
        // NOTE: lmao
        let axis_mold_hash: Digest = "6mhCSwJQDvbkbiPAUNjetJtVoo1VLtEhmEYoU4hmdGd6ep1F6ayaV4A"
            .try_into()
            .unwrap();
        (&self.spend_condition.hash(), axis_mold_hash, &self.proof).hash()
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable)]
pub struct MerkleProof {
    pub root: Digest,
    pub path: Vec<Digest>,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable)]
pub struct SpendCondition(pub Vec<LockPrimitive>);

impl SpendCondition {
    pub fn new_pkh(pkh: Pkh) -> Self {
        SpendCondition(vec![LockPrimitive::Pkh(pkh)])
    }

    pub fn first_name(&self) -> Digest {
        (true, self.hash()).hash()
    }

    pub fn pkh(&self) -> impl Iterator<Item = &Pkh> + '_ {
        self.0.iter().filter_map(|v| {
            if let LockPrimitive::Pkh(p) = v {
                Some(p)
            } else {
                None
            }
        })
    }

    pub fn tim(&self) -> impl Iterator<Item = &LockTim> + '_ {
        self.0.iter().filter_map(|v| {
            if let LockPrimitive::Tim(t) = v {
                Some(t)
            } else {
                None
            }
        })
    }

    pub fn hax(&self) -> impl Iterator<Item = &Hax> + '_ {
        self.0.iter().filter_map(|v| {
            if let LockPrimitive::Hax(h) = v {
                Some(h)
            } else {
                None
            }
        })
    }

    pub fn brn(&self) -> bool {
        self.0.iter().any(|v| matches!(v, LockPrimitive::Brn))
    }
}

#[derive(Debug, Clone)]
pub enum LockPrimitive {
    Pkh(Pkh),
    Tim(LockTim),
    Hax(Hax),
    Brn,
}

impl NounEncode for LockPrimitive {
    fn to_noun(&self) -> iris_ztd::Noun {
        match self {
            LockPrimitive::Pkh(pkh) => ("pkh", pkh).to_noun(),
            LockPrimitive::Tim(tim) => ("tim", tim).to_noun(),
            LockPrimitive::Hax(hax) => ("hax", hax).to_noun(),
            LockPrimitive::Brn => ("brn", 0).to_noun(),
        }
    }
}

impl NounDecode for LockPrimitive {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (p, n): (String, Noun) = NounDecode::from_noun(noun)?;
        Some(match &*p {
            "pkh" => LockPrimitive::Pkh(NounDecode::from_noun(&n)?),
            "tim" => LockPrimitive::Tim(NounDecode::from_noun(&n)?),
            "hax" => LockPrimitive::Hax(NounDecode::from_noun(&n)?),
            "brn" => LockPrimitive::Brn,
            _ => return None,
        })
    }
}

impl HashableTrait for LockPrimitive {
    fn hash(&self) -> Digest {
        match self {
            LockPrimitive::Pkh(pkh) => ("pkh", pkh).hash(),
            LockPrimitive::Tim(tim) => ("tim", tim).hash(),
            LockPrimitive::Hax(hax) => ("hax", hax).hash(),
            LockPrimitive::Brn => ("brn", 0).hash(),
        }
    }
}

#[derive(Debug, Clone, NounEncode, Hashable, NounDecode)]
pub struct LockTim {
    pub rel: TimelockRange,
    pub abs: TimelockRange,
}

impl LockTim {
    pub fn coinbase() -> Self {
        Self {
            rel: TimelockRange {
                min: Some(100),
                max: None,
            },
            abs: TimelockRange::none(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Hax(pub Vec<Digest>);

impl NounEncode for Hax {
    fn to_noun(&self) -> Noun {
        ZSet::from_iter(&self.0).to_noun()
    }
}

impl HashableTrait for Hax {
    fn hash(&self) -> Digest {
        ZSet::from_iter(&self.0).hash()
    }
}

impl NounDecode for Hax {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let v: ZSet<Digest> = NounDecode::from_noun(noun)?;
        Some(Self(v.into_iter().collect::<Vec<_>>()))
    }
}

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
    pub fn id(&self) -> TxId {
        match self {
            Tx::V0(tx) => tx.raw.id,
            Tx::V1(tx) => tx.raw.id,
        }
    }

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

    pub fn input_names(&self) -> Vec<Name> {
        match self {
            Tx::V0(tx) => tx.raw.input_names(),
            Tx::V1(tx) => tx.raw.input_names(),
        }
    }

    pub fn total_fees(&self) -> Nicks {
        match self {
            Tx::V0(tx) => tx.raw.total_fees,
            Tx::V1(tx) => tx.raw.spends.total_fees(),
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

    /// Returns the spend conditions for each input.
    /// For V0 transactions, this is always None.
    #[deprecated(
        note = "This returns empty vec for V0 transactions, and will be removed in future release. Only kept for Iris wallet V0 support."
    )]
    pub fn input_spend_conditions(&self) -> Vec<crate::v1::SpendCondition> {
        match self {
            RawTx::V0(_) => Default::default(),
            RawTx::V1(tx) => tx.input_spend_conditions(),
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

<<<<<<< HEAD
    #[test]
    fn check_tx_id() {
        let tx_bytes = hex::decode("7101047c379f8ffbd300a503081807fe895b2c89ca071070f500fb178f756a0f2020d6f8dc7daec0a90810b0c9e9665210f92bac0208cc4ede056771030906f8b1287cb3c0c9c3bb0104e24490e2e1c0b5880308a0748189a8b6669c037e93e53b87dd89cb6601f6d296b46758cb841f200ff63aba955efdeb0002d2eb569bde85c692017ec49e7977f2e1563e4080f1d0ecca4acbdcdbb82ae0c1ada1e30208302f6b7482f1300f061050861696e5aa69a20f20c01f65b4e7a52bac1b40802654a715537af51220f0cd44601ca826519b1a1760f7f0feb4a08cd6e701fe83df4a788b5dfe6280fe1575b988d421e10c20b0812cad8144baf40ff8932478f409ad48cd56c3c5b302082c143e2881c4867b06e89d0ff9cf9bb7f0f00002e3db85de4bcc71c3017ac4694ccfe96c253b800086a0bb8b404bed28e0671d5b29445746b317a0a7bd518a3ba839b603e4b38b0120593fd11ce0574d6a59738959d50610704c8929038c39540fb0374561f9170c5968800046a2cc5ca7cd4a3717205864ed680fe831abb77280409696393d40e02c6fcb18f05706c6b001821e18a6d400014cc33d35d03ff3c6d800818e30096a8040dd3f4e3d40e0d869de1ef0bd12d7a80191325833e0f23e8f316017380d75e0b3cd96ea8723f47084ae2c8080c28edfa6cd00287700012b7115916b50e7ce00b92117c2d849713e0610c06ff5f8b0b6c5b807fcf4e104e7329368c40c6800007380bf5feb45a2a01ab619a0675ed1c4b170e64403fce481d6412190c5c700bff236677af1d8771220c044d5424598bea49a65c3513a03a6f317c2612de17084061e002030ab0002e578b5eaa5f12db901febec80c05397433700081bec1757695bd8de000ff20075a70c1e87d13205040bf385d63fb1c5f008137df35146a01dded00bb003544c8641f3b0d20101aa5d5010051951e40a0cbb7e981d738b91bf0bbc7f2086a67adfc8dab862b66010f2d0c5f80bd9061b4d8dc9d0007e837a5793fb26948ca003feca5910f43d3e53c8000554e10b75366223aa057365e63c375d8898723b4714396bbd570f16cc81b2c40005bf9e71dd0e13e7bc4808ed12155060876b3f5f303047a46fda7013dcc9a590c1010a0caeb027fdf905e182048d7f3390f10f8d0dbaa07f4dd35de334040cd14e718d02bd0f1f4008114433a6e405f2574e181bfa30a0e1c8ed0c311bab221cb3d031a00801c4040010fb51fb88b0e3f8080bff571977ed87e6080ff362236762e30511b40c068f3d707b6c4751ef073cd9cdbe81d7090b36c384a0fdbb28723b4c3111a").unwrap();
        let noun = iris_ztd::cue(&tx_bytes).unwrap();

        let mut zm = ZMap::<String, Noun>::new();
        zm.insert("ver".to_string(), Version::V1.to_noun());
        zm.insert("ve2".to_string(), Version::V1.to_noun());
        let zm_noun = zm.to_noun();
        let _zm_decode = ZSet::<Noun>::from_noun(&zm_noun).unwrap();

        let _: (Version, TxId, ZMap<Name, Noun>) = NounDecode::from_noun(&noun).unwrap();
        let tx = RawTx::from_noun(&noun).unwrap();
        check_hash(
            "tx_id",
            &tx.id,
            "7dinV9KdtAUZgKhCZN1P8SZH9ux2RTe9kYUdh4fRvYWjX5wMopDQ6py",
        );
        check_hash(
            "tx_id",
            &tx.calc_id(),
            "ChtgwirfCoC1T8fg5EvkA6aGp9YPQh4mVxCDYrmhaBvq2oSCmpzrK6f",
        );
    }

    #[test]
    fn test_hash_vectors() {
        let pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX"
            .try_into()
            .unwrap();
        let seed1 = Seed::new_single_pkh(
            pkh,
            4290881913,
            "6qF9RtWRUWfCX8NS8QU2u7A3BufVrsMwwWWZ8KSzZ5gVn4syqmeVa4"
                .try_into()
                .unwrap(),
            true,
            None,
        );

        check_hash(
            "lock_root",
            &seed1.lock_root,
            "5bSsB8Hij6E3xefbs8WFdAw5CYSurBbJ4kL5kjoiuYFLak1eizq3v6b",
        );
        check_hash(
            "note-data",
            &seed1.note_data,
            "7hLhhBXik77vGuhxz9V9EKB5WcXhr692PsmV6AffGrQaxuF1df3kYUT",
        );

        let mut seed2 = seed1.clone();
        seed2.gift = 1234567;

        let mut spend = Spend {
            witness: Witness::new(SpendCondition(vec![
                LockPrimitive::Pkh(Pkh::single(pkh)),
                LockPrimitive::Tim(LockTim::coinbase()),
            ])),
            seeds: Seeds(vec![seed1.clone(), seed2.clone()]),
            fee: 2850816,
        };

        check_hash(
            "sig-hash",
            &spend.sig_hash(),
            "B17CfQv9SuHTxn1k576S6EcKrxmb7WRcUFFx9eTXTzVyhtVVGwCKXSn",
        );

        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let private_key = derive_master_key(&mnemonic.to_seed(""))
            .private_key
            .unwrap();

        let signature = private_key.sign(&spend.sig_hash());
        check_hash(
            "(hash of) signature",
            &signature.to_noun(),
            "DKGrE8s8hhacsnGMzLWqRKfTtXx4QG6tDvC3k1Xu6FA7xAaetGPK6Aj",
        );
        spend.add_signature(private_key.public_key(), signature);

        check_hash(
            "spend",
            &spend,
            "CTYHRFefGkubLBG8WszvXq1v5XevLkbP3aBezMza9zen6Fbvyu8dD17",
        );

        let name = Name::new(
            "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                .try_into()
                .unwrap(),
            "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                .try_into()
                .unwrap(),
        );
        check_hash(
            "name",
            &name,
            "AvHDRESkhM9F2FMPiYFPeQ9GrL2kX8QkmHP8dGpVT8Pr2f8xM1SLGJW",
        );

        check_hash(
            "spend condition tim",
            &spend.witness.lock_merkle_proof.spend_condition.0[1],
            "B5RtZnbphbf1D5vQwsZjHycLN2Ldp7RD2pK6V3qAMFCrxnUXAhgmKgg",
        );

        check_hash(
            "spend condition pkh",
            &spend.witness.lock_merkle_proof.spend_condition.0[0],
            "65RqCgowDZJziLZzpQkPULVy2tb1dMGMUrgsxxfC1mPPK6hSNKAP6DP",
        );

        check_hash(
            "spend condition",
            &spend.witness.lock_merkle_proof.spend_condition,
            "5k2qTDtcxyQWBmsVTi1fEmbSeoAnq5B83SGoJwDU8NJkRfXWevwQDWn",
        );

        check_hash(
            "pkh",
            &spend.witness.pkh_signature,
            "4oMCHwUMend6ds2Gt3bUyz4cNrZto4PepFgbQQWYDRKMB3v9qaccMT",
        );

        check_hash(
            "merkle proof",
            &spend.witness.lock_merkle_proof.proof,
            "MefKNQSmk8wzDzCPpY93GMdM53Pv1TGbUZe2Kn427FiuvbgjSZe5eJ",
        );

        check_hash(
            "lock merkle proof",
            &spend.witness.lock_merkle_proof,
            "6MNHCVrns4DjMxAV4CJQWKsPcpXPDSqizJsChgMYozsHsLBev52RRW1",
        );

        check_hash(
            "witness",
            &spend.witness,
            "4fnjd1sxmaxupG3EYqBkvaQs6aiKHi9bZKciYipBA9an4DXuRH938L8",
        );

        check_hash(
            "seeds",
            &spend.seeds,
            "7Zuskz3WibckR2anDXDuPcMUk45A2iJnrdPsFALj4Rc5NTufyca39gY",
        );

        let spends = Spends(vec![(name, spend)]);
        check_hash(
            "spends",
            &spends,
            "7WHUF24eUFiKm4gZ7Rw9EyB9FygRth9o7KVa7G3wKizb8xXR3hm4vjW",
        );

        let tx = RawTx::new(spends);
        check_hash(
            "transaction id",
            &tx.id,
            "3j4vkn72mcpVtQrTgNnYyoF3rDuYax3aebT5axu3Qe16jm9x2wLtepW",
        );
=======
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
