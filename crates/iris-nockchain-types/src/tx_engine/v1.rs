use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloc::{boxed::Box, format};
use iris_crypto::{PublicKey, Signature};
use iris_ztd::{Digest, Hashable, Noun, NounDecode, NounEncode, ZMap, ZSet};
use serde::{Deserialize, Serialize};

use super::note::{BlockHeight, ExpectedVersion, Name, Source, Version};
use super::v0::LegacySignature;
use super::TxId;
use crate::Nicks;

fn noun_words(n: &Noun) -> u64 {
    match n {
        Noun::Atom(_) => 1,
        Noun::Cell(l, r) => noun_words(l) + noun_words(r),
    }
}

#[derive(Debug, Clone, Hashable, NounDecode, NounEncode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct Pkh {
    pub m: u64,
    pub hashes: ZSet<Digest>,
}

impl Pkh {
    pub fn new(m: u64, hashes: Vec<Digest>) -> Self {
        Self {
            m,
            hashes: hashes.into(),
        }
    }

    pub fn single(hash: Digest) -> Self {
        Self {
            m: 1,
            hashes: [hash].into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, NounDecode, NounEncode)]
#[iris_ztd::wasm_noun_codec]
pub struct NoteData(pub ZMap<String, Noun>);

impl Hashable for NoteData {
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
        self.0
            .iter()
            .map(|(k, v)| (k, hash_noun(v)))
            .collect::<ZMap<_, _>>()
            .hash()
    }
}

impl NoteData {
    pub fn empty() -> Self {
        Self(ZMap::new())
    }

    pub fn push_pkh(&mut self, pkh: Pkh) {
        self.0
            .insert("lock".to_string(), (0, ("pkh", &pkh), 0).to_noun());
    }

    // TODO: support 2,4,8,16-way spend conditions.
    pub fn push_lock(&mut self, spend_condition: SpendCondition) {
        self.0
            .insert("lock".to_string(), (0, spend_condition).to_noun());
    }

    pub fn from_pkh(pkh: Pkh) -> Self {
        let mut ret = Self::empty();
        ret.push_pkh(pkh);
        ret
    }
}

#[derive(Debug, Clone, Hashable, Serialize, Deserialize, NounEncode, NounDecode, PartialEq, Eq)]
#[iris_ztd::wasm_noun_codec]
pub struct NoteV1 {
    pub version: Version,
    pub origin_page: BlockHeight,
    pub name: Name,
    pub note_data: NoteData,
    pub assets: Nicks,
}

impl NoteV1 {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
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

impl Hashable for LockRoot {
    fn hash(&self) -> Digest {
        match self {
            LockRoot::Hash(d) => *d,
            LockRoot::Lock(l) => l.hash(),
        }
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct SeedV1 {
    pub output_source: Option<Source>,
    pub lock_root: LockRoot,
    pub note_data: NoteData,
    pub gift: Nicks,
    pub parent_hash: Digest,
}

impl SeedV1 {
    pub fn new_single_pkh(
        pkh: Digest,
        gift: Nicks,
        parent_hash: Digest,
        include_lock_data: bool,
    ) -> Self {
        let lock_root = LockRoot::Lock(SpendCondition::new_pkh(Pkh::single(pkh)));
        let mut note_data = NoteData::empty();
        if include_lock_data {
            note_data.push_pkh(Pkh::single(pkh));
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

impl Hashable for SeedV1 {
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

#[derive(Debug, Clone, Copy)]
pub struct SigHashSeedV1<'a>(&'a SeedV1);

impl<'a> Hashable for SigHashSeedV1<'a> {
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

impl<'a> NounEncode for SigHashSeedV1<'a> {
    fn to_noun(&self) -> Noun {
        self.0.to_noun()
    }
}

#[derive(Debug, Clone, Hashable, NounDecode, NounEncode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct SeedsV1(pub ZSet<SeedV1>);

impl SeedsV1 {
    pub fn sig_hash(&self) -> Digest {
        ZSet::from_iter(self.0.iter().map(SigHashSeedV1)).hash()
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&SeedV1) -> bool,
    {
        let new_set: ZSet<SeedV1> = self.0.iter().filter(|s| f(s)).cloned().collect();
        self.0 = new_set;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Spend0V1 {
    pub signature: LegacySignature,
    pub seeds: SeedsV1,
    pub fee: Nicks,
}

impl Spend0V1 {
    pub fn sig_hash(&self) -> Digest {
        (&self.seeds.sig_hash(), self.fee).hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Spend1V1 {
    pub witness: Witness,
    pub seeds: SeedsV1,
    pub fee: Nicks,
}

impl Spend1V1 {
    pub fn sig_hash(&self) -> Digest {
        (&self.seeds.sig_hash(), self.fee).hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
#[serde(untagged)]
pub enum SpendV1 {
    S0 {
        #[cfg_attr(feature = "wasm", tsify(type = "0"))]
        version: ExpectedVersion<0>,
        spend: Spend0V1,
    },
    S1 {
        #[cfg_attr(feature = "wasm", tsify(type = "1"))]
        version: ExpectedVersion<1>,
        spend: Spend1V1,
    },
}

impl NounEncode for SpendV1 {
    fn to_noun(&self) -> Noun {
        match self {
            SpendV1::S0 { version, spend } => {
                (version, &spend.signature, &spend.seeds, &spend.fee).to_noun()
            }
            SpendV1::S1 { version, spend } => {
                (version, &spend.witness, &spend.seeds, &spend.fee).to_noun()
            }
        }
    }
}

impl NounDecode for SpendV1 {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (v, a, seeds, fee): (Version, Noun, SeedsV1, Nicks) = NounDecode::from_noun(noun)?;
        match v {
            Version::V0 => {
                let signature: LegacySignature = NounDecode::from_noun(&a)?;
                Some(SpendV1::S0 {
                    version: ExpectedVersion,
                    spend: Spend0V1 {
                        signature,
                        seeds,
                        fee,
                    },
                })
            }
            Version::V1 => {
                let witness: Witness = NounDecode::from_noun(&a)?;
                Some(SpendV1::S1 {
                    version: ExpectedVersion,
                    spend: Spend1V1 {
                        witness,
                        seeds,
                        fee,
                    },
                })
            }
            _ => None,
        }
    }
}

impl AsRef<SpendV1> for SpendV1 {
    fn as_ref(&self) -> &SpendV1 {
        self
    }
}

impl SpendV1 {
    pub const MIN_FEE: Nicks = Nicks(256);

    pub fn fee_for_many<T: AsRef<SpendV1>>(
        spends: impl Iterator<Item = T>,
        per_word: Nicks,
    ) -> Nicks {
        let fee = spends
            .map(|v| v.as_ref().unclamped_fee(per_word))
            .sum::<Nicks>();
        fee.max(Self::MIN_FEE)
    }

    pub fn unclamped_fee(&self, per_word: Nicks) -> Nicks {
        let (a, b) = self.calc_words();
        per_word * (a + b)
    }

    pub fn calc_words(&self) -> (u64, u64) {
        match self {
            SpendV1::S0 { spend, .. } => {
                let seed_words: u64 = spend
                    .seeds
                    .0
                    .iter()
                    .map(|seed| seed.note_data_words())
                    .sum();
                let sig_words = noun_words(&spend.signature.to_noun());
                (seed_words, sig_words)
            }
            SpendV1::S1 { spend, .. } => {
                let seed_words: u64 = spend
                    .seeds
                    .0
                    .iter()
                    .map(|seed| seed.note_data_words())
                    .sum();
                let witness_words = noun_words(&spend.witness.to_noun());
                (seed_words, witness_words)
            }
        }
    }

    pub fn new_legacy(seeds: SeedsV1, fee: Nicks) -> Self {
        SpendV1::S0 {
            version: ExpectedVersion,
            spend: Spend0V1 {
                signature: LegacySignature::default(),
                seeds,
                fee,
            },
        }
    }

    pub fn new_witness(witness: Witness, seeds: SeedsV1, fee: Nicks) -> Self {
        SpendV1::S1 {
            version: ExpectedVersion,
            spend: Spend1V1 {
                witness,
                seeds,
                fee,
            },
        }
    }

    pub fn fee(&self) -> Nicks {
        match self {
            SpendV1::S0 { spend, .. } => spend.fee,
            SpendV1::S1 { spend, .. } => spend.fee,
        }
    }

    pub fn fee_mut(&mut self) -> &mut Nicks {
        match self {
            SpendV1::S0 { spend, .. } => &mut spend.fee,
            SpendV1::S1 { spend, .. } => &mut spend.fee,
        }
    }

    pub fn seeds(&self) -> &SeedsV1 {
        match self {
            SpendV1::S0 { spend, .. } => &spend.seeds,
            SpendV1::S1 { spend, .. } => &spend.seeds,
        }
    }

    pub fn seeds_mut(&mut self) -> &mut SeedsV1 {
        match self {
            SpendV1::S0 { spend, .. } => &mut spend.seeds,
            SpendV1::S1 { spend, .. } => &mut spend.seeds,
        }
    }

    pub fn sig_hash(&self) -> Digest {
        match self {
            SpendV1::S0 { spend, .. } => spend.sig_hash(),
            SpendV1::S1 { spend, .. } => spend.sig_hash(),
        }
    }

    pub fn add_signature(&mut self, key: PublicKey, signature: Signature) {
        match self {
            SpendV1::S0 { spend, .. } => {
                spend.signature.add_entry(key, signature);
            }
            SpendV1::S1 { spend, .. } => {
                spend
                    .witness
                    .pkh_signature
                    .0
                    .insert(key.hash(), (key, signature));
            }
        }
    }

    pub fn add_preimage(&mut self, preimage: Noun) -> Digest {
        match self {
            SpendV1::S0 { .. } => {
                // Legacy spends do not carry hax preimages
                preimage.hash()
            }
            SpendV1::S1 { spend, .. } => {
                let digest = preimage.hash();
                spend.witness.hax_map.insert(digest, preimage);
                digest
            }
        }
    }

    pub fn clear_signatures(&mut self) {
        match self {
            SpendV1::S0 { spend, .. } => spend.signature.clear(),
            SpendV1::S1 { spend, .. } => spend.witness.pkh_signature.0.clear(),
        }
    }
}

impl Hashable for SpendV1 {
    fn hash(&self) -> Digest {
        match self {
            SpendV1::S0 { spend, .. } => {
                (Version::V0, &spend.signature, &spend.seeds, &spend.fee).hash()
            }
            SpendV1::S1 { spend, .. } => {
                (Version::V1, &spend.witness, &spend.seeds, &spend.fee).hash()
            }
        }
    }
}

#[derive(Debug, Clone, Default, Hashable, NounDecode, NounEncode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct PkhSignature(pub ZMap<Digest, (PublicKey, Signature)>);

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
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
            pkh_signature: PkhSignature(ZMap::new()),
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

#[derive(Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct LockMerkleProof {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub proof: MerkleProof,
}

impl Hashable for LockMerkleProof {
    fn hash(&self) -> Digest {
        // NOTE: lmao
        let axis_mold_hash: Digest = "6mhCSwJQDvbkbiPAUNjetJtVoo1VLtEhmEYoU4hmdGd6ep1F6ayaV4A"
            .try_into()
            .unwrap();
        (&self.spend_condition.hash(), axis_mold_hash, &self.proof).hash()
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct MerkleProof {
    pub root: Digest,
    pub path: Vec<Digest>,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct SpendCondition(pub Vec<LockPrimitive>);

impl SpendCondition {
    pub fn new_pkh(pkh: Pkh) -> Self {
        SpendCondition([LockPrimitive::Pkh(pkh)].into())
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
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

impl Hashable for LockPrimitive {
    fn hash(&self) -> Digest {
        match self {
            LockPrimitive::Pkh(pkh) => ("pkh", pkh).hash(),
            LockPrimitive::Tim(tim) => ("tim", tim).hash(),
            LockPrimitive::Hax(hax) => ("hax", hax).hash(),
            LockPrimitive::Brn => ("brn", 0).hash(),
        }
    }
}

pub type LockTim = super::v0::Timelock;

#[derive(Debug, Clone, Hashable, NounDecode, NounEncode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct Hax(pub ZSet<Digest>);

#[derive(Debug, Clone, Default, Hashable, NounDecode, NounEncode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct SpendsV1(pub ZMap<Name, SpendV1>);

impl SpendsV1 {
    pub fn fee(&self, per_word: Nicks) -> Nicks {
        SpendV1::fee_for_many(self.0.iter().map(|(_k, v)| v), per_word)
    }

    pub fn split_witness(&self) -> (SpendsV1, WitnessData) {
        let mut spends = SpendsV1(ZMap::new());
        let mut witness_data = WitnessData::default();
        for (name, spend) in &self.0 {
            let mut spend = spend.clone();
            match &mut spend {
                SpendV1::S1 { spend: ws, .. } => {
                    let witness = ws.witness.take_data();
                    spends.0.insert(*name, spend);
                    witness_data.data.insert(*name, witness);
                }
                SpendV1::S0 { .. } => {
                    spends.0.insert(*name, spend);
                }
            }
        }
        (spends, witness_data)
    }

    pub fn apply_witness(&self, witness_data: &WitnessData) -> SpendsV1 {
        let mut spends = SpendsV1::default();
        for (name, spend) in &self.0 {
            let mut spend = spend.clone();
            // NOTE: this behavior does not match the wallet hoon, but if the worst that can happen is transaction remain invalid, it's ok.
            if let SpendV1::S1 { spend: ws, .. } = &mut spend {
                if let Some(witness) = witness_data.data.get(name) {
                    ws.witness = witness.clone();
                }
            }
            spends.0.insert(*name, spend);
        }
        spends
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, NounEncode, NounDecode)]
#[iris_ztd::wasm_noun_codec(no_hash)]
pub struct RawTxV1 {
    #[cfg_attr(feature = "wasm", tsify(type = "1"))]
    pub version: ExpectedVersion<1>,
    pub id: TxId,
    pub spends: SpendsV1,
}

impl RawTxV1 {
    pub fn new(spends: SpendsV1) -> Self {
        let id = (Version::V1, &spends).hash();
        Self {
            version: ExpectedVersion,
            id,
            spends,
        }
    }

    pub fn version(&self) -> Version {
        Version::V1
    }

    /// Calculate output notes from the transaction spends.
    ///
    /// This function combines seeds across multiple spends into one output note per-lock-root.
    pub fn outputs(&self) -> Vec<NoteV1> {
        // Already a ZMap, no conversion needed
        let spends = &self.spends.0;

        let mut seeds_by_lock: BTreeMap<Digest, ZSet<SeedV1>> = BTreeMap::new();
        for (_, spend) in spends {
            for seed in spend.seeds().0.iter() {
                seeds_by_lock
                    .entry(seed.lock_root.hash())
                    .or_default()
                    .insert(seed.clone());
            }
        }

        let mut outputs: Vec<NoteV1> = Vec::new();

        for (lock_root_hash, seeds) in seeds_by_lock {
            let seeds: Vec<SeedV1> = seeds.into_iter().collect();

            if seeds.is_empty() {
                continue;
            }

            let total_assets: Nicks = seeds.iter().map(|s| s.gift).sum();

            // Hoon code ends up taking the last note-data for the output note, by the tap order of z-set.
            let note_data = seeds[seeds.len() - 1].note_data.clone();

            let mut normalized_seeds_set: ZSet<SeedV1> = ZSet::new();
            for seed in seeds {
                let mut normalized_seed = seed.clone();
                normalized_seed.output_source = None;
                normalized_seeds_set.insert(normalized_seed);
            }

            let src_hash = normalized_seeds_set.hash();

            let src = Source {
                hash: src_hash,
                is_coinbase: false,
            };

            let name = Name::new_v1(lock_root_hash, src);

            let note = NoteV1::new(
                Version::V1,
                // As opposed to `None`.
                0,
                name,
                note_data,
                total_assets,
            );

            outputs.push(note);
        }

        outputs
    }

    pub fn to_nockchain_tx(&self) -> NockchainTx {
        let (spends, witness_data) = self.spends.split_witness();
        NockchainTx {
            version: Version::V1,
            id: self.id,
            spends,
            display: TransactionDisplay::default(),
            witness_data,
        }
    }

    pub fn calc_id(&self) -> TxId {
        (&Version::V1, &self.spends).hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec(no_hash)]
pub struct NockchainTx {
    pub version: Version,
    pub id: TxId,
    pub spends: SpendsV1,
    pub display: TransactionDisplay,
    pub witness_data: WitnessData,
}

impl NockchainTx {
    pub fn to_raw_tx(&self) -> RawTxV1 {
        assert_eq!(
            self.version,
            Version::V1,
            "Non-V1 TXs presently unsupported"
        );

        let spends = self.spends.apply_witness(&self.witness_data);

        RawTxV1 {
            version: ExpectedVersion,
            id: self.id,
            spends,
        }
    }

    pub fn outputs(&self) -> Vec<NoteV1> {
        self.to_raw_tx().outputs()
    }
}

impl NounEncode for NockchainTx {
    fn to_noun(&self) -> Noun {
        (
            &self.version,
            &self.id.to_string(),
            &self.spends,
            &self.display,
            &self.witness_data,
        )
            .to_noun()
    }
}

impl NounDecode for NockchainTx {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (Version::V1, name, spends, display, witness_data): (_, String, _, _, _) =
            NounDecode::from_noun(noun)?
        else {
            return None;
        };

        let id = TxId::try_from(&*name).ok()?;

        Some(Self {
            version: Version::V1,
            id,
            spends,
            display,
            witness_data,
        })
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec(no_hash)]
pub struct WitnessData {
    pub data: ZMap<Name, Witness>,
}

impl NounEncode for WitnessData {
    fn to_noun(&self) -> Noun {
        (1, &self.data).to_noun()
    }
}

impl NounDecode for WitnessData {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (Version::V1, data) = NounDecode::from_noun(noun)? else {
            return None;
        };
        Some(Self { data })
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec]
pub struct LockMetadata {
    pub lock: SpendCondition,
    pub include_data: bool,
}

impl From<SpendCondition> for LockMetadata {
    fn from(value: SpendCondition) -> Self {
        Self {
            lock: value,
            include_data: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec(no_hash)]
#[serde(untagged)]
pub enum InputDisplay {
    V0 {
        #[cfg_attr(feature = "wasm", tsify(type = "0"))]
        version: ExpectedVersion<0>,
        p: ZMap<Name, super::v0::Sig>,
    },
    V1 {
        #[cfg_attr(feature = "wasm", tsify(type = "1"))]
        version: ExpectedVersion<1>,
        p: ZMap<Name, SpendCondition>,
    },
}

impl Default for InputDisplay {
    fn default() -> Self {
        Self::V0 {
            version: ExpectedVersion,
            p: ZMap::new(),
        }
    }
}

impl NounEncode for InputDisplay {
    fn to_noun(&self) -> Noun {
        match self {
            InputDisplay::V0 { version, p } => (version, p).to_noun(),
            InputDisplay::V1 { version, p } => (version, p).to_noun(),
        }
    }
}

impl NounDecode for InputDisplay {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (version, map): (Version, Noun) = NounDecode::from_noun(noun)?;
        match version {
            Version::V0 => Some(InputDisplay::V0 {
                version: ExpectedVersion,
                p: NounDecode::from_noun(&map)?,
            }),
            Version::V1 => Some(InputDisplay::V1 {
                version: ExpectedVersion,
                p: NounDecode::from_noun(&map)?,
            }),
            _ => None,
        }
    }
}

#[derive(Default, Debug, Clone, NounEncode, NounDecode, Serialize, Deserialize)]
#[iris_ztd::wasm_noun_codec(no_hash)]
pub struct TransactionDisplay {
    pub inputs: InputDisplay,
    pub outputs: ZMap<Digest, LockMetadata>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use iris_crypto::derive_master_key;
    use iris_ztd::Hashable;

    use super::{RawTxV1 as RawTx, SeedV1 as Seed, SpendV1 as Spend, SpendsV1 as Spends};

    fn check_hash(name: &str, h: &impl Hashable, exp: &str) {
        assert_eq!(h.hash().to_string(), exp, "hash mismatch for {}", name);
    }

    const TX1: &[u8] = include_bytes!(
        "../../test_vectors/45x6JVbHdgtWbGhJFEjYUoryo2axyq34CFyBfKnknEkbgUM6dwEnPSz.tx"
    );
    // Computed with (txr being the raw-tx from TX1):
    // /| txo tx |=  [v=@tas b=spends:v1:transact]  =/  a  (new:raw-tx:v1:transact b)  =/  tx  (new:tx:v1:transact a 0)  =/  outs  outputs.tx  =/  g  |=  [n=nnote:v1:transact b=seeds:v1:transact]  n  =/  ol  ~(tap z-in outs)  (turn ol g)
    const TX1_OUTPUTS: &[u8] = include_bytes!(
        "../../test_vectors/45x6JVbHdgtWbGhJFEjYUoryo2axyq34CFyBfKnknEkbgUM6dwEnPSz.txo"
    );

    #[test]
    fn check_tx_v0_v1() {
        let noun = iris_ztd::cue(TX1).unwrap();
        let (txid, spends): (String, Spends) = NounDecode::from_noun(&noun).unwrap();
        let tx = RawTx::new(spends);
        let id = tx.calc_id();
        assert_eq!(id.to_string(), txid);

        let out_noun = iris_ztd::cue(TX1_OUTPUTS).unwrap();
        let mut outs: Vec<NoteV1> = NounDecode::from_noun(&out_noun).unwrap();
        outs.sort_by_key(|note| note.name);

        let mut tx_outs = tx.outputs();
        tx_outs.sort_by_key(|note| note.name);

        assert_eq!(outs, tx_outs);
    }

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
            Nicks(4290881913),
            "6qF9RtWRUWfCX8NS8QU2u7A3BufVrsMwwWWZ8KSzZ5gVn4syqmeVa4"
                .try_into()
                .unwrap(),
            true,
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
        seed2.gift = Nicks(1234567);

        let mut spend = Spend::new_witness(
            Witness::new(SpendCondition(
                [
                    LockPrimitive::Pkh(Pkh::single(pkh)),
                    LockPrimitive::Tim(LockTim::coinbase()),
                ]
                .into(),
            )),
            SeedsV1([seed1.clone(), seed2.clone()].into()),
            Nicks(2850816),
        );

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

        let SpendV1::S1 { spend: ws, .. } = &spend else {
            panic!("expected witness spend");
        };

        check_hash(
            "spend condition tim",
            &ws.witness.lock_merkle_proof.spend_condition.0[1],
            "B5RtZnbphbf1D5vQwsZjHycLN2Ldp7RD2pK6V3qAMFCrxnUXAhgmKgg",
        );

        check_hash(
            "spend condition pkh",
            &ws.witness.lock_merkle_proof.spend_condition.0[0],
            "65RqCgowDZJziLZzpQkPULVy2tb1dMGMUrgsxxfC1mPPK6hSNKAP6DP",
        );

        check_hash(
            "spend condition",
            &ws.witness.lock_merkle_proof.spend_condition,
            "5k2qTDtcxyQWBmsVTi1fEmbSeoAnq5B83SGoJwDU8NJkRfXWevwQDWn",
        );

        check_hash(
            "pkh",
            &ws.witness.pkh_signature,
            "4oMCHwUMend6ds2Gt3bUyz4cNrZto4PepFgbQQWYDRKMB3v9qaccMT",
        );

        check_hash(
            "merkle proof",
            &ws.witness.lock_merkle_proof.proof,
            "MefKNQSmk8wzDzCPpY93GMdM53Pv1TGbUZe2Kn427FiuvbgjSZe5eJ",
        );

        check_hash(
            "lock merkle proof",
            &ws.witness.lock_merkle_proof,
            "6MNHCVrns4DjMxAV4CJQWKsPcpXPDSqizJsChgMYozsHsLBev52RRW1",
        );

        check_hash(
            "witness",
            &ws.witness,
            "4fnjd1sxmaxupG3EYqBkvaQs6aiKHi9bZKciYipBA9an4DXuRH938L8",
        );

        check_hash(
            "seeds",
            spend.seeds(),
            "7Zuskz3WibckR2anDXDuPcMUk45A2iJnrdPsFALj4Rc5NTufyca39gY",
        );

        let spends = Spends([(name, spend)].into());
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
    }
}
