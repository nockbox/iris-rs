use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use nbx_crypto::{PublicKey, Signature};
use nbx_ztd::{Digest, Hashable as HashableTrait, Noun, NounDecode, NounEncode, ZMap, ZSet};
use nbx_ztd_derive::{Hashable, NounDecode, NounEncode};

use super::note::{Name, NoteData, Source, TimelockRange, Version};
use crate::{Nicks, Pkh};

fn noun_words(n: &Noun) -> u64 {
    match n {
        Noun::Atom(_) => 1,
        Noun::Cell(l, r) => noun_words(l) + noun_words(r),
    }
}

#[derive(Debug, Clone, NounEncode, NounDecode)]
pub struct Seed {
    pub output_source: Option<Source>,
    pub lock_root: Digest,
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
    ) -> Self {
        let lock_root = SpendCondition::new_pkh(Pkh::single(pkh)).hash();
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

#[derive(Debug, Clone)]
pub struct PkhSignature(pub Vec<(Digest, PublicKey, Signature)>);

impl HashableTrait for PkhSignature {
    fn hash(&self) -> Digest {
        ZSet::from_iter(&self.0).hash()
    }
}

impl NounEncode for PkhSignature {
    fn to_noun(&self) -> Noun {
        ZSet::from_iter(&self.0).to_noun()
    }
}

impl NounDecode for PkhSignature {
    fn from_noun(noun: &Noun) -> Option<Self> {
        Some(Self(ZSet::from_noun(noun)?.into_iter().collect::<Vec<_>>()))
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

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode)]
pub struct MerkleProof {
    pub root: Digest,
    pub path: Vec<Digest>,
}

#[derive(Debug, Clone, Hashable, NounEncode, NounDecode)]
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
    fn to_noun(&self) -> nbx_ztd::Noun {
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

#[derive(Debug, Clone, NounEncode, Hashable, NounDecode)]
pub struct Hax(pub Vec<Digest>);

pub type TxId = Digest;

#[derive(Debug, Clone)]
pub struct Spends(pub Vec<(Name, Spend)>);

impl Spends {
    pub fn fee(&self, per_word: Nicks) -> Nicks {
        Spend::fee_for_many(self.0.iter().map(|v| &v.1), per_word)
    }
}

impl NounEncode for Spends {
    fn to_noun(&self) -> Noun {
        ZMap::from_iter(self.0.iter().cloned()).to_noun()
    }
}

impl NounDecode for Spends {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let v: ZMap<Name, Spend> = NounDecode::from_noun(noun)?;
        Some(Self(v.into_iter().collect::<Vec<_>>()))
    }
}

impl HashableTrait for Spends {
    fn hash(&self) -> Digest {
        ZSet::from_iter(&self.0).hash()
    }
}

#[derive(Debug, Clone, NounEncode)]
pub struct RawTx {
    pub version: Version,
    pub id: TxId,
    pub spends: Spends,
}

impl RawTx {
    pub fn new(spends: Spends) -> Self {
        let version = Version::V1;
        let id = (&version, &spends).hash();
        Self {
            version,
            id,
            spends,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use bip39::Mnemonic;
    use nbx_crypto::derive_master_key;
    use nbx_ztd::Hashable;

    fn check_hash(name: &str, h: &impl Hashable, exp: &str) {
        assert!(
            h.hash() == exp.try_into().unwrap(),
            "hash mismatch for {}",
            name
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
    }
}
