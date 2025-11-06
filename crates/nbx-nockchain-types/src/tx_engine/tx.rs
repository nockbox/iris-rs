use alloc::vec;
use alloc::vec::Vec;
use nbx_crypto::{PublicKey, Signature};
use nbx_ztd::{Belt, Digest, Hashable as HashableTrait, NounHashable, ZSet};
use nbx_ztd_derive::{Hashable, NounHashable};

use super::note::{Name, NoteData, Source, TimelockRange, Version};
use crate::{Nicks, Pkh};

#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct Seed {
    pub lock_root: Digest,
    pub note_data: NoteData,
    pub gift: Nicks,
    pub parent_hash: Digest,
}

impl Seed {
    pub fn new_single_pkh(pkh: Digest, gift: Nicks, parent_hash: Digest) -> Self {
        let lock_root = SpendCondition::new_pkh(Pkh::single(pkh)).hash();
        let note_data = NoteData(Pkh::single(pkh));
        Self {
            lock_root,
            note_data,
            gift,
            parent_hash,
        }
    }

    pub fn sig_hash(&self) -> Digest {
        // NOTE: we assume output-source=~
        (&Option::<Source>::None, &self).hash()
    }
}

#[derive(Debug, Clone)]
pub struct Seeds(pub Vec<Seed>);

impl Seeds {
    fn sig_hash(&self) -> Digest {
        ZSet::from_iter(self.0.iter().map(Seed::sig_hash)).hash()
    }
}

impl HashableTrait for Seeds {
    fn hash(&self) -> Digest {
        ZSet::from_iter(self.0.iter().map(Seed::hash)).hash()
    }
}

impl NounHashable for Seeds {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        ZSet::from_iter(self.0.iter()).write_noun_parts(leaves, dyck);
    }
}

#[derive(Debug, Clone, NounHashable)]
pub struct Spend {
    pub witness: Witness,
    pub seeds: Seeds,
    pub fee: Nicks,
}

impl Spend {
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
        self.witness.pkh_signature.0.push((key, signature));
    }
}

impl HashableTrait for Spend {
    fn hash(&self) -> Digest {
        (1, (&self.witness, (&self.seeds, &self.fee))).hash()
    }
}

#[derive(Debug, Clone)]
pub struct PkhSignature(pub Vec<(PublicKey, Signature)>);

impl HashableTrait for PkhSignature {
    fn hash(&self) -> Digest {
        ZSet::from_iter(self.0.iter().map(|e| (e.0.hash(), e).hash())).hash()
    }
}

impl NounHashable for PkhSignature {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        ZSet::from_iter(self.0.iter()).write_noun_parts(leaves, dyck);
    }
}

#[derive(Debug, Clone, NounHashable)]
pub struct Witness {
    pub lock_merkle_proof: LockMerkleProof,
    pub pkh_signature: PkhSignature,
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
        }
    }
}

impl HashableTrait for Witness {
    fn hash(&self) -> Digest {
        [
            self.lock_merkle_proof.hash(),
            self.pkh_signature.hash(),
            0.hash(), // hax
            0.hash(), // tim
        ]
        .as_slice()
        .hash()
    }
}

#[derive(Debug, Clone, NounHashable)]
pub struct LockMerkleProof {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub proof: MerkleProof,
}

impl HashableTrait for LockMerkleProof {
    fn hash(&self) -> Digest {
        // NOTE: lmao
        let axis_mold_hash: Digest =
            "6mhCSwJQDvbkbiPAUNjetJtVoo1VLtEhmEYoU4hmdGd6ep1F6ayaV4A".into();
        (&self.spend_condition.hash(), (axis_mold_hash, &self.proof)).hash()
    }
}

#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct MerkleProof {
    pub root: Digest,
    pub path: Vec<Digest>,
}

#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct SpendCondition(pub Vec<LockPrimitive>);

impl SpendCondition {
    pub fn new_pkh(pkh: Pkh) -> Self {
        SpendCondition(vec![LockPrimitive::Pkh(pkh)])
    }
}

#[derive(Debug, Clone)]
pub enum LockPrimitive {
    Pkh(Pkh),
    Tim(LockTim),
    Hax(Hax),
    Brn,
}

impl NounHashable for LockPrimitive {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        match self {
            LockPrimitive::Pkh(pkh) => ("pkh", pkh).write_noun_parts(leaves, dyck),
            LockPrimitive::Tim(tim) => ("tim", tim).write_noun_parts(leaves, dyck),
            LockPrimitive::Hax(hax) => ("hax", hax).write_noun_parts(leaves, dyck),
            LockPrimitive::Brn => ("brn", 0).write_noun_parts(leaves, dyck),
        }
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

#[derive(Debug, Clone, NounHashable, Hashable)]
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

#[derive(Debug, Clone, NounHashable, Hashable)]
pub struct Hax(pub Vec<Digest>);

pub type TxId = Digest;

#[derive(Debug, Clone)]
pub struct Spends(pub Vec<(Name, Spend)>);

impl HashableTrait for Spends {
    fn hash(&self) -> Digest {
        ZSet::from_iter(self.0.iter()).hash()
    }
}

#[derive(Debug, Clone)]
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
    use nbx_ztd::{Hashable, NounHashable};

    fn check_hash(name: &str, h: &impl Hashable, exp: &str) {
        assert!(h.hash() == exp.into(), "hash mismatch for {}", name);
    }

    #[test]
    fn test_hash_vectors() {
        let seed1 = Seed::new_single_pkh(
            "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".into(),
            4290881913,
            "6qF9RtWRUWfCX8NS8QU2u7A3BufVrsMwwWWZ8KSzZ5gVn4syqmeVa4".into(),
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
        check_hash(
            "seed1 sighash",
            &seed1.sig_hash(),
            "3aoHgNNtKdMd3tDQkSHcouYw9y8PbefbcWGTSEYaKvdam8VNvCnXBJS",
        );

        let mut seed2 = seed1.clone();
        seed2.gift = 1234567;
        check_hash(
            "seed2 sighash",
            &seed2.sig_hash(),
            "ANtVFbzDyhjx9SZwS92n9vKGkRLA5fhiLg8963JpUcRYEYgby5DKVeA",
        );

        let mut spend = Spend {
            witness: Witness::new(SpendCondition(vec![
                LockPrimitive::Pkh(seed1.note_data.0.clone()),
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
            &signature.noun_hash(),
            "DKGrE8s8hhacsnGMzLWqRKfTtXx4QG6tDvC3k1Xu6FA7xAaetGPK6Aj",
        );
        spend.add_signature(private_key.public_key(), signature);

        check_hash(
            "spend",
            &spend,
            "CTYHRFefGkubLBG8WszvXq1v5XevLkbP3aBezMza9zen6Fbvyu8dD17",
        );

        let name = Name::new(
            "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".into(),
            "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".into(),
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
            "transaction name",
            &tx.id,
            "3j4vkn72mcpVtQrTgNnYyoF3rDuYax3aebT5axu3Qe16jm9x2wLtepW",
        );
    }
}
