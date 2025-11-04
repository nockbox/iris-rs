use alloc::vec::Vec;
use nbx_crypto::{PublicKey, Signature};
use nbx_ztd::Digest;
use nbx_ztd_derive::Hashable;

use super::note::{Name, NoteData, Source, TimelockRange, Version};
use crate::{Nicks, Pkh};

#[derive(Debug, Clone, Hashable)]
pub struct Seed {
    pub output_source: Option<Source>,
    pub lock_root: Digest,
    pub note_data: NoteData,
    pub gift: Nicks,
    pub parent_hash: Digest,
}

#[derive(Debug, Clone, Hashable)]
pub struct Seeds(pub Vec<Seed>);

#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone)]
pub struct Witness {
    pub lock_merkle_proof: LockMerkleProof,
    pub pkh_signature: PkhSignature,
    pub hax: Vec<HaxPreimage>,
    _tim: Option<()>, // always None for now
}

impl Witness {
    pub fn new(
        lock_merkle_proof: LockMerkleProof,
        pkh_signature: PkhSignature,
        hax: Vec<HaxPreimage>,
    ) -> Self {
        Self {
            lock_merkle_proof,
            pkh_signature,
            hax,
            _tim: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HaxPreimage {
    pub hash: Digest,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PkhSignature(pub Vec<PkhSignatureEntry>);

#[derive(Debug, Clone)]
pub struct PkhSignatureEntry {
    pub hash: Digest,
    pub pubkey: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone)]
pub struct LockMerkleProof {
    pub spend_condition: SpendCondition,
    pub axis: u64,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub root: Digest,
    pub path: Vec<Digest>,
}

#[derive(Debug, Clone)]
pub struct SpendCondition(pub Vec<LockPrimitive>);

#[derive(Debug, Clone)]
pub enum LockPrimitive {
    Pkh(Pkh),
    Tim(LockTim),
    Hax(Hax),
    Burn,
}

#[derive(Debug, Clone)]
pub struct LockTim {
    pub rel: TimelockRange,
    pub abs: TimelockRange,
}

#[derive(Debug, Clone)]
pub struct Hax(pub Vec<Digest>);

pub type TxId = Digest;

#[derive(Debug, Clone)]
pub struct RawTx {
    pub version: Version,
    pub id: TxId,
    pub spends: Spends,
}

#[derive(Debug, Clone)]
pub struct Spends(pub Vec<(Name, Spend)>);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use bip39::Mnemonic;
    use nbx_crypto::derive_master_key;
    use nbx_ztd::from_b58;
    use nbx_ztd::{Belt, Hashable, NounHashable};

    fn check_hash(name: &str, h: &impl Hashable, exp: &str) {
        assert!(
            h.hash().to_bytes().to_vec() == from_b58(exp),
            "hash mismatch for {}",
            name
        );
    }

    #[test]
    fn test_hash_vectors() {
        let pubkey1 = PublicKey::from_be_bytes(&from_b58("2avD9nwHSnpPMopwMFpJkQpcovPcb75X81CjNhHNL5c5B4T96CpZbUBMB9YsQBgK7S6J767oAezPcTYJuafAQReGWLRuy6CvPjN8URX2UYd1Yq5a9NcsNGQuAY9Q1KDiK643"));
        let parent_hash = Digest([
            Belt(0xbb2ecaacd363a37b),
            Belt(0xf7b92ab955f8ef95),
            Belt(0x74356725cdb71450),
            Belt(0x16da9b635d708d08),
            Belt(0x02060b5a39ba3f8d),
        ]);

        // let lock_root = Pkh::new(1, vec![pubkey1.hash()]).hash();

        let lock_root = Digest([
            Belt(0x7234a70620ce55ec),
            Belt(0xe0283891c013ac52),
            Belt(0x1d18bf3f6e112429),
            Belt(0xe6f8d2ca743d3093),
            Belt(0x5c74aef22db7d96e),
        ]);

        let seed1 = Seed {
            output_source: None,
            lock_root,
            note_data: NoteData(ZMap::new()),
            gift: Nicks(1234567),
            parent_hash,
        };

        // let spend = &Spend {
        //     witness: Witness::new(lock_merkle_proof, pkh_signature, hax)
        //     seeds: Seeds::new(vec![seed1.clone(), seed2.clone()]),
        //     fee: Nicks(2850816),
        // };

        check_hash(
            "output_source=~",
            &seed1.output_source,
            "3Ssr4tiWsbX5CE3AG6p5qPHP51fiyvtt1XEEHmSbGgDjp3qjUew6DFB",
        );
        check_hash(
            "nicks=1234567",
            &seed1.gift,
            "9MnJmEz2kfExCthx4ib6dHvaZ42bFyQy9sVy4RBboSnKP6aUvYbvQhb",
        );
        check_hash(
            "note-data",
            &seed1.note_data,
            "7hLhhBXik77vGuhxz9V9EKB5WcXhr692PsmV6AffGrQaxuF1df3kYUT",
        );
        check_hash(
            "seed1",
            &seed1,
            "ANtVFbzDyhjx9SZwS92n9vKGkRLA5fhiLg8963JpUcRYEYgby5DKVeA",
        );
        // check_hash(
        //     "sig-hash",
        //     &spend.sig_hash(),
        //     "7WFUmayFyvYootwtdjQCk7rB94oUs5gp88HVuQDNBrQwo8geJMpBfJ8",
        // );

        check_hash(
            "sig-hash",
            &(Seeds(vec![seed1.clone()]), Nicks(2850816)),
            "7WFUmayFyvYootwtdjQCk7rB94oUs5gp88HVuQDNBrQwo8geJMpBfJ8",
        );

        // from nockchain-wallet sign-tx
        // let mnemonic = Mnemonic::parse("fee hurry again spread effort private grape avoid found mixture ship upper ask diamond wrong cluster maze polar digital cross gesture report agree become").unwrap();
        // assert_eq!(
        //     derive_master_key(&mnemonic.to_seed(""))
        //         .private_key
        //         .unwrap()
        //         .sign(&spend.sig_hash())
        //         .noun_hash()
        //         .to_bytes()
        //         .to_vec(),
        //     from_b58("2MBv1RmgAhywpoJC9PbMXrBMrDUZ51j5Mx1Qv2LNHR9aGxo67nxYNoJ")
        // );
    }
}
