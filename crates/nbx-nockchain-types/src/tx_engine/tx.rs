use alloc::vec::Vec;
use nbx_crypto::{PrivateKey, PublicKey, Signature};
use nbx_ztd::{Digest, Hashable, ZSet};
use nbx_ztd_derive::{Hashable, NounHashable};

use super::note::{Name, Note, Source, TimelockIntent};
use crate::{Lock, Nicks, TimelockRange};

#[derive(Debug, Clone, Hashable, NounHashable)]
pub struct Seed {
    pub output_source: Option<Source>,
    pub recipient: Lock,
    pub timelock_intent: Option<TimelockIntent>,
    pub gift: Nicks,
    pub parent_hash: Digest,
}

#[derive(Debug, Clone, Hashable)]
pub struct Seeds {
    pub seeds: ZSet<Seed>,
}

impl Seeds {
    pub fn new(seeds: Vec<Seed>) -> Self {
        Self {
            seeds: ZSet::from_iter(seeds),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Input {
    pub note: Note,
    pub spend: Spend,
}

#[derive(Debug, Clone)]
pub struct Spend {
    pub signatures: Vec<(PublicKey, Signature)>,
    pub seeds: Seeds,
    pub fee: Nicks,
}

impl Spend {
    pub fn new(seeds: Seeds, fee: Nicks) -> Self {
        Self {
            signatures: Vec::new(),
            seeds,
            fee,
        }
    }

    pub fn sig_hash(&self) -> Digest {
        (&self.seeds, &self.fee).hash()
    }

    pub fn sign(mut self, private_key: &PrivateKey) -> Self {
        self.signatures.push((
            private_key.derive_public_key(),
            private_key.sign(&self.sig_hash()),
        ));
        self
    }
}

#[derive(Debug, Clone)]
pub struct Inputs(pub Vec<(Name, Input)>);

pub type TxId = Digest;

#[derive(Debug, Clone)]
pub struct RawTx {
    pub id: TxId,
    pub inputs: Inputs,
    pub timelock_range: TimelockRange,
    pub total_fees: Nicks,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockHeight;
    use alloc::vec;
    use bip39::Mnemonic;
    use nbx_crypto::derive_master_key;
    use nbx_ztd::from_b58;
    use nbx_ztd::{Belt, NounHashable};

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
        let pubkey2 = PublicKey::from_be_bytes(&from_b58("3151zjow1euAu8xJLewQc5xAwUzcVnpqWWLD8r8MHKzej5puDPFa1UpgtYcWU9kdu2sq9ZkJKMooZdJPHowdQrZVoUQUVRL5PSDAZPvkkJmRGdsz2YQZvghymFtX3bcQcECZ"));
        let parent_hash = Digest([
            Belt(0x86508283151be52d),
            Belt(0x4dbad02401bf7137),
            Belt(0xa1a705b85205c9a8),
            Belt(0xa183ecffbb02b0e2),
            Belt(0xc1de55bcd4c0de0e),
        ]);

        let seed1 = Seed {
            output_source: None,
            recipient: Lock::new(1, vec![pubkey1]),
            timelock_intent: Some(TimelockIntent {
                absolute: TimelockRange::new(None, None),
                relative: TimelockRange::new(
                    Some(BlockHeight(Belt(30))),
                    Some(BlockHeight(Belt(1000))),
                ),
            }),
            gift: Nicks(1000),
            parent_hash,
        };

        let seed2 = Seed {
            output_source: None,
            recipient: Lock::new(1, vec![pubkey2]),
            timelock_intent: None,
            gift: Nicks(4294966286),
            parent_hash,
        };

        let spend = &Spend {
            signatures: vec![],
            seeds: Seeds::new(vec![seed1.clone(), seed2.clone()]),
            fee: Nicks(10),
        };

        check_hash(
            "output_source=~",
            &seed1.output_source,
            "3Ssr4tiWsbX5CE3AG6p5qPHP51fiyvtt1XEEHmSbGgDjp3qjUew6DFB",
        );
        check_hash(
            "nicks=1.000",
            &seed1.gift,
            "96JweZRSXEBMQHg1XVKRqJGgnUdKURQRSK72idXPqbhSW3UzNjwx4xQ",
        );
        check_hash(
            "timelock-intent=[~ [absolute=[min=~ max=~] relative=[min=[~ 30] max=[~ 1.000]]]]",
            &seed1.timelock_intent,
            "6axBiDcCo41grhGBTKMR6hGsv8Yd8Sqz8wX9kis9N6WFPyYpsZcrdx3",
        );
        check_hash(
            "lock=[m=1 pubkeys={...}]",
            &seed1.recipient,
            "DMZhz1i4HPkzqLa8hEjEeWRfbdh5oKMtSkAjtTxFRZuYNYhNCtPLvzn",
        );
        check_hash(
            "seed1",
            &seed1,
            "4PzxKM56mAceYK1Kxf1FjUCfF5wNoLEFotPyS6dfEXme6EBVv2UCSx8",
        );
        check_hash(
            "seed2",
            &seed2,
            "54Y5UhsKQZD9nkrM8pZ8mvULLTTyCgie593c9mjyboSWhrBrNthJorT",
        );
        check_hash(
            "sig-hash",
            &spend.sig_hash(),
            "7WFUmayFyvYootwtdjQCk7rB94oUs5gp88HVuQDNBrQwo8geJMpBfJ8",
        );

        // from nockchain-wallet sign-tx
        let mnemonic = Mnemonic::parse("fee hurry again spread effort private grape avoid found mixture ship upper ask diamond wrong cluster maze polar digital cross gesture report agree become").unwrap();
        assert_eq!(
            derive_master_key(&mnemonic.to_seed(""))
                .private_key
                .unwrap()
                .sign(&spend.sig_hash())
                .noun_hash()
                .to_bytes()
                .to_vec(),
            from_b58("2MBv1RmgAhywpoJC9PbMXrBMrDUZ51j5Mx1Qv2LNHR9aGxo67nxYNoJ")
        );
    }
}
