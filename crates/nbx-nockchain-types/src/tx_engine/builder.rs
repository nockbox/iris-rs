use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use nbx_crypto::PrivateKey;
use nbx_ztd::{Digest, Hashable as HashableTrait, Noun};

use super::{LockPrimitive, Name, NoteData};
use super::note::Note;
use super::tx::{Seed, Seeds, Spend, SpendCondition, Spends, Witness};
use crate::{Nicks, RawTx};

struct SpendBuilder {
    note: Note,
    unlocks: Vec<(LockPrimitive, bool)>,
    witness: Witness,
    fee_portion: Nicks,
}

impl SpendBuilder {
    pub fn new(note: Note, spend_condition: SpendCondition) -> Self {
        Self {
            note,
            witness: Witness::new(spend_condition.clone()),
            unlocks: spend_condition.0.into_iter().map(|v| (v, false)).collect(),
            fee_portion: 0,
        }
    }

    pub fn fee_portion(&mut self, fee_portion: Note) {
        self.fee_portion = fee_portion;
    }
}

pub struct TxBuilder {
    spends: BTreeMap<Name, SpendBuilder>,
    fee: Nicks,
}

impl TxBuilder {
    pub fn new() -> Self {
        Self {
            spends: BTreeMap::new(),
            fee: 0,
        }
    }

    pub fn spend(&mut self, spend: SpendBuilder) -> bool {
        let name = spend.note.name;
        self.spends.insert(name, spend)
    }

    pub fn new_simple(
        notes: Vec<Note>,
        spend_condition: SpendCondition,
        recipient: Digest,
        gift: Nicks,
        fee: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
    ) -> Result<Self, BuildError> {
        if gift == 0 {
            return Err(BuildError::ZeroGift);
        }

        let mut spends_vec = Vec::new();
        let mut remaining_gift = gift;
        let mut remaining_fee = fee;

        for note in notes {
            let gift_portion = remaining_gift.min(note.assets);
            let fee_portion = remaining_fee.min(note.assets.saturating_sub(gift_portion));
            let refund = note.assets.saturating_sub(gift_portion + fee_portion);

            if gift_portion == 0 && refund == 0 {
                continue;
            }

            remaining_gift -= gift_portion;
            remaining_fee -= fee_portion;

            let mut seeds_vec = Vec::new();
            if refund > 0 {
                seeds_vec.push(Seed::new_single_pkh(refund_pkh, refund, note.hash(), include_lock_data));
            }
            if gift_portion > 0 {
                seeds_vec.push(Seed::new_single_pkh(recipient, gift_portion, note.hash(), include_lock_data));
            }

            let spend = Spend::new(
                Witness::new(spend_condition.clone()),
                Seeds(seeds_vec),
                fee_portion,
            );
            spends_vec.push((note.name.clone(), spend));
        }

        if remaining_gift > 0 || remaining_fee > 0 {
            return Err(BuildError::InsufficientFunds);
        }

        Ok(Self {
            spends: Spends(spends_vec),
            fee,
        })
    }

    pub fn add_preimage(&mut self, note: &Note, preimage: Noun) -> Digest {
        let digest = preimage.hash();

        for spend in self.spends.values_mut() {
            for (c, u) in spend.unlocks.iter_mut() {
                if *c == LockPrimitive::Hax(digest) {
                    *u = true;
                    spend.witness.hax_map.insert(digest, preimage.clone());
                    break;
                }
            }
        }

        digest
    }

    pub fn sign(mut self, signing_key: &PrivateKey) -> Result<RawTx, BuildError> {
        let pkh = signing_key.public_key().hash();

        for spend in self.spends.values_mut() {
            for (c, u) in spend.unlocks.iter_mut() {
                match *c {
                    LockPrimitive::Pkh(pkh) if pkh.hashes.contains(&pkh) => {
                        *u = true;
                        spend.add_signature()
                    }
                }
                if *c == LockPrimitive::Pkh(pkh) {
                    *u = true;
                    spend.witness.hax_map.insert(digest, preimage.clone());
                    break;
                }
            }
        }

        let mut spends = self.spends;
        self.spends = Spends(vec![]);
        for (_, spend) in spends.0.as_mut_slice() {
            spend.add_signature(
                signing_key.public_key(),
                signing_key.sign(&spend.sig_hash()),
            );
        }
        Ok(RawTx::new(spends))
    }
}

#[derive(Debug)]
pub enum BuildError {
    ZeroGift,
    InsufficientFunds,
    AccountingMismatch,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BuildError::ZeroGift => write!(f, "Cannot create a transaction with zero gift"),
            BuildError::InsufficientFunds => write!(f, "Insufficient funds to pay fee and gift"),
            BuildError::AccountingMismatch => {
                write!(f, "Assets in must equal gift + fee + refund")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LockPrimitive, LockTim, Name, NoteData, Pkh, Version};
    use alloc::{string::ToString, vec};
    use bip39::Mnemonic;
    use nbx_crypto::derive_master_key;

    #[test]
    fn test_vector() {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let private_key = derive_master_key(&mnemonic.to_seed(""))
            .private_key
            .unwrap();

        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".into(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".into(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };

        let recipient = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".into();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".into();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let tx = TxBuilder::new_simple(
            vec![note.clone()],
            spend_condition.clone(),
            recipient,
            gift,
            fee,
            refund_pkh,
            true,
        )
        .unwrap()
        .sign(&private_key)
        .unwrap();

        assert_eq!(tx.id.to_string(), "3j4vkn72mcpVtQrTgNnYyoF3rDuYax3aebT5axu3Qe16jm9x2wLtepW");

        let tx = TxBuilder::new_simple(
            vec![note],
            spend_condition,
            recipient,
            gift,
            fee,
            refund_pkh,
            false,
        )
        .unwrap()
        .sign(&private_key)
        .unwrap();

        assert_eq!(tx.id.to_string(), "AXiVtrHSXTDpK3RdpevVfkDmyheS5NnPsaYRf8uGZWP9JXfVVCzLpVH");
    }
}
