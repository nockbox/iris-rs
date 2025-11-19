use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use nbx_crypto::PrivateKey;
use nbx_ztd::{Digest, Hashable as HashableTrait, Noun};

use super::note::Note;
use super::tx::{Seed, Seeds, Spend, SpendCondition, Spends, Witness};
use super::{Name, NoteData};
use crate::{Nicks, Pkh, RawTx};

#[derive(Clone, Debug)]
pub enum MissingUnlocks {
    Pkh {
        num_sigs: u64,
        sig_of: BTreeSet<Digest>,
    },
    Hax {
        preimages_for: BTreeSet<Digest>,
    },
    Brn,
}

#[derive(Clone, Debug)]
struct SpendBuilder {
    note: Note,
    spend: Spend,
    spend_condition: SpendCondition,
    refund_lock: Option<SpendCondition>,
}

impl SpendBuilder {
    pub fn new(
        note: Note,
        spend_condition: SpendCondition,
        refund_lock: Option<SpendCondition>,
    ) -> Self {
        Self {
            note,
            spend: Spend::new(
                Witness::new(spend_condition.clone()),
                Seeds(Default::default()),
                0,
            ),
            spend_condition,
            refund_lock,
        }
    }

    pub fn fee(&mut self, fee_portion: Nicks) -> &mut Self {
        if self.spend.fee != fee_portion {
            self.invalidate_sigs();
        }
        self.spend.fee = fee_portion;
        self
    }

    pub fn compute_refund(&mut self, include_lock_data: bool) -> &mut Self {
        if self.refund_lock.is_some() {
            self.invalidate_sigs();
            let rl = self.refund_lock.clone().unwrap();
            let lock_root = rl.hash();
            // Remove the previous refund
            self.spend.seeds.0.retain(|v| v.lock_root != lock_root);
            let refund = self.note.assets
                - self.spend.fee
                - self.spend.seeds.0.iter().map(|v| v.gift).sum::<u64>();
            if refund > 0 {
                self.build_seed(rl, refund, include_lock_data);
            }
        }
        self
    }

    pub fn cur_refund(&self) -> Option<&Seed> {
        let rl = self.refund_lock.as_ref()?;
        let lock_root = rl.hash();
        self.spend.seeds.0.iter().find(|v| v.lock_root == lock_root)
    }

    pub fn is_balanced(&self) -> bool {
        self.note
            .assets
            .wrapping_sub(self.spend.fee)
            .wrapping_sub(self.spend.seeds.0.iter().map(|v| v.gift).sum::<u64>())
            == 0
    }

    pub fn build_seed(
        &mut self,
        lock: SpendCondition,
        gift: Nicks,
        include_lock_data: bool,
    ) -> &mut Self {
        let lock_root = lock.hash();
        let mut note_data = NoteData::empty();
        if include_lock_data {
            note_data.push_lock(lock);
        }
        let parent_hash = self.note.hash();
        self.seed(Seed {
            lock_root,
            note_data,
            gift,
            parent_hash,
        })
    }

    pub fn seed(&mut self, seed: Seed) -> &mut Self {
        self.invalidate_sigs();
        self.spend.seeds.0.push(seed);
        self
    }

    pub fn invalidate_sigs(&mut self) -> &mut Self {
        self.spend.witness.pkh_signature.0.clear();
        self
    }

    pub fn missing_unlocks(&self) -> Vec<MissingUnlocks> {
        let mut missing_unlocks = vec![];

        for p in self.spend_condition.pkh() {
            let mut checked_pkh = BTreeSet::new();
            let mut valid_pkh = BTreeSet::new();

            if p.m > 0 {
                for (pk, _) in &self.spend.witness.pkh_signature.0 {
                    let pkh = pk.hash();
                    valid_pkh.insert(pkh);
                    if !checked_pkh.contains(&pkh) && p.hashes.contains(&pkh) {
                        checked_pkh.insert(pkh);
                        if checked_pkh.len() as u64 >= p.m {
                            break;
                        }
                    }
                }
            }

            if (checked_pkh.len() as u64) < p.m {
                let sig_of = &valid_pkh ^ &checked_pkh;
                missing_unlocks.push(MissingUnlocks::Pkh {
                    num_sigs: p.m - checked_pkh.len() as u64,
                    sig_of,
                })
            }
        }

        for h in self.spend_condition.hax() {
            let valid_hax = h.0.iter().cloned().collect::<BTreeSet<_>>();

            let current_hax = self
                .spend
                .witness
                .hax_map
                .clone()
                .into_iter()
                .map(|v| v.0)
                .collect::<BTreeSet<_>>();

            let checked_hax = &current_hax & &valid_hax;

            let preimages_for = &valid_hax ^ &checked_hax;
            if !preimages_for.is_empty() {
                missing_unlocks.push(MissingUnlocks::Hax { preimages_for });
            }
        }

        if self.spend_condition.brn() {
            missing_unlocks.push(MissingUnlocks::Brn);
        }

        missing_unlocks
    }

    pub fn add_preimage(&mut self, preimage: Noun) -> Option<Digest> {
        let digest = preimage.hash();

        for h in self.spend_condition.hax() {
            if h.0.contains(&digest) {
                self.spend.witness.hax_map.insert(digest, preimage);
                return Some(digest);
            }
        }

        None
    }

    pub fn sign(&mut self, signing_key: &PrivateKey) -> bool {
        let pkpkh = signing_key.public_key().hash();

        for p in self.spend_condition.pkh() {
            if p.hashes.contains(&pkpkh) {
                self.spend.add_signature(
                    signing_key.public_key(),
                    signing_key.sign(&self.spend.sig_hash()),
                );
                return true;
            }
        }

        false
    }
}

pub struct TxBuilder {
    spends: BTreeMap<Name, SpendBuilder>,
    fee_per_word: Nicks,
}

impl TxBuilder {
    pub fn new(fee_per_word: Nicks) -> Self {
        Self {
            spends: BTreeMap::new(),
            fee_per_word,
        }
    }

    pub fn spend(&mut self, spend: SpendBuilder) -> Option<SpendBuilder> {
        let name = spend.note.name.clone();
        self.spends.insert(name, spend)
    }

    pub fn new_simple_base(
        notes: Vec<(Note, SpendCondition)>,
        recipient: Digest,
        gift: Nicks,
        fee_per_word: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
    ) -> Result<Self, BuildError> {
        if gift == 0 {
            return Err(BuildError::ZeroGift);
        }

        let refund_lock = SpendCondition::new_pkh(Pkh::single(refund_pkh));
        let mut builder = TxBuilder::new(fee_per_word);

        let mut remaining_gift = gift;

        for (note, spend_condition) in notes {
            let gift_portion = remaining_gift.min(note.assets);

            remaining_gift -= gift_portion;

            let mut spend = SpendBuilder::new(note, spend_condition, Some(refund_lock.clone()));
            if gift_portion > 0 {
                spend.build_seed(
                    SpendCondition::new_pkh(Pkh::single(recipient)),
                    gift_portion,
                    include_lock_data,
                );
            }
            spend.compute_refund(include_lock_data);
            assert!(spend.is_balanced());

            builder.spend(spend);
        }

        if remaining_gift > 0 {
            return Err(BuildError::InsufficientFunds);
        }

        Ok(builder)
    }

    pub fn new_simple(
        notes: Vec<(Note, SpendCondition)>,
        recipient: Digest,
        gift: Nicks,
        fee_per_word: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
    ) -> Result<Self, BuildError> {
        let mut builder = Self::new_simple_base(
            notes,
            recipient,
            gift,
            fee_per_word,
            refund_pkh,
            include_lock_data,
        )?;
        builder
            .subtract_fee_from_refund(include_lock_data)?
            .remove_unused_notes();
        Ok(builder)
    }

    pub fn add_preimage(&mut self, note: &Note, preimage: Noun) -> Option<Digest> {
        let s = self.spends.get_mut(&note.name)?;
        s.add_preimage(preimage)
    }

    pub fn sign(&mut self, signing_key: &PrivateKey) -> &mut Self {
        for spend in self.spends.values_mut() {
            spend.sign(signing_key);
        }
        self
    }

    pub fn validate(&mut self) -> Result<&mut Self, BuildError> {
        let cur_fee = self.cur_fee();
        let needed_fee = self.calc_fee();
        if cur_fee < needed_fee {
            return Err(BuildError::InvalidFee(needed_fee, cur_fee));
        }

        if self.spends.values().any(|v| !v.is_balanced()) {
            return Err(BuildError::UnbalancedSpends);
        }

        let unlocks = self
            .spends
            .values()
            .flat_map(|v| v.missing_unlocks())
            .collect::<Vec<_>>();
        if !unlocks.is_empty() {
            return Err(BuildError::MissingUnlocks(unlocks));
        }

        Ok(self)
    }

    pub fn build(&self) -> RawTx {
        RawTx::new(Spends(
            self.spends
                .iter()
                .map(|(a, b)| (a.clone(), b.spend.clone()))
                .collect(),
        ))
    }

    pub fn cur_fee(&self) -> Nicks {
        self.spends.values().map(|v| v.spend.fee).sum::<Nicks>()
    }

    pub fn calc_fee(&self) -> Nicks {
        let mut fee =
            Spend::fee_for_many(self.spends.values().map(|v| &v.spend), self.fee_per_word);

        for s in self.spends.values() {
            for mu in s.missing_unlocks() {
                match mu {
                    MissingUnlocks::Pkh { num_sigs, .. } => {
                        // Heuristic for missing signatures. It is perhaps 30, but perhaps not.
                        fee += 30 * num_sigs * self.fee_per_word;
                    }
                    // TODO: handle hax
                    _ => (),
                }
            }
        }

        fee
    }

    pub fn remove_unused_notes(&mut self) -> &mut Self {
        self.spends.retain(|_, v| {
            !v.is_balanced() || v.cur_refund().map(|v| v.gift) != Some(v.note.assets)
        });
        self
    }

    pub fn subtract_fee_from_refund(
        &mut self,
        include_lock_data: bool,
    ) -> Result<&mut Self, BuildError> {
        let fee = self.calc_fee();
        self.set_fee_and_balance_refund(fee, include_lock_data)
    }

    pub fn set_fee_and_balance_refund(
        &mut self,
        fee: Nicks,
        include_lock_data: bool,
    ) -> Result<&mut Self, BuildError> {
        let cur_fee = self.cur_fee();

        // TODO: if cur_fee > fee, reset fee to 0
        if cur_fee >= fee {
            return Ok(self);
        }

        let mut fee_left = fee - cur_fee;

        let mut spends = self.spends.values_mut().collect::<Vec<_>>();
        // Sort by non-refund assets, so that we prioritize refunds from used-up notes
        spends.sort_by(|a, b| {
            let anra = a.note.assets - a.cur_refund().map(|v| v.gift).unwrap_or(0);
            let bnra = b.note.assets - b.cur_refund().map(|v| v.gift).unwrap_or(0);
            if anra != bnra {
                // By default, put the greatest non-refund transfers first
                bnra.cmp(&anra)
            } else if b.spend.fee != a.spend.fee {
                // If equal, prioritize highest fee
                b.spend.fee.cmp(&a.spend.fee)
            } else {
                // Otherwise, sort by name
                b.note.name.cmp(&a.note.name)
            }
        });

        for s in spends {
            if let Some(rs) = s.cur_refund() {
                let sub_refund = rs.gift.min(fee_left);
                if sub_refund > 0 {
                    let cur_fee = s.spend.fee;
                    s.fee(cur_fee + sub_refund);
                    fee_left -= sub_refund;
                    s.compute_refund(include_lock_data);
                }
            }
        }

        if fee_left > 0 {
            return Err(BuildError::InsufficientFunds);
        } else {
            Ok(self)
        }
    }
}

#[derive(Debug)]
pub enum BuildError {
    ZeroGift,
    InsufficientFunds,
    AccountingMismatch,
    InvalidFee(Nicks, Nicks),
    UnbalancedSpends,
    MissingUnlocks(Vec<MissingUnlocks>),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BuildError::ZeroGift => write!(f, "Cannot create a transaction with zero gift"),
            BuildError::InsufficientFunds => write!(f, "Insufficient funds to pay fee and gift"),
            BuildError::AccountingMismatch => {
                write!(f, "Assets in must equal gift + fee + refund")
            }
            BuildError::InvalidFee(expected, got) => {
                write!(
                    f,
                    "Insufficient fee for transaction (needed: {expected}, got: {got})"
                )
            }
            BuildError::UnbalancedSpends => write!(
                f,
                "Some spends are not balanced (forgot to compute refunds?)"
            ),
            BuildError::MissingUnlocks(unlocks) => {
                write!(
                    f,
                    "The note is note fully unlocked. The following unlocks are missing:"
                )?;
                for u in unlocks {
                    write!(f, "{u:?}")?;
                }
                Ok(())
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
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqY".into();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let tx = TxBuilder::new_simple_base(
            vec![(note.clone(), spend_condition.clone())],
            recipient,
            gift,
            1,
            refund_pkh,
            true,
        )
        .unwrap()
        .set_fee_and_balance_refund(fee, true)
        .unwrap()
        .sign(&private_key)
        .validate()
        .unwrap()
        .build();

        assert_eq!(
            tx.id.to_string(),
            "87UEseTQfzPb1GDdqEpbBRvAWXxfnzHauMpFyxYhWuc1R4zJQFNKh8D",
            "{tx:?}"
        );

        let mut tx = TxBuilder::new_simple_base(
            vec![(note.clone(), spend_condition.clone())],
            recipient,
            gift,
            1 << 17,
            refund_pkh,
            true,
        )
        .unwrap();

        tx.set_fee_and_balance_refund(fee, true)
            .unwrap()
            .sign(&private_key);

        assert!(tx.validate().is_err());

        let fee_per_word = 40000;
        let mut builder = TxBuilder::new_simple(
            vec![(note, spend_condition)],
            recipient,
            gift,
            fee_per_word,
            refund_pkh,
            false,
        )
        .unwrap();

        let fee1 = builder.calc_fee();

        let tx = builder.sign(&private_key).build();

        assert_eq!(tx.spends.fee(fee_per_word), 2320000);
        assert_eq!(fee1, 2320000);
    }

    #[test]
    fn test_first_name() {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let public_key = derive_master_key(&mnemonic.to_seed("")).public_key;

        let sc = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(public_key.hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        assert_eq!(
            sc.first_name().to_string(),
            "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH",
        )
    }
}
