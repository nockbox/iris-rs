use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use nbx_crypto::PrivateKey;
use nbx_ztd::{noun_deserialize, noun_serialize, Digest, Hashable as HashableTrait, Noun};
use serde::{Deserialize, Serialize};

use super::note::Note;
use super::tx::{Seed, Seeds, Spend, SpendCondition, Spends, Witness};
use super::{Name, NoteData, Version};
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SpendBuilder {
    note: Note,
    #[serde(
        serialize_with = "noun_serialize",
        deserialize_with = "noun_deserialize"
    )]
    spend: Spend,
    #[serde(
        serialize_with = "noun_serialize",
        deserialize_with = "noun_deserialize"
    )]
    spend_condition: SpendCondition,
    #[serde(
        serialize_with = "noun_serialize",
        deserialize_with = "noun_deserialize"
    )]
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

    pub fn from_spend(
        spend: Spend,
        note: Note,
        spend_condition: SpendCondition,
        refund_lock: Option<SpendCondition>,
    ) -> Option<Self> {
        if spend.witness.lock_merkle_proof.proof.root != spend_condition.hash() {
            return None;
        }

        Some(Self {
            note,
            spend,
            spend_condition,
            refund_lock,
        })
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
                let seed = self.build_seed(rl, refund, include_lock_data);
                // NOTE: by convention, the refund seed is always first
                self.spend.seeds.0.insert(0, seed);
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
        let spend_sum: Nicks = self.spend.seeds.0.iter().map(|v| v.gift).sum();
        self.note.assets == spend_sum + self.spend.fee
    }

    pub fn build_seed(&self, lock: SpendCondition, gift: Nicks, include_lock_data: bool) -> Seed {
        let lock_root = lock.hash();
        let mut note_data = NoteData::empty();
        if include_lock_data {
            note_data.push_lock(lock);
        }
        let parent_hash = self.note.hash();
        Seed {
            output_source: None,
            lock_root,
            note_data,
            gift,
            parent_hash,
        }
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
                for (pkh, _, _) in &self.spend.witness.pkh_signature.0 {
                    valid_pkh.insert(*pkh);
                    if !checked_pkh.contains(pkh) && p.hashes.contains(pkh) {
                        checked_pkh.insert(*pkh);
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

    fn unclamped_fee(&self, fee_per_word: Nicks) -> Nicks {
        let mut fee = self.spend.unclamped_fee(fee_per_word);

        for mu in self.missing_unlocks() {
            match mu {
                MissingUnlocks::Pkh { num_sigs, .. } => {
                    // Heuristic for missing signatures. It is perhaps 30, but perhaps not.
                    fee += 35 * num_sigs * fee_per_word;
                }
                // TODO: handle hax
                _ => (),
            }
        }

        fee
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxBuilder {
    spends: BTreeMap<Name, SpendBuilder>,
    fee_pool: Vec<SpendBuilder>,
    fee_per_word: Nicks,
}

impl TxBuilder {
    /// Create an empty TxBuilder
    pub fn new(fee_per_word: Nicks) -> Self {
        Self {
            spends: BTreeMap::new(),
            fee_pool: vec![],
            fee_per_word,
        }
    }

    pub fn from_tx(
        tx: RawTx,
        mut notes: BTreeMap<Name, (Note, SpendCondition)>,
    ) -> Result<Self, BuildError> {
        if tx.version != Version::V1 {
            return Err(BuildError::InvalidVersion);
        }

        Ok(Self {
            spends: tx
                .spends
                .0
                .into_iter()
                .map(|(n, s)| {
                    let (note, sc) = notes
                        .remove(&n)
                        .ok_or_else(|| BuildError::NoteNotFound(n.clone()))?;
                    Ok((
                        n,
                        SpendBuilder::from_spend(s, note, sc, None)
                            .ok_or(BuildError::InvalidSpendCondition)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
            fee_pool: vec![],
            fee_per_word: 1 << 15,
        })
    }

    /// Append a `SpendBuilder` to this transaction
    pub fn spend(&mut self, spend: SpendBuilder) -> Option<SpendBuilder> {
        let name = spend.note.name.clone();
        self.spends.insert(name, spend)
    }

    pub fn simple_spend_base(
        &mut self,
        notes: Vec<(Note, SpendCondition)>,
        recipient: Digest,
        gift: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
    ) -> Result<&mut Self, BuildError> {
        if gift == 0 {
            return Err(BuildError::ZeroGift);
        }

        let refund_lock = SpendCondition::new_pkh(Pkh::single(refund_pkh));

        let mut remaining_gift = gift;

        for (note, spend_condition) in notes {
            let gift_portion = remaining_gift.min(note.assets);

            remaining_gift -= gift_portion;

            let mut spend = SpendBuilder::new(note, spend_condition, Some(refund_lock.clone()));
            if gift_portion > 0 {
                let seed = spend.build_seed(
                    SpendCondition::new_pkh(Pkh::single(recipient)),
                    gift_portion,
                    include_lock_data,
                );
                spend.seed(seed);
                spend.compute_refund(include_lock_data);
                assert!(spend.is_balanced());
                self.spend(spend);
            } else {
                spend.compute_refund(include_lock_data);
                assert!(spend.is_balanced());
                self.fee_pool.push(spend);
            }
        }

        if remaining_gift > 0 {
            return Err(BuildError::InsufficientFunds);
        }

        Ok(self)
    }

    pub fn simple_spend(
        &mut self,
        notes: Vec<(Note, SpendCondition)>,
        recipient: Digest,
        gift: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
    ) -> Result<&mut Self, BuildError> {
        self.simple_spend_base(notes, recipient, gift, refund_pkh, include_lock_data)?
            .recalc_and_set_fee(include_lock_data)?;

        Ok(self)
    }

    pub fn add_preimage(&mut self, preimage: Noun) -> Option<Digest> {
        let mut ret = None;
        for (_, s) in self.spends.iter_mut() {
            let r = s.add_preimage(preimage.clone());
            if r.is_some() {
                ret = r;
            }
        }
        ret
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

    pub fn all_notes(&self) -> BTreeMap<Name, (Note, SpendCondition)> {
        self.spends
            .iter()
            .map(|(a, b)| (a.clone(), (b.note.clone(), b.spend_condition.clone())))
            .collect()
    }

    pub fn cur_fee(&self) -> Nicks {
        self.spends.values().map(|v| v.spend.fee).sum::<Nicks>()
    }

    pub fn calc_fee(&self) -> Nicks {
        let mut fee = 0;

        for s in self.spends.values() {
            fee += s.unclamped_fee(self.fee_per_word);
        }

        fee.max(Spend::MIN_FEE)
    }

    pub fn recalc_and_set_fee(&mut self, include_lock_data: bool) -> Result<&mut Self, BuildError> {
        let fee = self.calc_fee();
        self.set_fee_and_balance_refund(fee, true, include_lock_data)
    }

    pub fn set_fee_and_balance_refund(
        &mut self,
        fee: Nicks,
        adjust_fee: bool,
        include_lock_data: bool,
    ) -> Result<&mut Self, BuildError> {
        let cur_fee = self.cur_fee();

        let mut spends = self.spends.values_mut().collect::<Vec<_>>();

        if cur_fee == fee {
            return Ok(self);
        } else if cur_fee < fee {
            let mut fee_left = fee - cur_fee;

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
                    let words = rs.note_data_words();
                    let sub_refund = rs.gift.min(fee_left);
                    if sub_refund > 0 {
                        let cur_fee = s.spend.fee;
                        s.fee(cur_fee + sub_refund);
                        fee_left -= sub_refund;
                        s.compute_refund(include_lock_data);

                        // Eliminate refund seed words, if the refund is now gone.
                        if adjust_fee && s.cur_refund().is_none() {
                            fee_left -= fee_left.min(words * self.fee_per_word);
                        }
                    }
                }
            }

            // Pop entries from the fee pool, so that we can cover any excess fees. These shall be
            // sorted by assets.
            self.fee_pool.sort_by_key(|v| v.note.assets);
            while fee_left > 0 {
                let Some(mut r) = self.fee_pool.pop() else {
                    break;
                };
                r.compute_refund(include_lock_data);
                let rs = r.cur_refund().expect("Fee pool entry must have refund");
                if adjust_fee {
                    fee_left += r.unclamped_fee(self.fee_per_word);
                }
                let sub_refund = rs.gift.min(fee_left);
                if sub_refund > 0 {
                    let cur_fee = r.spend.fee;
                    r.fee(cur_fee + sub_refund);
                    fee_left -= sub_refund;
                    r.compute_refund(include_lock_data);
                }
                self.spend(r);
            }

            if fee_left > 0 {
                return Err(BuildError::InsufficientFunds);
            } else {
                Ok(self)
            }
        } else {
            let mut refund_left = cur_fee - fee;

            // Sort by smallest fee, so that we can return as many low-fee notes to fee pool as
            // possible.
            spends.sort_by(|a, b| {
                let anra = a.note.assets - a.cur_refund().map(|v| v.gift).unwrap_or(0);
                let bnra = b.note.assets - b.cur_refund().map(|v| v.gift).unwrap_or(0);
                let aor = a.spend.seeds.0.len() == 1 && a.cur_refund().is_some();
                let bor = b.spend.seeds.0.len() == 1 && b.cur_refund().is_some();
                if aor != bor {
                    // By default, pick a note that only has refund, as adjusting fee here does not
                    // change the fee.
                    bor.cmp(&aor)
                } else if a.spend.fee != b.spend.fee {
                    // If both are like that, or neither, put the lowest fee first
                    a.spend.fee.cmp(&b.spend.fee)
                } else if b.spend.fee != a.spend.fee {
                    // If equal, prioritize lowest assets
                    anra.cmp(&bnra)
                } else {
                    // Otherwise, sort by name
                    b.note.name.cmp(&a.note.name)
                }
            });

            let mut return_to_pool = vec![];

            for s in spends {
                if s.refund_lock.is_some() {
                    let add_refund = s.spend.fee.min(refund_left);

                    if add_refund > 0 {
                        let cur_fee = s.spend.fee;
                        s.fee(cur_fee - add_refund);
                        refund_left -= add_refund;
                        s.compute_refund(include_lock_data);
                    }

                    if s.spend.fee == add_refund {
                        return_to_pool.push(s.note.name.clone());
                        // We are returning this note to pool (making it unused), all its required
                        // fee shall disappear. The only case we don't handle here is whenever we
                        // reach the MIN_FEE (256 nicks). Hence, TODO: handle MIN_FEE case. This is
                        // irrelevant for the current consensus version with high fees.
                        refund_left =
                            refund_left.saturating_sub(s.unclamped_fee(self.fee_per_word));
                    }
                }
            }

            // Take all notes that we are meant to return to fee pool, and return there.
            for note in return_to_pool {
                let sp = self.spends.remove(&note).unwrap();
                self.fee_pool.push(sp);
            }

            if refund_left > 0 {
                return Err(BuildError::AccountingMismatch);
            } else {
                Ok(self)
            }
        }
    }
}

#[derive(Debug)]
pub enum BuildError {
    ZeroGift,
    InsufficientFunds,
    AccountingMismatch,
    NoteNotFound(Name),
    InvalidFee(Nicks, Nicks),
    InvalidVersion,
    InvalidSpendCondition,
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
            BuildError::NoteNotFound(name) => write!(
                f,
                "Unable to find note [{} {}]",
                name.first.to_string(),
                name.last.to_string()
            ),
            BuildError::InvalidFee(expected, got) => {
                write!(
                    f,
                    "Insufficient fee for transaction (needed: {expected}, got: {got})"
                )
            }
            BuildError::InvalidVersion => write!(f, "Invalid RawTx version"),
            BuildError::InvalidSpendCondition => {
                write!(f, "Spend condition is invalid (mismatch?)")
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
    use nbx_ztd::{jam, NounEncode};

    #[test]
    fn test_builder() {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let private_key = derive_master_key(&mnemonic.to_seed(""))
            .private_key
            .unwrap();

        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".try_into().unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".try_into().unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };

        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME".try_into().unwrap();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".try_into().unwrap();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let tx = TxBuilder::new(1)
            .simple_spend_base(
                vec![(note.clone(), spend_condition.clone())],
                recipient,
                gift,
                refund_pkh,
                true,
            )
            .unwrap()
            .set_fee_and_balance_refund(fee, false, true)
            .unwrap()
            .sign(&private_key)
            .validate()
            .unwrap()
            .build();

        assert_eq!(
            tx.id.to_string(),
            "3pmkA1knKhJzmd28t5TULP9DADK7GhWsHaNSTpPcGcN4nxzrWsDK2xe",
        );

        let mut tx = TxBuilder::new(1 << 17);

        tx.simple_spend_base(
            vec![(note.clone(), spend_condition.clone())],
            recipient,
            gift,
            refund_pkh,
            true,
        )
        .unwrap()
        .set_fee_and_balance_refund(fee, false, true)
        .unwrap()
        .sign(&private_key);

        assert!(tx.validate().is_err());

        let fee_per_word = 40000;
        let mut builder = TxBuilder::new(fee_per_word);

        builder
            .simple_spend(
                vec![(note, spend_condition)],
                recipient,
                gift,
                refund_pkh,
                false,
            )
            .unwrap();

        let fee1 = builder.calc_fee();

        let tx = builder.sign(&private_key).build();

        assert_eq!(tx.spends.fee(fee_per_word), 2520000);
        assert_eq!(fee1, 2520000);
    }

    #[test]
    fn test_fee_calcs_up() {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let private_key = derive_master_key(&mnemonic.to_seed(""))
            .private_key
            .unwrap();

        let notes = [
            Note {
                version: Version::V1,
                origin_page: 13,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".try_into().unwrap(),
                    "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".try_into().unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 3000,
            },
            Note {
                version: Version::V1,
                origin_page: 14,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".try_into().unwrap(),
                    "6yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".try_into().unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 3000,
            },
            Note {
                version: Version::V1,
                origin_page: 15,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".try_into().unwrap(),
                    "5yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".try_into().unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 3000,
            },
        ];

        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME".try_into().unwrap();
        let gift = 2700;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".try_into().unwrap();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let notes = notes
            .into_iter()
            .map(|v| (v, spend_condition.clone()))
            .collect::<Vec<_>>();
        let mut builder = TxBuilder::new(8);

        builder
            .simple_spend_base(notes, recipient, gift, refund_pkh, false)
            .unwrap();

        // By default, fee is just 504, because we are using one note, and one note only.
        assert_eq!(builder.calc_fee(), 504);

        // Since fee pool exists, we will automatically pick a note from it to set the fee appropriately.
        builder.recalc_and_set_fee(false).unwrap();
        assert_eq!(
            builder.calc_fee(),
            992,
            "{} {:?}",
            builder.fee_pool.len(),
            builder.spends
        );
        assert_eq!(builder.cur_fee(), 992);

        // Calling this twice should not make the fee jump back and forth.
        builder.recalc_and_set_fee(false).unwrap();
        assert_eq!(
            builder.calc_fee(),
            992,
            "{} {:?}",
            builder.fee_pool.len(),
            builder.spends
        );
        assert_eq!(builder.cur_fee(), 992);

        // After signing, the fee shouldn't change.
        builder.sign(&private_key);
        assert_eq!(builder.calc_fee(), 992);
        assert_eq!(builder.cur_fee(), 992);

        // And the transaction should validate.
        builder.validate().unwrap();
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

    #[test]
    fn test_jam_vector() {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let private_key = derive_master_key(&mnemonic.to_seed(""))
            .private_key
            .unwrap();
        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH".try_into().unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM".try_into().unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };
        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME".try_into().unwrap();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX".try_into().unwrap();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let tx = TxBuilder::new(1)
            .simple_spend_base(
                vec![(note.clone(), spend_condition.clone())],
                recipient,
                gift,
                refund_pkh,
                true,
            )
            .unwrap()
            .set_fee_and_balance_refund(fee, false, true)
            .unwrap()
            .sign(&private_key)
            .validate()
            .unwrap()
            .build();
        assert_eq!(
            tx.id.to_string(),
            "3pmkA1knKhJzmd28t5TULP9DADK7GhWsHaNSTpPcGcN4nxzrWsDK2xe",
        );

        let mut jam_vec = jam((&tx.id.to_string(), &tx.spends).to_noun());
        jam_vec.reverse();
        assert_eq!(
            bs58::encode(jam_vec).into_string(),
            "We2QrLoo6X48Y58ZPCBKuv1oy859epNaxa9CNvstysytqWhtNxzuViSDShA7VFXevc62rNDcGqLiaggx5gswVJ5SSE9JKwMNZeMiyacmWGNtj1jk287RAvybG7BZ6MiwwZDBaTQgXxvvRmJBseKFnz8Rt3SQbU4zkPNkfbt4n9ZNHGTfqPhYiUhPwcf5PRG7pEbtAUZf7HXpfWPQffBcvMKuJdErUEytq27p2kjqzeqqbReCiRDGmfe6DF8JnVvo6ePiyrhscA1tdaH1P6jUphxeFnHAMUEd4E5WhHHx2YceQciw5NxnCkbUbauz4HEj7ioaZtWX3MfXfebLuiVf75eFNJa2wKtgrEfcevy6LT2XWDXGJPk59D8xUaSjPzNwwGwj1tvqxYQt9G3BBZvVDpS1aRvWRdjd1NmakevKfGCwaAyVpGJsvacgJxa1918ab5EWj4ZSXKZsar2oWohPN1Fi4EAFuL5MFFeJdtmtbBTEE8qGmJZ56XTeByszhhmPfbJY8XXqEigNVNxX2US5mtv6MyeFvhCXcQGGcENYcFUv4tHDwrx3Hf7GUXqKsjpR53dbGG54T7gmQ9NEAiFFwRoVRiCfBNajDCCixEQqVa4BLtfmPmZEtfSS9Q9qpMAFiXTYdErFg5GxW6Qb7aXh5XCAq3aW67fqCs3Q6x6SL2si9zFDXsX9QAyjYqXYAjYVCrV4UYfRdmiB3jsJBRacAmbqj2KjAzwKHaJNtr4vmwKuTave2vFFE46yxG3yRUxm9oZGBD2oBLsfTasV2xj3ZoxPvdPjy2sutsQVboXVvS91ux8umyJQ6TdcNnWyKqa4r2fkAhDGMe3Kb2Ag7b8VemsAiR5ijcQyj2q5qHMUUTKYXA7jzDh8WnQDtFg3z3ehVtdZLS8uh4RyubmSoeDDxMVYh9yqMBca5dRb5QPQtmRw7cYoZxRigNqaRCJdbM1VxJAHQkVpmSvuHi3NucJbZRzB8VbWsmAWx57WC96MLtQDNiB1a",
        );
    }
}
