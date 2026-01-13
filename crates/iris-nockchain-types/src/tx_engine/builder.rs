use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use iris_crypto::PrivateKey;
use iris_ztd::{noun_deserialize, noun_serialize, Digest, Hashable as HashableTrait, Noun, ZSet};
use serde::{Deserialize, Serialize};

use super::note::Note;
use super::tx::{
    LockRoot, NockchainTx, Seed, Seeds, Spend, SpendCondition, Spends, TransactionDisplay, Witness,
};
use super::{Name, NoteData, Version};
use crate::{Nicks, Pkh, RawTx};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
            let lock_root = LockRoot::Lock(rl.clone());
            // If the previous refund seed had memo note-data, preserve it across refund
            // recomputation (fee changes rebuild the refund seed).
            let preserved_memo: Option<Noun> = self
                .spend
                .seeds
                .0
                .iter()
                .find(|v| v.lock_root.hash() == lock_root.hash())
                .and_then(|seed| {
                    seed.note_data
                        .entries
                        .iter()
                        .find(|e| e.key == crate::MEMO_KEY)
                        .map(|e| e.val.clone())
                });

            // Remove the previous refund.
            self.spend
                .seeds
                .0
                .retain(|v| v.lock_root.hash() != lock_root.hash());
            let refund = self.note.assets
                - self.spend.fee
                - self.spend.seeds.0.iter().map(|v| v.gift).sum::<u64>();
            if refund > 0 {
                let mut seed = self.build_seed(rl, refund, include_lock_data);
                if let Some(memo) = preserved_memo {
                    seed.note_data.push_memo(memo);
                }
                // NOTE: by convention, the refund seed is always first
                self.spend.seeds.0.insert(0, seed);
            }
        }
        self
    }

    pub fn cur_refund(&self) -> Option<&Seed> {
        let rl = self.refund_lock.as_ref()?;
        let lock_root = LockRoot::Lock(rl.clone());
        self.spend
            .seeds
            .0
            .iter()
            .find(|v| v.lock_root.hash() == lock_root.hash())
    }

    pub fn is_balanced(&self) -> bool {
        let spend_sum: Nicks = self.spend.seeds.0.iter().map(|v| v.gift).sum();
        self.note.assets == spend_sum + self.spend.fee
    }

    pub fn build_seed(&self, lock: SpendCondition, gift: Nicks, include_lock_data: bool) -> Seed {
        let lock_root = LockRoot::Lock(lock.clone());
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
            let valid_pkh = p.hashes.iter().cloned().collect::<BTreeSet<_>>();

            if p.m > 0 {
                for (pkh, _, _) in &self.spend.witness.pkh_signature.0 {
                    if !checked_pkh.contains(pkh) && valid_pkh.contains(pkh) {
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
            #[allow(clippy::single_match)]
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
        memo: Option<Noun>,
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

        if let Some(memo) = memo {
            self.apply_memo_to_last_seed_of_best_lock(memo);
        }

        Ok(self)
    }

    // Match CLI/hoon behavior: memo note-data must be on the *last* seed of the lock-root
    // that has the highest total gift. This is because tx engine preserves note-data from the
    // last seed for each lock-root during merge.
    fn apply_memo_to_last_seed_of_best_lock(&mut self, memo: Noun) {
        let mut totals: BTreeMap<Digest, Nicks> = BTreeMap::new();
        for (_, spend) in self.spends.iter() {
            for seed in spend.spend.seeds.0.iter() {
                *totals.entry(seed.lock_root.hash()).or_default() += seed.gift;
            }
        }

        let mut best_lock: Option<Digest> = None;
        let mut best_total: Nicks = 0;
        for (lock, total) in totals {
            if best_lock.is_none() || total > best_total {
                best_lock = Some(lock);
                best_total = total;
            }
        }
        let Some(best_lock) = best_lock else {
            return;
        };

        // IMPORTANT:
        // Outputs pick note-data from the *last seed in the tap order of the z-set* of seeds for
        // a given lock-root (see `RawTx::outputs`). That ordering is NOT the same as the builder's
        // insertion order, and adding memo changes the seed hash (and thus its z-set position).
        //
        // To match CLI/hoon behavior robustly, we choose a seed within the best lock-root such
        // that, *after memo is applied to that seed only*, it becomes the last seed in the z-set
        // iteration order for that lock-root.
        fn seed_has_memo(seed: &Seed) -> bool {
            seed.note_data
                .entries
                .iter()
                .any(|e| e.key == crate::MEMO_KEY)
        }

        // Collect all seeds for this lock-root in the exact order they will be inserted into the
        // z-set during output computation (spends order, then seeds vector order).
        let mut seeds_for_lock: Vec<(Name, usize, Seed)> = Vec::new();
        for (name, spend) in self.spends.iter() {
            for (i, seed) in spend.spend.seeds.0.iter().enumerate() {
                if seed.lock_root.hash() == best_lock {
                    seeds_for_lock.push((name.clone(), i, seed.clone()));
                }
            }
        }
        if seeds_for_lock.is_empty() {
            return;
        }

        let mut chosen: Option<(Name, usize)> = None;
        for (cand_name, cand_idx, _) in seeds_for_lock.iter() {
            let mut set: ZSet<Seed> = ZSet::new();
            for (name, idx, seed) in seeds_for_lock.iter() {
                let mut s = seed.clone();
                if name == cand_name && idx == cand_idx {
                    s.note_data.push_memo(memo.clone());
                }
                set.insert(s);
            }
            let ordered: Vec<Seed> = set.into_iter().collect();
            if ordered.last().is_some_and(seed_has_memo) {
                chosen = Some((cand_name.clone(), *cand_idx));
            }
        }

        let Some((name, idx)) = chosen else {
            // Should not happen, but if it does, fail gracefully by doing nothing.
            return;
        };
        if let Some(spend) = self.spends.get_mut(&name) {
            if let Some(seed) = spend.spend.seeds.0.get_mut(idx) {
                seed.note_data.push_memo(memo);
            }
        }
    }

    pub fn simple_spend(
        &mut self,
        notes: Vec<(Note, SpendCondition)>,
        recipient: Digest,
        gift: Nicks,
        refund_pkh: Digest,
        include_lock_data: bool,
        memo: Option<Noun>,
    ) -> Result<&mut Self, BuildError> {
        self.simple_spend_base(notes, recipient, gift, refund_pkh, include_lock_data, memo)?
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

    pub fn build(&self) -> NockchainTx {
        let mut display = TransactionDisplay::default();
        let mut spends = Spends(Vec::new());

        for (name, spend) in &self.spends {
            display
                .inputs
                .insert(name.clone(), spend.spend_condition.clone());
            for seed in spend.spend.seeds.0.iter() {
                if let LockRoot::Lock(lock) = &seed.lock_root {
                    display.outputs.insert(lock.hash(), lock.clone().into());
                }
            }
            spends.0.push((name.clone(), spend.spend.clone()));
        }

        let version = Version::V1;
        let id = (&version, &spends).hash();
        let (spends, witness_data) = spends.split_witness();

        NockchainTx {
            version,
            id,
            spends,
            display,
            witness_data,
        }
    }

    pub fn all_notes(&self) -> BTreeMap<Name, (Note, SpendCondition)> {
        self.spends
            .iter()
            .map(|(a, b)| (a.clone(), (b.note.clone(), b.spend_condition.clone())))
            .collect()
    }

    pub fn all_spends(&self) -> &BTreeMap<Name, SpendBuilder> {
        &self.spends
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
            Ok(self)
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
                Err(BuildError::InsufficientFunds)
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
                } else if anra != bnra {
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
                Err(BuildError::AccountingMismatch)
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
            BuildError::NoteNotFound(name) => {
                write!(f, "Unable to find note [{} {}]", name.first, name.last)
            }
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
                    "The note is not fully unlocked. The following unlocks are missing:"
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
    use iris_crypto::{derive_master_key, PublicKey};
    use iris_ztd::{jam, NounEncode};

    fn keys() -> (PrivateKey, PublicKey) {
        let mnemonic = Mnemonic::parse("dice domain inspire horse time initial monitor nature mass impose tone benefit vibrant dash kiss mosquito rice then color ribbon agent method drop fat").unwrap();
        let ek = derive_master_key(&mnemonic.to_seed(""));
        (ek.private_key.unwrap(), ek.public_key)
    }

    #[test]
    fn test_builder() {
        let (private_key, _) = keys();

        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                    .try_into()
                    .unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };

        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX"
            .try_into()
            .unwrap();
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
                None,
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
            None,
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
                None,
            )
            .unwrap();

        let fee1 = builder.calc_fee();

        let tx = builder.sign(&private_key).build();

        assert_eq!(tx.to_raw_tx().spends.fee(fee_per_word), 2520000);
        assert_eq!(fee1, 2520000);
    }

    #[test]
    fn test_fee_calcs_up() {
        let (private_key, _) = keys();

        let notes = [
            Note {
                version: Version::V1,
                origin_page: 13,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                        .try_into()
                        .unwrap(),
                    "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                        .try_into()
                        .unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 3000,
            },
            Note {
                version: Version::V1,
                origin_page: 14,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                        .try_into()
                        .unwrap(),
                    "6yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                        .try_into()
                        .unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 3000,
            },
            Note {
                version: Version::V1,
                origin_page: 15,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                        .try_into()
                        .unwrap(),
                    "5yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                        .try_into()
                        .unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 3000,
            },
        ];

        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let gift = 2700;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX"
            .try_into()
            .unwrap();
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
            .simple_spend_base(notes, recipient, gift, refund_pkh, false, None)
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
    fn test_memo_increases_fee() {
        let (private_key, _) = keys();
        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                    .try_into()
                    .unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 10_000,
        };
        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let gift = 2_000;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX"
            .try_into()
            .unwrap();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let notes = vec![(note.clone(), spend_condition.clone())];
        let fee_per_word = 1 << 10;

        let mut builder_without_memo = TxBuilder::new(fee_per_word);
        builder_without_memo
            .simple_spend_base(
                notes.clone(),
                recipient,
                gift,
                refund_pkh,
                /* include_lock_data */ false,
                None,
            )
            .unwrap();
        let base_fee = builder_without_memo.calc_fee();

        let memo = 7u64.to_noun();
        let mut builder_with_memo = TxBuilder::new(fee_per_word);
        builder_with_memo
            .simple_spend_base(
                notes,
                recipient,
                gift,
                refund_pkh,
                /* include_lock_data */ false,
                Some(memo),
            )
            .unwrap();
        let memo_fee = builder_with_memo.calc_fee();

        assert!(memo_fee > base_fee);
    }

    fn seed_has_memo(seed: &Seed) -> bool {
        seed.note_data
            .entries
            .iter()
            .any(|e| e.key == crate::MEMO_KEY)
    }

    #[test]
    fn test_memo_applied_to_last_seed_of_best_lock() {
        // This test targets the CLI/hoon rule:
        // - group all seeds by lock-root
        // - pick the lock-root with the highest total gift
        // - ensure memo is preserved by landing on the *last seed in z-set order* for that lock-root
        //
        // It also ensures we handle multiple spends, each with multiple seeds.

        let (private_key, public_key) = keys();

        let refund_pkh: Digest = public_key.hash();
        let refund_lock = SpendCondition::new_pkh(Pkh::single(refund_pkh));

        // Use three distinct recipient PKHs (lock-roots).
        let pkh_a: Digest = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let pkh_b: Digest = "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
            .try_into()
            .unwrap();
        let pkh_c: Digest = "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
            .try_into()
            .unwrap();

        let lock_a = SpendCondition::new_pkh(Pkh::single(pkh_a));
        let lock_b = SpendCondition::new_pkh(Pkh::single(pkh_b));
        let lock_c = SpendCondition::new_pkh(Pkh::single(pkh_c));

        // Total gifts by lock-root (across BOTH spends):
        // - A: 2 + 5 = 7
        // - B: 5 + 6 = 11  (best)
        // - C: 1 + 2 = 3
        let memo = 7u64.to_noun();

        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);

        // Spend 1: three seeds, ordered [A, B, C] so B is in the *middle* of the seeds array.
        let note1 = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                    .try_into()
                    .unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvD"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 8,
        };
        let mut spend1 =
            SpendBuilder::new(note1, spend_condition.clone(), Some(refund_lock.clone()));
        spend1.seed(spend1.build_seed(lock_a.clone(), 2, false)); // idx 0
        spend1.seed(spend1.build_seed(lock_b.clone(), 5, false)); // idx 1 (middle)  <-- candidate
        spend1.seed(spend1.build_seed(lock_c.clone(), 1, false)); // idx 2
        spend1.compute_refund(false);
        assert!(spend1.is_balanced());

        // Spend 2: three seeds, ordered [A, B, C] so B is again in the *middle* of the array.
        let note2 = Note {
            version: Version::V1,
            origin_page: 14,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                    .try_into()
                    .unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvA"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 13,
        };
        let mut spend2 = SpendBuilder::new(note2, spend_condition, Some(refund_lock));
        spend2.seed(spend2.build_seed(lock_a.clone(), 5, false)); // idx 0
        spend2.seed(spend2.build_seed(lock_b.clone(), 6, false)); // idx 1 (middle)  <-- candidate
        spend2.seed(spend2.build_seed(lock_c.clone(), 2, false)); // idx 2
        spend2.compute_refund(false);
        assert!(spend2.is_balanced());

        let mut builder = TxBuilder::new(1);
        builder.spend(spend1);
        builder.spend(spend2);

        // Apply memo using the same logic the CLI/hoon expects.
        builder.apply_memo_to_last_seed_of_best_lock(memo);

        let best_lock = lock_b.hash();

        // Memo must be applied to exactly one seed in the whole tx.
        let mut memo_seed_count = 0usize;
        let mut memo_seed_is_middle = false;
        for (_name, spend) in builder.spends.iter() {
            for (i, seed) in spend.spend.seeds.0.iter().enumerate() {
                if seed_has_memo(seed) {
                    memo_seed_count += 1;
                    memo_seed_is_middle = i == 1;
                }
            }
        }
        assert_eq!(
            memo_seed_count, 1,
            "memo must be applied to exactly one seed"
        );
        assert!(
            memo_seed_is_middle,
            "memo must be applied to a seed in the middle of its spend's seeds array (idx=1)"
        );

        // Memo must land on the last seed in z-set order for the best lock-root.
        let mut set: ZSet<Seed> = ZSet::new();
        for (_name, spend) in builder.spends.iter() {
            for seed in spend.spend.seeds.0.iter() {
                if seed.lock_root.hash() == best_lock {
                    set.insert(seed.clone());
                }
            }
        }
        let ordered: Vec<Seed> = set.into_iter().collect();
        assert!(
            ordered.last().is_some_and(seed_has_memo),
            "memo must end up on the last seed for the best lock-root in z-set order"
        );

        // And it must survive into outputs (only B output keeps memo).
        let outputs = builder.build().outputs();
        let out_a = outputs
            .iter()
            .find(|n| n.assets == 7)
            .expect("expected lock A output");
        let out_b = outputs
            .iter()
            .find(|n| n.assets == 11)
            .expect("expected lock B output");
        let out_c = outputs
            .iter()
            .find(|n| n.assets == 3)
            .expect("expected lock C output");

        assert!(!out_a
            .note_data
            .entries
            .iter()
            .any(|e| e.key == crate::MEMO_KEY));
        assert!(out_b
            .note_data
            .entries
            .iter()
            .any(|e| e.key == crate::MEMO_KEY));
        assert!(!out_c
            .note_data
            .entries
            .iter()
            .any(|e| e.key == crate::MEMO_KEY));
    }

    #[test]
    fn test_memo_survives_fee_recalc_and_refund_recompute() {
        // This test exercises the real wasm flow:
        // `simple_spend` calls `simple_spend_base` then `recalc_and_set_fee`, which recomputes
        // refunds (rebuilding the refund seed). If memo was placed onto the refund seed (because
        // refund lock-root is best), it must survive that rebuild.
        let (private_key, public_key) = keys();

        let note1 = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                    .try_into()
                    .unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 1_000_000,
        };

        let recipient: Digest = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let refund_pkh: Digest = public_key.hash();
        let gift: Nicks = 1_000;

        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);

        // Use a non-trivial fee_per_word so that `recalc_and_set_fee` adjusts fee/refund, but
        // keep it small enough that we have sufficient funds.
        let mut builder = TxBuilder::new(1 << 10);
        builder
            .simple_spend(
                vec![(note1, spend_condition)],
                recipient,
                gift,
                refund_pkh,
                /* include_lock_data */ false,
                Some(7u64.to_noun()),
            )
            .unwrap();

        // Refund output should be the best lock-root (it is much larger than gift).
        let outputs = builder.build().outputs();
        let out_recipient = outputs.iter().find(|n| n.assets == gift).unwrap();
        let out_refund = outputs.iter().find(|n| n.assets > gift).unwrap();

        assert!(
            out_refund
                .note_data
                .entries
                .iter()
                .any(|e| e.key == crate::MEMO_KEY),
            "memo should survive refund recomputation and land on refund output note-data"
        );
        assert!(
            !out_recipient
                .note_data
                .entries
                .iter()
                .any(|e| e.key == crate::MEMO_KEY),
            "memo should not be on recipient output for this case"
        );
    }

    #[test]
    fn test_first_name() {
        let (_, public_key) = keys();

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
    fn test_multiseed_outputs() {
        let (private_key, public_key) = keys();
        let notes = [
            Note {
                version: Version::V1,
                origin_page: 13,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                        .try_into()
                        .unwrap(),
                    "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                        .try_into()
                        .unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 4294967296,
            },
            Note {
                version: Version::V1,
                origin_page: 14,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                        .try_into()
                        .unwrap(),
                    "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvA"
                        .try_into()
                        .unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 4294967296,
            },
            Note {
                version: Version::V1,
                origin_page: 15,
                name: Name::new(
                    "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                        .try_into()
                        .unwrap(),
                    "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvD"
                        .try_into()
                        .unwrap(),
                ),
                note_data: NoteData::empty(),
                assets: 4294967296,
            },
        ];

        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let gift = 4294967296 * 3 - 65536 * 100;
        let refund_pkh = public_key.hash();

        let tx = TxBuilder::new(1 << 15)
            .simple_spend_base(
                notes
                    .into_iter()
                    .map(|note| {
                        (
                            note,
                            SpendCondition(vec![
                                LockPrimitive::Pkh(Pkh::single(public_key.hash())),
                                LockPrimitive::Tim(LockTim::coinbase()),
                            ]),
                        )
                    })
                    .collect(),
                recipient,
                gift,
                refund_pkh,
                false,
                None,
            )
            .unwrap()
            .recalc_and_set_fee(false)
            .unwrap()
            .sign(&private_key)
            .validate()
            .unwrap()
            .build();

        assert_eq!(
            tx.id.to_string(),
            "2AZCrc5hQiTBYvovYSjjWuYAmSbgNQtAtA252YNosdcrCNDycf4SZ9g",
        );

        let mut jam_vec = jam(tx.to_noun());
        jam_vec.reverse();
        assert_eq!(
            bs58::encode(jam_vec).into_string(),
            "3Rjw3yC2WJumTugHhn9TS8SB8n3h6gc2bCKvhgHArZCwW2zWhzXtFX9x7owmx5XJGX8pRZSAsrM8Cj9JKMANcJ6KJHhYA1BP557jThfKwDmEKe6JduSmRa5fmsE1MYNBjuFNPL7uFTH3iqpk1ACWpPHRaffKhct9Z9Dq1A1mqgu5WQ2MtVUNVqkbHnyKnd1AmWMDtcnhmfvWBRq6t6BhYDLFSdDFKgoQwqVi4bvjaY56XxWDPneU2w5WCWKf9JBJKhucSAEvPjk2BmDgkcmSuwskCkaoLW82eZfdQTWy4Gc22EHZrSjGaXJYnQYEkgWWzaSSQbRJuXGMPyFPN1CRHecKm2ktgj3qirkHZHN6qJasdVeX9itovLhmCHn13DSvHmRGoqAh2haX4SrJMusHL2Eg7pGGNHWQsrPCVZ82qRJ3svai4RSKKVA7Z3PvuMfpKkgeA8SVsYUryViaBULu9mgqa38QcbbtToPiZsvBq8zDAURVPMeXtVscarvQ6WrhA2ksqarjyWwqbzKhVzADd2Z3GA14xdFaVtDUxpg8trgkdqnG5rgjL5QDxtW7EuCT1VtuJS2yqbmYd52B9p9JUa4XwYrEuxPVoYy1pMUPuJ6zx5Y4VnqtasFYez727DKWbfwiareiQRGAG7MidnEucW3gB3bnEQRPDMZyUdTmH1UocnYBSWH5cBgtdifc3VgwbfFR2QYpUmjoRuB7uHgQkXQvw1hyH8jd8DJbr2gpz5FV4fD5dxntaHwajzqKHFGViHnzWQ23sB5UuMHenrZbLb2R6Z2XdXYFd8cmkFPuEYtQKCg1u2rvUnc1V3Quty2jtDyGkhpAuT485Atc2FonS2TRTzCwcRf9DDZHTMMwaW9368C6q1UoVkfY757RjcueKMMyT85LY2nKFeAk15ZxG5LgZHAnHMCjHsGpWT4n1gzjDAJqacW3Q1GszsmyU7XTx5BXXtWrHjHW5wQd7J9nr6QjFtAQf2dLDJHdqK8g66bExJ1iiRBVdTVHW12dVrvp4vsoyLhTLeyr5ADh2SEsX126xHTNKxuPWvLJ5oDSK4mhfKgLwKLxWzQqZnpSg5CUni4fvA7HRv9p7KXxBndwCEAZCuKjVWDGYYChoSzJcfmJ6h7SoEZtyye9xynGSLoTF4CkY2vRyED62LdiLU12YtxJBSXmLb5TuiBydpQC2yy4DFVeV97WaEwcB42FbrEYmYo36zSGjas5soTUg7hW2E8ES8gHxHH7QLkiiiarjBE9gwzhVCp6rnZt1kJUzFAaRbYdLyyKDbSDDfJjHX3jxrJMjQ84PZrR3yz5csndZroMW2NLYRQ5XX3pBTGn7BopMyDZY2WM3hhbism9rm4o3SEaUc7X9c96gr7KZpojPPTrgLxLSqnsKzefQeACbNXSXQqVQEtXFaFzrSeVatYiFXfJnmBXXr5W6ufVD57hcuXqC62sdBv2UntRXp9zDEYak8jhrnvgK4o5cGgRr2fS6Wk1g3Z8R3BKgZEzeowvVmn1RN6xbVh8XHBq83NELH2mm35oqiTCuoeJ6vcdVvF2Cy9dkdqcXfJBnPyhnLG",
        );

        let outputs = tx.outputs();
        let names = outputs
            .iter()
            .map(|output| (output.name.first.to_string(), output.name.last.to_string()))
            .collect::<Vec<_>>();
        assert_eq!(outputs[0].assets, 425984);
        assert_eq!(outputs[1].assets, 12878348288);
        assert_eq!(
            names[0],
            (
                "3k18JRFPMXUEnXJq9XRNrfX4Hz89YBY7RcxVzM3UQnUJQXAvbZ8Gwz4".to_string(),
                "6CpT2CXH2PuYzy5F17gbWWTSbPkZqBJmk8QhDtdbGvggucgWkA5HCiW".to_string()
            )
        );
        assert_eq!(
            names[1],
            (
                "CB1qjzHgZXRjV2827BffsuSeJV1WFbSfcpD48oBkWL7QKeBrq7ZrJvJ".to_string(),
                "97ieQ5D2FafHMx6L29f9EvY1aKdmb4Z27TfXA6MtViCncjizMVzTZ7d".to_string()
            )
        );
        // TODO: test note-data order
    }

    #[test]
    fn test_missing_unlock() {
        let (private_key, _) = keys();
        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                    .try_into()
                    .unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };
        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX"
            .try_into()
            .unwrap();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(private_key.public_key().hash())),
            LockPrimitive::Tim(LockTim::coinbase()),
        ]);
        let mut builder = TxBuilder::new(1);

        builder
            .simple_spend_base(
                vec![(note.clone(), spend_condition.clone())],
                recipient,
                gift,
                refund_pkh,
                true,
                None,
            )
            .unwrap()
            .set_fee_and_balance_refund(fee, false, true)
            .unwrap();

        let unlocks = builder
            .all_spends()
            .values()
            .flat_map(|v| v.missing_unlocks())
            .collect::<BTreeSet<_>>();
        assert_eq!(unlocks.len(), 1);
        assert_eq!(
            unlocks.first(),
            Some(&MissingUnlocks::Pkh {
                num_sigs: 1,
                sig_of: [private_key.public_key().hash()].into_iter().collect()
            })
        );
    }

    #[test]
    fn test_missing_unlock_hax() {
        use crate::Hax;
        use iris_ztd::Belt;
        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "4aAqswWFkNi6bey6Ac58QxsmMLV3VAC1LKnXwAaQvhYSZb6epr7aXap"
                    .try_into()
                    .unwrap(),
                "pnCZnNbZ1NGqeP2vSBBzQM3ecpjCoAnmFJH6Z6gGwpfjjBhNtddZqj"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };
        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX"
            .try_into()
            .unwrap();
        let spend_condition = SpendCondition(vec![
            LockPrimitive::Pkh(Pkh::single(
                "9zpwNfGdcPT1QUKw2Fnw2zvftzpAYEjzZfTqGW8KLnf3NmEJ7yR5t2Y"
                    .try_into()
                    .unwrap(),
            )),
            LockPrimitive::Hax(Hax(vec![Digest([
                Belt(1730770831742798981),
                Belt(2676322185709933211),
                Belt(8329210750824781744),
                Belt(16756092452590401876),
                Belt(3547445316740171466),
            ])])),
        ]);
        let mut builder = TxBuilder::new(1);

        builder
            .simple_spend_base(
                vec![(note.clone(), spend_condition.clone())],
                recipient,
                gift,
                refund_pkh,
                true,
                None,
            )
            .unwrap()
            .set_fee_and_balance_refund(fee, false, true)
            .unwrap();

        builder.add_preimage(0.to_noun());

        let unlocks = builder
            .all_spends()
            .values()
            .flat_map(|v| v.missing_unlocks())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            unlocks.into_iter().collect::<Vec<_>>(),
            vec![MissingUnlocks::Pkh {
                num_sigs: 1,
                sig_of: ["9zpwNfGdcPT1QUKw2Fnw2zvftzpAYEjzZfTqGW8KLnf3NmEJ7yR5t2Y"
                    .try_into()
                    .unwrap()]
                .into_iter()
                .collect()
            }]
        );
    }
    #[test]
    fn test_jam_vector() {
        let (private_key, _) = keys();
        let note = Note {
            version: Version::V1,
            origin_page: 13,
            name: Name::new(
                "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                    .try_into()
                    .unwrap(),
                "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                    .try_into()
                    .unwrap(),
            ),
            note_data: NoteData::empty(),
            assets: 4294967296,
        };
        let recipient = "2nEFkqYm51yfqsYgfRx72w8FF9bmWqnkJu8XqY8T7psXufjYNRxf5ME"
            .try_into()
            .unwrap();
        let gift = 1234567;
        let fee = 2850816;
        let refund_pkh = "6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX"
            .try_into()
            .unwrap();
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
                None,
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
            "3gBbvwuhALLvTWnLfgP3KVWz2qSWKsvLXHmFAKXfqYjiNiu1Xc32GguLGUTzfEFyWMCfWuxurCkmgUaXnWJEoWdX62tiTwmdXPhJzcEgDeoy99rmZyezkHK992jinuFNmDEDEvVd5vM19g7MRNRi5d3zWPtjCL2j9JyfT6mtTKgh9PNnWLY75A2JwzUDd6FSytomgVBeyqhjBWm7tMgkXngduhJGoZ6rS5MkyrzFhmtAYmtjVV9p4HnjDW6rrtgKXLEqUp3jpEdxXA4nHT8mtbSAxNvvQF5V4wmYddKDrzCPeWd8mccHUnsSxWLLRgEbYgUHvC6Wh5F5nKsEb6zvT9jGB9s9etXPYknTRBHmsDBWBveCmAzVy6Fa2x8iNuc15NPmQQwbbGZsmjGbVQKFT8vJz7HjcefhEZg9zbyq9BhQ3u6gY8vYqETL5u8wCvRb9bkNMkUEBcsNnkfmeXQcSdaYfTaExQFPpdLDkBPcG4bHTffXsgEwRxFpLXRWgzzM5ESBYZvKyEtk32tUodnsbQ9zun2mptmFq6zLW6kLhDwKBT6rR3ErddCE82p5qcUaC4ZLR3fiz59Hg14MQeYnBkAy7Cj3Z7WdqvfPoXhZZ2FCztn9SZXeLFxotFZNqeHp9PQu754PnCq1rUpgCUcnoQiWwyjEP7JbY6T9hLyA3m7T6b97DbEqD7iuDNwrhwbofKyyfPxFeZKap",
        );
    }
}
