//! Transaction building objects, mirroring `iris-wasm` `tx.rs`.
//!
//! `PrivateKey`, `TxBuilder` and `SpendBuilder` are stateful handles (uniffi
//! objects). Complex parameters/returns cross as JSON strings with the same
//! serde shapes as the wasm tsify boundary.

use std::sync::Mutex;

use iris_crypto::cheetah::PrivateKey as CryptoPrivateKey;
use iris_nockchain_types::{
    builder::TxBuilder as CoreTxBuilder,
    note::Note,
    tx::RawTx,
    v1::{Lock, LockRoot, NockchainTx, SeedV1},
    Nicks, SpendBuilder as CoreSpendBuilder, TxEngineSettings,
};
use iris_ztd::U256;
use serde::Deserialize;

use crate::{crypto_stack::run_on_crypto_stack, digest_from_str, from_json, to_json, FfiError, Result};

fn nicks_from_str(s: &str) -> Result<Nicks> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| FfiError::msg(format!("invalid Nicks '{s}': {e}")))
}

fn nicks_to_string(n: &Nicks) -> String {
    // Nicks serializes as a decimal string (serde_u64_as_string)
    serde_json::to_value(n)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Mirror of wasm `TxLock` (untagged: null/None or { lock, lock_sp_index }).
#[derive(Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // mirrors iris-wasm's TxLock exactly
enum TxLock {
    None,
    Some { lock: Lock, lock_sp_index: usize },
}

impl TxLock {
    fn into_tuple(self) -> Option<(Lock, usize)> {
        match self {
            TxLock::None => None,
            TxLock::Some {
                lock,
                lock_sp_index,
            } => Some((lock, lock_sp_index)),
        }
    }
}

// ---------------------------------------------------------------------------
// PrivateKey (wasm: `PrivateKey`)
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct FfiPrivateKey {
    signing_key: CryptoPrivateKey,
    public_key_bytes: Vec<u8>,
}

#[uniffi::export]
impl FfiPrivateKey {
    /// wasm: `PrivateKey.fromBytes(bytes)` / `new PrivateKey(bytes)`
    #[uniffi::constructor]
    pub fn from_bytes(signing_key_bytes: Vec<u8>) -> Result<Self> {
        if signing_key_bytes.len() != 32 {
            return Err(FfiError::msg("Private key must be 32 bytes"));
        }
        run_on_crypto_stack("iris-private-key-from-bytes", move || {
            let signing_key = CryptoPrivateKey(U256::from_be_slice(&signing_key_bytes));
            let public_key_bytes = signing_key.public_key().to_be_bytes().to_vec();
            Self {
                signing_key,
                public_key_bytes,
            }
        })
    }

    /// wasm: `privateKey.publicKey` getter
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }

    /// wasm: `privateKey.backendKind()`
    pub fn backend_kind(&self) -> String {
        "bytes".to_string()
    }
}

// ---------------------------------------------------------------------------
// TxBuilder (wasm: `TxBuilder`)
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct FfiTxBuilder {
    builder: Mutex<CoreTxBuilder>,
}

#[uniffi::export]
impl FfiTxBuilder {
    /// wasm: `new TxBuilder(settings)`
    #[uniffi::constructor]
    pub fn new(settings_json: String) -> Result<Self> {
        let settings: TxEngineSettings = from_json(&settings_json)?;
        Ok(Self {
            builder: Mutex::new(CoreTxBuilder::new(settings)),
        })
    }

    /// wasm: `TxBuilder.fromRawTx(tx, settings)`
    #[uniffi::constructor]
    pub fn from_raw_tx(raw_tx_json: String, settings_json: String) -> Result<Self> {
        let tx: RawTx = from_json(&raw_tx_json)?;
        let settings: TxEngineSettings = from_json(&settings_json)?;
        let builder =
            CoreTxBuilder::from_raw_tx(tx, settings).map_err(|e| FfiError::msg(e.to_string()))?;
        Ok(Self {
            builder: Mutex::new(builder),
        })
    }

    /// wasm: `TxBuilder.fromNockchainTx(tx, settings)`
    #[uniffi::constructor]
    pub fn from_nockchain_tx(nockchain_tx_json: String, settings_json: String) -> Result<Self> {
        let tx: NockchainTx = from_json(&nockchain_tx_json)?;
        let settings: TxEngineSettings = from_json(&settings_json)?;
        let builder = CoreTxBuilder::from_nockchain_tx(tx, settings)
            .map_err(|e| FfiError::msg(e.to_string()))?;
        Ok(Self {
            builder: Mutex::new(builder),
        })
    }

    /// wasm: `txBuilder.simpleSpend(notes, locks, recipient, gift, feeOverride, refundPkh, includeLockData)`
    #[allow(clippy::too_many_arguments)]
    pub fn simple_spend(
        &self,
        notes_json: String,
        locks_json: String,
        recipient: String,
        gift: String,
        fee_override: Option<String>,
        refund_pkh: String,
        include_lock_data: bool,
    ) -> Result<()> {
        let notes: Vec<Note> = from_json(&notes_json)?;
        let locks: Vec<TxLock> = from_json(&locks_json)?;
        if notes.len() != locks.len() {
            return Err(FfiError::msg("notes and locks must have the same length"));
        }
        let recipient = digest_from_str(&recipient)?;
        let gift = nicks_from_str(&gift)?;
        let refund_pkh = digest_from_str(&refund_pkh)?;
        let fee_override = fee_override.map(|f| nicks_from_str(&f)).transpose()?;

        let internal_notes: Vec<(Note, Option<(Lock, usize)>)> = notes
            .into_iter()
            .zip(locks)
            .map(|(n, lck)| (n, lck.into_tuple()))
            .collect();

        run_on_crypto_stack("iris-tx-simple-spend", || {
            let mut builder = self.builder.lock().unwrap();
            builder
                .simple_spend_base(
                    internal_notes,
                    recipient,
                    gift,
                    refund_pkh,
                    include_lock_data,
                )
                .map_err(|e| FfiError::msg(format!("{e}")))?;

            if let Some(fee) = fee_override {
                builder.set_fee_and_balance_refund(fee, false, include_lock_data)
            } else {
                builder.recalc_and_set_fee(include_lock_data)
            }
            .map_err(|e| FfiError::msg(format!("{e}")))?;

            Ok::<(), FfiError>(())
        })?
    }

    /// wasm: `txBuilder.setFeeAndBalanceRefund(fee, adjustFee, includeLockData)`
    pub fn set_fee_and_balance_refund(
        &self,
        fee: String,
        adjust_fee: bool,
        include_lock_data: bool,
    ) -> Result<()> {
        let fee = nicks_from_str(&fee)?;
        self.builder
            .lock()
            .unwrap()
            .set_fee_and_balance_refund(fee, adjust_fee, include_lock_data)
            .map_err(|e| FfiError::msg(e.to_string()))?;
        Ok(())
    }

    /// wasm: `txBuilder.recalcAndSetFee(includeLockData)`
    pub fn recalc_and_set_fee(&self, include_lock_data: bool) -> Result<()> {
        run_on_crypto_stack("iris-tx-recalc-fee", || {
            self.builder
                .lock()
                .unwrap()
                .recalc_and_set_fee(include_lock_data)
                .map_err(|e| FfiError::msg(e.to_string()))?;
            Ok::<(), FfiError>(())
        })?
    }

    /// wasm: `txBuilder.addPreimage(preimageJam)` -> Digest | undefined
    pub fn add_preimage(&self, preimage_jam: Vec<u8>) -> Result<Option<String>> {
        let preimage = iris_ztd::cue(&preimage_jam)
            .ok_or_else(|| FfiError::msg("Unable to cue preimage jam"))?;
        Ok(self
            .builder
            .lock()
            .unwrap()
            .add_preimage(preimage)
            .map(|d| d.to_string()))
    }

    /// wasm: `txBuilder.sign(privateKey)`
    pub fn sign(&self, signing_key: &FfiPrivateKey) -> Result<()> {
        run_on_crypto_stack("iris-tx-sign", || {
            self.builder.lock().unwrap().sign(&signing_key.signing_key);
        })
    }

    /// wasm: `txBuilder.validate()`
    pub fn validate(&self) -> Result<()> {
        run_on_crypto_stack("iris-tx-validate", || {
            self.builder
                .lock()
                .unwrap()
                .validate()
                .map_err(|e| FfiError::msg(e.to_string()))?;
            Ok::<(), FfiError>(())
        })?
    }

    /// wasm: `txBuilder.curFee()` -> Nicks (decimal string)
    pub fn cur_fee(&self) -> String {
        nicks_to_string(&self.builder.lock().unwrap().cur_fee())
    }

    /// wasm: `txBuilder.calcFee()` -> Nicks (decimal string)
    pub fn calc_fee(&self) -> String {
        nicks_to_string(&self.builder.lock().unwrap().calc_fee())
    }

    /// wasm: `txBuilder.build()` -> NockchainTx JSON
    pub fn build(&self) -> Result<String> {
        run_on_crypto_stack("iris-tx-build", || {
            to_json(&self.builder.lock().unwrap().build())
        })?
    }
}

// ---------------------------------------------------------------------------
// SpendBuilder (wasm: `SpendBuilder`)
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct FfiSpendBuilder {
    builder: Mutex<CoreSpendBuilder>,
}

#[uniffi::export]
impl FfiSpendBuilder {
    /// wasm: `new SpendBuilder(note, lock?, lockSpIndex?, refundLock?)`
    #[uniffi::constructor]
    pub fn new(
        note_json: String,
        lock_json: Option<String>,
        lock_sp_index: Option<u64>,
        refund_lock_json: Option<String>,
    ) -> Result<Self> {
        let note: Note = from_json(&note_json)?;
        let lock: Option<Lock> = lock_json.map(|l| from_json(&l)).transpose()?;
        let refund_lock: Option<LockRoot> = refund_lock_json.map(|l| from_json(&l)).transpose()?;
        let builder = CoreSpendBuilder::new(
            note,
            lock.zip(lock_sp_index.map(|i| i as usize)),
            refund_lock,
        )
        .map_err(|e| FfiError::msg(e.to_string()))?;
        Ok(Self {
            builder: Mutex::new(builder),
        })
    }

    /// wasm: `spendBuilder.fee(nicks)`
    pub fn fee(&self, fee: String) -> Result<()> {
        self.builder.lock().unwrap().fee(nicks_from_str(&fee)?);
        Ok(())
    }

    /// wasm: `spendBuilder.computeRefund(includeLockData)`
    pub fn compute_refund(&self, include_lock_data: bool) {
        self.builder
            .lock()
            .unwrap()
            .compute_refund(include_lock_data);
    }

    /// wasm: `spendBuilder.curRefund()` -> SeedV1 JSON | undefined
    pub fn cur_refund(&self) -> Result<Option<String>> {
        match self.builder.lock().unwrap().cur_refund() {
            Some(seed) => Ok(Some(to_json(seed)?)),
            None => Ok(None),
        }
    }

    /// wasm: `spendBuilder.isBalanced()`
    pub fn is_balanced(&self) -> bool {
        self.builder.lock().unwrap().is_balanced()
    }

    /// wasm: `spendBuilder.seed(seed)`
    pub fn seed(&self, seed_json: String) -> Result<()> {
        let seed: SeedV1 = from_json(&seed_json)?;
        self.builder.lock().unwrap().seed(seed);
        Ok(())
    }

    /// wasm: `spendBuilder.invalidateSigs()`
    pub fn invalidate_sigs(&self) {
        self.builder.lock().unwrap().invalidate_sigs();
    }

    /// wasm: `spendBuilder.missingUnlocks()` -> MissingUnlocks[] JSON
    pub fn missing_unlocks(&self) -> Result<String> {
        to_json(&self.builder.lock().unwrap().missing_unlocks())
    }

    /// wasm: `spendBuilder.addPreimage(preimageJam)` -> Digest | undefined
    pub fn add_preimage(&self, preimage_jam: Vec<u8>) -> Result<Option<String>> {
        let preimage = iris_ztd::cue(&preimage_jam)
            .ok_or_else(|| FfiError::msg("Unable to cue preimage jam"))?;
        Ok(self
            .builder
            .lock()
            .unwrap()
            .add_preimage(preimage)
            .map(|d| d.to_string()))
    }

    /// wasm: `spendBuilder.sign(privateKey)` -> bool
    pub fn sign(&self, signing_key: &FfiPrivateKey) -> bool {
        run_on_crypto_stack("iris-spend-sign", || {
            self.builder.lock().unwrap().sign(&signing_key.signing_key)
        })
        .unwrap_or(false)
    }
}

// Note: wasm `txBuilder.spend(spendBuilder)` and `allSpends()` move
// SpendBuilder values between handles; deferred to the UBRN integration pass
// where object-passing conventions are settled (tracked in iris-ffi README).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_public_key, tx_engine_settings_v1_default};

    #[test]
    fn private_key_round_trip() {
        let key_bytes =
            hex::decode("362b4073814e43f427983a83f11efcceb6741082c18f0d64b7e47340ba4485ba")
                .unwrap();
        let key = FfiPrivateKey::from_bytes(key_bytes).unwrap();
        assert_eq!(key.backend_kind(), "bytes");
        assert_eq!(
            hash_public_key(key.public_key()).unwrap(),
            "AyzPiJoqcqmdZdjxZ9aGLnVsbYcCphidHERKBWVXyKhNqTirshTmicG"
        );
    }

    #[test]
    fn tx_builder_constructs_with_default_settings() {
        let settings = tx_engine_settings_v1_default().unwrap();
        let builder = FfiTxBuilder::new(settings).unwrap();
        // An empty builder reports a fee (min fee floor applies on calc)
        let _ = builder.cur_fee();
        let built = builder.build().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&built).unwrap();
        assert!(parsed.is_object() || parsed.is_array());
    }

    #[test]
    fn tx_builder_rejects_invalid_settings() {
        assert!(FfiTxBuilder::new("not json".into()).is_err());
    }
}
