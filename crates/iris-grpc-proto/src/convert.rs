use iris_nockchain_types::tx_engine::{v0, v1};
use iris_nockchain_types::v0::LegacySignature;
use iris_nockchain_types::v1::{
    Hax, LockMerkleProof, LockPrimitive, LockRoot, LockTim, MerkleProof, Pkh, PkhSignature, Seed,
    Seeds, Spend, Spend0, Spend1, SpendCondition, Witness,
};
use iris_nockchain_types::*;
use iris_ztd::{jam, Belt, Digest, Noun, U256};

use crate::common::{ConversionError, Required};
use crate::pb::common::v1::{
    BlockHeight as PbBlockHeight, Hash as PbHash, Name as PbName, Nicks as PbNicks,
    NoteVersion as PbNoteVersion, SchnorrSignature as PbSchnorrSignature,
    Signature as PbLegacySignature, SignatureEntry as PbSignatureEntry, Source as PbSource,
    TimeLockRangeAbsolute as PbTimeLockRangeAbsolute,
    TimeLockRangeRelative as PbTimeLockRangeRelative,
};
use crate::pb::common::v1::{
    Lock as PbLegacyLock, Note as PbNoteV0, SchnorrPubkey as PbSchnorrPubkey,
    TimeLockIntent as PbTimeLockIntent,
};
use crate::pb::common::v2::{
    lock_primitive, spend, Balance as PbBalance, BalanceEntry as PbBalanceEntry,
    BurnLock as PbBurnLock, HaxLock as PbHaxLock, HaxPreimage as PbHaxPreimage,
    LegacySpend as PbLegacySpend, LockMerkleProof as PbLockMerkleProof,
    LockPrimitive as PbLockPrimitive, LockTim as PbLockTim, MerkleProof as PbMerkleProof,
    Note as PbNote, NoteData as PbNoteData, NoteDataEntry as PbNoteDataEntry, NoteV1 as PbNoteV1,
    PkhLock as PbPkhLock, PkhSignature as PbPkhSignature, RawTransaction as PbRawTransaction,
    Seed as PbSeed, Spend as PbSpend, SpendCondition as PbSpendCondition,
    SpendEntry as PbSpendEntry, Witness as PbWitness, WitnessSpend as PbWitnessSpend,
};

// V0 protobuf types from v1/blockchain.proto
use crate::pb::common::v1::{
    Input as PbInputV0, NamedInput as PbNamedInputV0, RawTransaction as PbRawTransactionV0,
    Seed as PbSeedV0, Spend as PbSpendV0,
};

// =========================
// Primitive type conversions
// =========================

impl From<Belt> for crate::pb::common::v1::Belt {
    fn from(b: Belt) -> Self {
        crate::pb::common::v1::Belt { value: b.0 }
    }
}

impl From<crate::pb::common::v1::Belt> for Belt {
    fn from(b: crate::pb::common::v1::Belt) -> Self {
        Belt(b.value)
    }
}

impl<T: Into<Digest>> From<T> for PbHash {
    fn from(h: T) -> Self {
        let h = h.into();
        PbHash {
            belt_1: Some(crate::pb::common::v1::Belt::from(h.0[0])),
            belt_2: Some(crate::pb::common::v1::Belt::from(h.0[1])),
            belt_3: Some(crate::pb::common::v1::Belt::from(h.0[2])),
            belt_4: Some(crate::pb::common::v1::Belt::from(h.0[3])),
            belt_5: Some(crate::pb::common::v1::Belt::from(h.0[4])),
        }
    }
}

impl TryFrom<PbHash> for Digest {
    type Error = ConversionError;
    fn try_from(h: PbHash) -> Result<Self, Self::Error> {
        Ok(Digest([
            h.belt_1.required("Hash", "belt_1")?.into(),
            h.belt_2.required("Hash", "belt_2")?.into(),
            h.belt_3.required("Hash", "belt_3")?.into(),
            h.belt_4.required("Hash", "belt_4")?.into(),
            h.belt_5.required("Hash", "belt_5")?.into(),
        ]))
    }
}

impl TryFrom<PbHash> for LockRoot {
    type Error = ConversionError;
    fn try_from(h: PbHash) -> Result<Self, Self::Error> {
        Ok(LockRoot::Hash(TryFrom::try_from(h)?))
    }
}

impl From<Name> for PbName {
    fn from(name: Name) -> Self {
        PbName {
            first: Some(PbHash::from(name.first)),
            last: Some(PbHash::from(name.last)),
        }
    }
}

impl From<&Name> for PbName {
    fn from(name: &Name) -> Self {
        PbName {
            first: Some(PbHash::from(name.first)),
            last: Some(PbHash::from(name.last)),
        }
    }
}

impl TryFrom<PbName> for Name {
    type Error = ConversionError;
    fn try_from(name: PbName) -> Result<Self, Self::Error> {
        let first: Digest = name.first.required("Name", "first")?.try_into()?;
        let last: Digest = name.last.required("Name", "last")?.try_into()?;
        Ok(Name::new(first, last))
    }
}

impl From<Nicks> for PbNicks {
    fn from(n: Nicks) -> Self {
        PbNicks { value: n }
    }
}

impl From<PbNicks> for Nicks {
    fn from(n: PbNicks) -> Self {
        n.value
    }
}

impl From<Version> for PbNoteVersion {
    fn from(v: Version) -> Self {
        PbNoteVersion { value: v.into() }
    }
}

impl From<PbNoteVersion> for Version {
    fn from(v: PbNoteVersion) -> Self {
        Version::from(v.value)
    }
}

impl From<BlockHeight> for PbBlockHeight {
    fn from(h: BlockHeight) -> Self {
        PbBlockHeight { value: h }
    }
}

impl From<PbBlockHeight> for BlockHeight {
    fn from(h: PbBlockHeight) -> Self {
        h.value
    }
}

impl From<Source> for PbSource {
    fn from(source: Source) -> Self {
        PbSource {
            hash: Some(PbHash::from(source.hash)),
            coinbase: source.is_coinbase,
        }
    }
}

impl TryFrom<PbSource> for Source {
    type Error = ConversionError;
    fn try_from(source: PbSource) -> Result<Self, Self::Error> {
        Ok(Source {
            hash: source.hash.required("Source", "hash")?.try_into()?,
            is_coinbase: source.coinbase,
        })
    }
}

impl From<TimelockRange> for PbTimeLockRangeAbsolute {
    fn from(range: TimelockRange) -> Self {
        PbTimeLockRangeAbsolute {
            min: range.min.map(Into::into),
            max: range.max.map(Into::into),
        }
    }
}

impl From<PbTimeLockRangeAbsolute> for TimelockRange {
    fn from(range: PbTimeLockRangeAbsolute) -> Self {
        TimelockRange::new(range.min.map(|v| v.into()), range.max.map(|v| v.into()))
    }
}

impl From<TimelockRange> for PbTimeLockRangeRelative {
    fn from(range: TimelockRange) -> Self {
        // PbTimeLockRangeRelative expects BlockHeightDelta which is just a u64 wrapper
        PbTimeLockRangeRelative {
            min: range
                .min
                .map(|v| crate::pb::common::v1::BlockHeightDelta { value: v }),
            max: range
                .max
                .map(|v| crate::pb::common::v1::BlockHeightDelta { value: v }),
        }
    }
}

impl From<PbTimeLockRangeRelative> for TimelockRange {
    fn from(range: PbTimeLockRangeRelative) -> Self {
        TimelockRange::new(range.min.map(|v| v.value), range.max.map(|v| v.value))
    }
}

// =========================
// Transaction type conversions
// =========================

impl From<Seed> for PbSeed {
    fn from(seed: Seed) -> Self {
        PbSeed {
            output_source: None, // nbx types don't track output source
            lock_root: Some(PbHash::from(seed.lock_root)),
            note_data: Some(PbNoteData::from(seed.note_data)),
            gift: Some(PbNicks::from(seed.gift)),
            parent_hash: Some(PbHash::from(seed.parent_hash)),
        }
    }
}

// Helper function instead of From impl to avoid orphan rules
pub fn seeds_to_pb(seeds: Seeds) -> Vec<PbSeed> {
    seeds.0.into_iter().map(PbSeed::from).collect()
}

impl From<iris_nockchain_types::v1::NoteDataEntry> for PbNoteDataEntry {
    fn from(data: iris_nockchain_types::v1::NoteDataEntry) -> Self {
        Self {
            key: data.key,
            blob: jam(data.val),
        }
    }
}

impl From<iris_nockchain_types::v1::NoteData> for PbNoteData {
    fn from(data: iris_nockchain_types::v1::NoteData) -> Self {
        Self {
            entries: data.0.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<LockTim> for PbLockTim {
    fn from(tim: LockTim) -> Self {
        PbLockTim {
            rel: Some(PbTimeLockRangeRelative::from(tim.rel)),
            abs: Some(PbTimeLockRangeAbsolute::from(tim.abs)),
        }
    }
}

impl TryFrom<PbLockTim> for LockTim {
    type Error = ConversionError;
    fn try_from(tim: PbLockTim) -> Result<Self, Self::Error> {
        Ok(LockTim {
            rel: tim.rel.required("LockTim", "rel")?.into(),
            abs: tim.abs.required("LockTim", "abs")?.into(),
        })
    }
}

impl From<Pkh> for PbPkhLock {
    fn from(pkh: Pkh) -> Self {
        let mut hashes = pkh.hashes.into_iter().map(PbHash::from).collect::<Vec<_>>();
        hashes.dedup();
        PbPkhLock { m: pkh.m, hashes }
    }
}

impl From<LockPrimitive> for PbLockPrimitive {
    fn from(primitive: LockPrimitive) -> Self {
        let primitive = match primitive {
            LockPrimitive::Pkh(pkh) => lock_primitive::Primitive::Pkh(pkh.into()),
            LockPrimitive::Tim(tim) => lock_primitive::Primitive::Tim(tim.into()),
            LockPrimitive::Hax(hax) => {
                let mut hashes = hax.0.into_iter().map(PbHash::from).collect::<Vec<_>>();
                hashes.dedup();
                lock_primitive::Primitive::Hax(PbHaxLock { hashes })
            }
            LockPrimitive::Brn => lock_primitive::Primitive::Burn(PbBurnLock {}),
        };
        PbLockPrimitive {
            primitive: Some(primitive),
        }
    }
}

impl From<SpendCondition> for PbSpendCondition {
    fn from(condition: SpendCondition) -> Self {
        PbSpendCondition {
            primitives: condition.0.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MerkleProof> for PbMerkleProof {
    fn from(proof: MerkleProof) -> Self {
        PbMerkleProof {
            root: Some(PbHash::from(proof.root)),
            path: proof.path.into_iter().map(PbHash::from).collect(),
        }
    }
}

impl From<LockMerkleProof> for PbLockMerkleProof {
    fn from(proof: LockMerkleProof) -> Self {
        PbLockMerkleProof {
            spend_condition: Some(PbSpendCondition::from(proof.spend_condition)),
            axis: proof.axis,
            proof: Some(PbMerkleProof::from(proof.proof)),
        }
    }
}

impl From<PkhSignature> for PbPkhSignature {
    fn from(signature: PkhSignature) -> Self {
        use iris_ztd::Belt as ZBelt;

        PbPkhSignature {
            entries: signature
                .0
                .into_iter()
                .map(|(pkh, pubkey, sig)| {
                    // Convert UBig to Belt arrays for c and s
                    let c_bytes = sig.c.to_le_bytes();
                    let s_bytes = sig.s.to_le_bytes();
                    let c_belts = ZBelt::from_bytes(&c_bytes);
                    let s_belts = ZBelt::from_bytes(&s_bytes);

                    // Pad to 8 belts
                    let mut chal = [0u64; 8];
                    for (i, belt) in c_belts.iter().take(8).enumerate() {
                        chal[i] = belt.0;
                    }
                    let mut sig_val = [0u64; 8];
                    for (i, belt) in s_belts.iter().take(8).enumerate() {
                        sig_val[i] = belt.0;
                    }

                    crate::pb::common::v2::PkhSignatureEntry {
                        hash: Some(PbHash::from(pkh)),
                        pubkey: Some(crate::pb::common::v1::SchnorrPubkey {
                            value: Some(crate::pb::common::v1::CheetahPoint {
                                x: Some(crate::pb::common::v1::SixBelt {
                                    belt_1: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.x.0[0].0,
                                    }),
                                    belt_2: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.x.0[1].0,
                                    }),
                                    belt_3: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.x.0[2].0,
                                    }),
                                    belt_4: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.x.0[3].0,
                                    }),
                                    belt_5: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.x.0[4].0,
                                    }),
                                    belt_6: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.x.0[5].0,
                                    }),
                                }),
                                y: Some(crate::pb::common::v1::SixBelt {
                                    belt_1: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.y.0[0].0,
                                    }),
                                    belt_2: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.y.0[1].0,
                                    }),
                                    belt_3: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.y.0[2].0,
                                    }),
                                    belt_4: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.y.0[3].0,
                                    }),
                                    belt_5: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.y.0[4].0,
                                    }),
                                    belt_6: Some(crate::pb::common::v1::Belt {
                                        value: pubkey.0.y.0[5].0,
                                    }),
                                }),
                                inf: pubkey.0.inf,
                            }),
                        }),
                        signature: Some(crate::pb::common::v1::SchnorrSignature {
                            chal: Some(crate::pb::common::v1::EightBelt {
                                belt_1: Some(crate::pb::common::v1::Belt { value: chal[0] }),
                                belt_2: Some(crate::pb::common::v1::Belt { value: chal[1] }),
                                belt_3: Some(crate::pb::common::v1::Belt { value: chal[2] }),
                                belt_4: Some(crate::pb::common::v1::Belt { value: chal[3] }),
                                belt_5: Some(crate::pb::common::v1::Belt { value: chal[4] }),
                                belt_6: Some(crate::pb::common::v1::Belt { value: chal[5] }),
                                belt_7: Some(crate::pb::common::v1::Belt { value: chal[6] }),
                                belt_8: Some(crate::pb::common::v1::Belt { value: chal[7] }),
                            }),
                            sig: Some(crate::pb::common::v1::EightBelt {
                                belt_1: Some(crate::pb::common::v1::Belt { value: sig_val[0] }),
                                belt_2: Some(crate::pb::common::v1::Belt { value: sig_val[1] }),
                                belt_3: Some(crate::pb::common::v1::Belt { value: sig_val[2] }),
                                belt_4: Some(crate::pb::common::v1::Belt { value: sig_val[3] }),
                                belt_5: Some(crate::pb::common::v1::Belt { value: sig_val[4] }),
                                belt_6: Some(crate::pb::common::v1::Belt { value: sig_val[5] }),
                                belt_7: Some(crate::pb::common::v1::Belt { value: sig_val[6] }),
                                belt_8: Some(crate::pb::common::v1::Belt { value: sig_val[7] }),
                            }),
                        }),
                    }
                })
                .collect(),
        }
    }
}

impl TryFrom<PbPkhSignature> for PkhSignature {
    type Error = ConversionError;

    fn try_from(pb: PbPkhSignature) -> Result<Self, Self::Error> {
        use iris_crypto::{PublicKey, Signature};
        use iris_ztd::crypto::cheetah::{CheetahPoint, F6lt};
        use iris_ztd::{Belt as ZBelt, U256};

        let entries = pb
            .entries
            .into_iter()
            .map(|entry| {
                let pkh: Digest = entry
                    .hash
                    .required("PkhSignatureEntry", "hash")?
                    .try_into()?;

                let pubkey_pb = entry
                    .pubkey
                    .required("PkhSignatureEntry", "pubkey")?
                    .value
                    .required("SchnorrPubkey", "value")?;

                let x_pb = pubkey_pb.x.required("CheetahPoint", "x")?;
                let y_pb = pubkey_pb.y.required("CheetahPoint", "y")?;

                let pubkey = PublicKey(CheetahPoint {
                    x: F6lt([
                        ZBelt(x_pb.belt_1.required("SixBelt", "belt_1")?.value),
                        ZBelt(x_pb.belt_2.required("SixBelt", "belt_2")?.value),
                        ZBelt(x_pb.belt_3.required("SixBelt", "belt_3")?.value),
                        ZBelt(x_pb.belt_4.required("SixBelt", "belt_4")?.value),
                        ZBelt(x_pb.belt_5.required("SixBelt", "belt_5")?.value),
                        ZBelt(x_pb.belt_6.required("SixBelt", "belt_6")?.value),
                    ]),
                    y: F6lt([
                        ZBelt(y_pb.belt_1.required("SixBelt", "belt_1")?.value),
                        ZBelt(y_pb.belt_2.required("SixBelt", "belt_2")?.value),
                        ZBelt(y_pb.belt_3.required("SixBelt", "belt_3")?.value),
                        ZBelt(y_pb.belt_4.required("SixBelt", "belt_4")?.value),
                        ZBelt(y_pb.belt_5.required("SixBelt", "belt_5")?.value),
                        ZBelt(y_pb.belt_6.required("SixBelt", "belt_6")?.value),
                    ]),
                    inf: pubkey_pb.inf,
                });

                let sig_pb = entry.signature.required("PkhSignatureEntry", "signature")?;
                let chal_pb = sig_pb.chal.required("SchnorrSignature", "chal")?;
                let sig_val_pb = sig_pb.sig.required("SchnorrSignature", "sig")?;

                // Collect belt values into arrays
                let chal_belts = [
                    chal_pb.belt_1.required("EightBelt", "belt_1")?.value,
                    chal_pb.belt_2.required("EightBelt", "belt_2")?.value,
                    chal_pb.belt_3.required("EightBelt", "belt_3")?.value,
                    chal_pb.belt_4.required("EightBelt", "belt_4")?.value,
                    chal_pb.belt_5.required("EightBelt", "belt_5")?.value,
                    chal_pb.belt_6.required("EightBelt", "belt_6")?.value,
                    chal_pb.belt_7.required("EightBelt", "belt_7")?.value,
                    chal_pb.belt_8.required("EightBelt", "belt_8")?.value,
                ];
                let sig_belts = [
                    sig_val_pb.belt_1.required("EightBelt", "belt_1")?.value,
                    sig_val_pb.belt_2.required("EightBelt", "belt_2")?.value,
                    sig_val_pb.belt_3.required("EightBelt", "belt_3")?.value,
                    sig_val_pb.belt_4.required("EightBelt", "belt_4")?.value,
                    sig_val_pb.belt_5.required("EightBelt", "belt_5")?.value,
                    sig_val_pb.belt_6.required("EightBelt", "belt_6")?.value,
                    sig_val_pb.belt_7.required("EightBelt", "belt_7")?.value,
                    sig_val_pb.belt_8.required("EightBelt", "belt_8")?.value,
                ];

                // Convert belt arrays to U256
                let c_vec: Vec<ZBelt> = chal_belts.iter().map(|v| ZBelt(*v)).collect();
                let s_vec: Vec<ZBelt> = sig_belts.iter().map(|v| ZBelt(*v)).collect();

                let c = U256::from_le_slice(&ZBelt::to_bytes(&c_vec));
                let s = U256::from_le_slice(&ZBelt::to_bytes(&s_vec));

                let signature = Signature { c, s };

                Ok((pkh, pubkey, signature))
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;

        Ok(PkhSignature(entries))
    }
}

fn public_key_to_pb(pubkey: iris_crypto::PublicKey) -> PbSchnorrPubkey {
    PbSchnorrPubkey {
        value: Some(crate::pb::common::v1::CheetahPoint {
            x: Some(crate::pb::common::v1::SixBelt {
                belt_1: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.x.0[0].0,
                }),
                belt_2: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.x.0[1].0,
                }),
                belt_3: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.x.0[2].0,
                }),
                belt_4: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.x.0[3].0,
                }),
                belt_5: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.x.0[4].0,
                }),
                belt_6: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.x.0[5].0,
                }),
            }),
            y: Some(crate::pb::common::v1::SixBelt {
                belt_1: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.y.0[0].0,
                }),
                belt_2: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.y.0[1].0,
                }),
                belt_3: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.y.0[2].0,
                }),
                belt_4: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.y.0[3].0,
                }),
                belt_5: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.y.0[4].0,
                }),
                belt_6: Some(crate::pb::common::v1::Belt {
                    value: pubkey.0.y.0[5].0,
                }),
            }),
            inf: pubkey.0.inf,
        }),
    }
}

fn schnorr_sig_to_pb(sig: iris_crypto::Signature) -> PbSchnorrSignature {
    use iris_ztd::Belt as ZBelt;

    // Convert UBig to Belt arrays for c and s
    let c_bytes = sig.c.to_le_bytes();
    let s_bytes = sig.s.to_le_bytes();
    let c_belts = ZBelt::from_bytes(&c_bytes);
    let s_belts = ZBelt::from_bytes(&s_bytes);

    // Pad to 8 belts
    let mut chal = [0u64; 8];
    for (i, belt) in c_belts.iter().take(8).enumerate() {
        chal[i] = belt.0;
    }
    let mut sig_val = [0u64; 8];
    for (i, belt) in s_belts.iter().take(8).enumerate() {
        sig_val[i] = belt.0;
    }

    PbSchnorrSignature {
        chal: Some(crate::pb::common::v1::EightBelt {
            belt_1: Some(crate::pb::common::v1::Belt { value: chal[0] }),
            belt_2: Some(crate::pb::common::v1::Belt { value: chal[1] }),
            belt_3: Some(crate::pb::common::v1::Belt { value: chal[2] }),
            belt_4: Some(crate::pb::common::v1::Belt { value: chal[3] }),
            belt_5: Some(crate::pb::common::v1::Belt { value: chal[4] }),
            belt_6: Some(crate::pb::common::v1::Belt { value: chal[5] }),
            belt_7: Some(crate::pb::common::v1::Belt { value: chal[6] }),
            belt_8: Some(crate::pb::common::v1::Belt { value: chal[7] }),
        }),
        sig: Some(crate::pb::common::v1::EightBelt {
            belt_1: Some(crate::pb::common::v1::Belt { value: sig_val[0] }),
            belt_2: Some(crate::pb::common::v1::Belt { value: sig_val[1] }),
            belt_3: Some(crate::pb::common::v1::Belt { value: sig_val[2] }),
            belt_4: Some(crate::pb::common::v1::Belt { value: sig_val[3] }),
            belt_5: Some(crate::pb::common::v1::Belt { value: sig_val[4] }),
            belt_6: Some(crate::pb::common::v1::Belt { value: sig_val[5] }),
            belt_7: Some(crate::pb::common::v1::Belt { value: sig_val[6] }),
            belt_8: Some(crate::pb::common::v1::Belt { value: sig_val[7] }),
        }),
    }
}

fn pb_schnorr_pubkey_to_public_key(
    pb: PbSchnorrPubkey,
) -> Result<iris_crypto::PublicKey, ConversionError> {
    use iris_ztd::crypto::cheetah::{CheetahPoint, F6lt};
    use iris_ztd::Belt as ZBelt;

    let pt = pb.value.required("SchnorrPubkey", "value")?;
    let x_pb = pt.x.required("CheetahPoint", "x")?;
    let y_pb = pt.y.required("CheetahPoint", "y")?;

    Ok(iris_crypto::PublicKey(CheetahPoint {
        x: F6lt([
            ZBelt(x_pb.belt_1.required("SixBelt", "belt_1")?.value),
            ZBelt(x_pb.belt_2.required("SixBelt", "belt_2")?.value),
            ZBelt(x_pb.belt_3.required("SixBelt", "belt_3")?.value),
            ZBelt(x_pb.belt_4.required("SixBelt", "belt_4")?.value),
            ZBelt(x_pb.belt_5.required("SixBelt", "belt_5")?.value),
            ZBelt(x_pb.belt_6.required("SixBelt", "belt_6")?.value),
        ]),
        y: F6lt([
            ZBelt(y_pb.belt_1.required("SixBelt", "belt_1")?.value),
            ZBelt(y_pb.belt_2.required("SixBelt", "belt_2")?.value),
            ZBelt(y_pb.belt_3.required("SixBelt", "belt_3")?.value),
            ZBelt(y_pb.belt_4.required("SixBelt", "belt_4")?.value),
            ZBelt(y_pb.belt_5.required("SixBelt", "belt_5")?.value),
            ZBelt(y_pb.belt_6.required("SixBelt", "belt_6")?.value),
        ]),
        inf: pt.inf,
    }))
}

fn pb_schnorr_sig_to_sig(
    pb: PbSchnorrSignature,
) -> Result<iris_crypto::Signature, ConversionError> {
    use iris_ztd::Belt as ZBelt;

    let chal_pb = pb.chal.required("SchnorrSignature", "chal")?;
    let sig_val_pb = pb.sig.required("SchnorrSignature", "sig")?;

    let chal_belts = [
        chal_pb.belt_1.required("EightBelt", "belt_1")?.value,
        chal_pb.belt_2.required("EightBelt", "belt_2")?.value,
        chal_pb.belt_3.required("EightBelt", "belt_3")?.value,
        chal_pb.belt_4.required("EightBelt", "belt_4")?.value,
        chal_pb.belt_5.required("EightBelt", "belt_5")?.value,
        chal_pb.belt_6.required("EightBelt", "belt_6")?.value,
        chal_pb.belt_7.required("EightBelt", "belt_7")?.value,
        chal_pb.belt_8.required("EightBelt", "belt_8")?.value,
    ];
    let sig_belts = [
        sig_val_pb.belt_1.required("EightBelt", "belt_1")?.value,
        sig_val_pb.belt_2.required("EightBelt", "belt_2")?.value,
        sig_val_pb.belt_3.required("EightBelt", "belt_3")?.value,
        sig_val_pb.belt_4.required("EightBelt", "belt_4")?.value,
        sig_val_pb.belt_5.required("EightBelt", "belt_5")?.value,
        sig_val_pb.belt_6.required("EightBelt", "belt_6")?.value,
        sig_val_pb.belt_7.required("EightBelt", "belt_7")?.value,
        sig_val_pb.belt_8.required("EightBelt", "belt_8")?.value,
    ];

    let c_vec: Vec<ZBelt> = chal_belts.iter().map(|v| ZBelt(*v)).collect();
    let s_vec: Vec<ZBelt> = sig_belts.iter().map(|v| ZBelt(*v)).collect();

    let c = U256::from_le_slice(&ZBelt::to_bytes(&c_vec));
    let s = U256::from_le_slice(&ZBelt::to_bytes(&s_vec));

    Ok(iris_crypto::Signature { c, s })
}

impl From<LegacySignature> for PbLegacySignature {
    fn from(signature: LegacySignature) -> Self {
        PbLegacySignature {
            entries: signature
                .0
                .into_iter()
                .map(|(pubkey, signature)| PbSignatureEntry {
                    schnorr_pubkey: Some(public_key_to_pb(pubkey)),
                    signature: Some(schnorr_sig_to_pb(signature)),
                })
                .collect(),
        }
    }
}

impl TryFrom<PbLegacySignature> for LegacySignature {
    type Error = ConversionError;

    fn try_from(pb: PbLegacySignature) -> Result<Self, Self::Error> {
        let entries = pb
            .entries
            .into_iter()
            .map(|e| {
                let pubkey = pb_schnorr_pubkey_to_public_key(
                    e.schnorr_pubkey
                        .required("SignatureEntry", "schnorr_pubkey")?,
                )?;
                let sig =
                    pb_schnorr_sig_to_sig(e.signature.required("SignatureEntry", "signature")?)?;
                Ok((pubkey, sig))
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;
        Ok(LegacySignature(entries))
    }
}

impl From<Witness> for PbWitness {
    fn from(witness: Witness) -> Self {
        PbWitness {
            lock_merkle_proof: Some(PbLockMerkleProof::from(witness.lock_merkle_proof)),
            pkh_signature: Some(PbPkhSignature::from(witness.pkh_signature)),
            hax: witness.hax_map.into_iter().map(|hax| hax.into()).collect(),
        }
    }
}

impl From<Spend> for PbSpend {
    fn from(spend: Spend) -> Self {
        match spend {
            Spend::S1(ws) => PbSpend {
                spend_kind: Some(spend::SpendKind::Witness(PbWitnessSpend {
                    witness: Some(PbWitness::from(ws.witness)),
                    seeds: seeds_to_pb(ws.seeds),
                    fee: Some(PbNicks::from(ws.fee)),
                })),
            },
            Spend::S0(ls) => PbSpend {
                spend_kind: Some(spend::SpendKind::Legacy(PbLegacySpend {
                    signature: Some(PbLegacySignature::from(ls.signature)),
                    seeds: seeds_to_pb(ls.seeds),
                    fee: Some(PbNicks::from(ls.fee)),
                })),
            },
        }
    }
}

impl From<v1::RawTx> for PbRawTransaction {
    fn from(tx: v1::RawTx) -> Self {
        PbRawTransaction {
            version: Some(PbNoteVersion::from(tx.version())),
            id: Some(PbHash::from(tx.id)),
            spends: tx
                .spends
                .0
                .into_iter()
                .map(|(name, spend)| PbSpendEntry {
                    name: Some(PbName::from(name)),
                    spend: Some(PbSpend::from(spend)),
                })
                .collect(),
        }
    }
}

impl TryFrom<iris_nockchain_types::RawTx> for PbRawTransaction {
    type Error = ConversionError;

    fn try_from(tx: iris_nockchain_types::RawTx) -> Result<Self, Self::Error> {
        match tx {
            iris_nockchain_types::RawTx::V0(_) => Err(ConversionError::Invalid(
                "V0 RawTx should use PbRawTransactionV0, not PbRawTransaction",
            )),
            iris_nockchain_types::RawTx::V1(tx) => Ok(PbRawTransaction::from(tx)),
        }
    }
}

impl From<(Digest, Noun)> for PbHaxPreimage {
    fn from((hash, preimage): (Digest, Noun)) -> Self {
        PbHaxPreimage {
            hash: Some(PbHash::from(hash)),
            value: jam(preimage),
        }
    }
}

// Balance and Note conversions

impl From<v0::TimelockIntent> for PbTimeLockIntent {
    fn from(intent: v0::TimelockIntent) -> Self {
        PbTimeLockIntent {
            value: intent.tim.map(|t| {
                crate::pb::common::v1::time_lock_intent::Value::AbsoluteAndRelative(
                    crate::pb::common::v1::TimeLockRangeAbsoluteAndRelative {
                        absolute: Some(PbTimeLockRangeAbsolute {
                            min: t.abs.min.map(|v| v.into()),
                            max: t.abs.max.map(|v| v.into()),
                        }),
                        relative: Some(PbTimeLockRangeRelative {
                            min: t
                                .rel
                                .min
                                .map(|v| crate::pb::common::v1::BlockHeightDelta { value: v }),
                            max: t
                                .rel
                                .max
                                .map(|v| crate::pb::common::v1::BlockHeightDelta { value: v }),
                        }),
                    },
                )
            }),
        }
    }
}

impl TryFrom<PbTimeLockIntent> for v0::TimelockIntent {
    type Error = ConversionError;

    fn try_from(intent: PbTimeLockIntent) -> Result<Self, Self::Error> {
        use crate::pb::common::v1::time_lock_intent;

        let tim = match intent.value {
            None | Some(time_lock_intent::Value::Neither(_)) => None,
            Some(time_lock_intent::Value::Absolute(abs)) => Some(v0::Timelock {
                rel: TimelockRange::none(),
                abs: abs.into(),
            }),
            Some(time_lock_intent::Value::Relative(rel)) => Some(v0::Timelock {
                rel: rel.into(),
                abs: TimelockRange::none(),
            }),
            Some(time_lock_intent::Value::AbsoluteAndRelative(ar)) => Some(v0::Timelock {
                rel: ar
                    .relative
                    .map(Into::into)
                    .unwrap_or_else(TimelockRange::none),
                abs: ar
                    .absolute
                    .map(Into::into)
                    .unwrap_or_else(TimelockRange::none),
            }),
        };

        Ok(v0::TimelockIntent { tim })
    }
}

impl From<v0::Sig> for PbLegacyLock {
    fn from(sig: v0::Sig) -> Self {
        PbLegacyLock {
            keys_required: sig.m as u32,
            schnorr_pubkeys: sig.pubkeys.into_iter().map(public_key_to_pb).collect(),
        }
    }
}

impl TryFrom<PbLegacyLock> for v0::Sig {
    type Error = ConversionError;

    fn try_from(lock: PbLegacyLock) -> Result<Self, Self::Error> {
        let pubkeys = lock
            .schnorr_pubkeys
            .into_iter()
            .map(pb_schnorr_pubkey_to_public_key)
            .collect::<Result<Vec<iris_crypto::PublicKey>, ConversionError>>()?;

        Ok(v0::Sig {
            m: lock.keys_required as u64,
            pubkeys,
        })
    }
}

// v0::Note <-> PbNoteV0 (crate::pb::common::v1::Note) conversions
impl From<v0::Note> for crate::pb::common::v1::Note {
    fn from(note: v0::Note) -> Self {
        crate::pb::common::v1::Note {
            origin_page: Some(PbBlockHeight::from(note.inner.origin_page)),
            timelock: Some(PbTimeLockIntent::from(note.inner.timelock)),
            name: Some(PbName::from(note.name)),
            lock: Some(PbLegacyLock::from(note.sig)),
            source: Some(PbSource::from(note.source)),
            assets: Some(PbNicks::from(note.assets)),
            version: Some(PbNoteVersion::from(note.inner.version)),
        }
    }
}

impl TryFrom<crate::pb::common::v1::Note> for v0::Note {
    type Error = ConversionError;

    fn try_from(pb: crate::pb::common::v1::Note) -> Result<Self, Self::Error> {
        let origin_page: BlockHeight = pb.origin_page.required("Note", "origin_page")?.into();
        let name: Name = pb.name.required("Note", "name")?.try_into()?;
        let assets: Nicks = pb.assets.required("Note", "assets")?.into();
        let version: Version = pb.version.required("Note", "version")?.into();
        let source: Source = pb.source.required("Note", "source")?.try_into()?;
        let sig: v0::Sig = pb.lock.required("Note", "lock")?.try_into()?;
        let timelock: v0::TimelockIntent = if let Some(intent) = pb.timelock {
            intent.try_into()?
        } else {
            v0::TimelockIntent { tim: None }
        };

        Ok(v0::Note::new(
            version,
            origin_page,
            timelock,
            name,
            sig,
            source,
            assets,
        ))
    }
}

impl From<iris_nockchain_types::Note> for PbNote {
    fn from(note: iris_nockchain_types::Note) -> Self {
        PbNote {
            note_version: Some(match note {
                iris_nockchain_types::Note::V0(note) => {
                    crate::pb::common::v2::note::NoteVersion::Legacy(PbNoteV0 {
                        version: Some(PbNoteVersion::from(note.inner.version)),
                        origin_page: Some(PbBlockHeight::from(note.inner.origin_page)),
                        timelock: Some(PbTimeLockIntent::from(note.inner.timelock)),
                        name: Some(PbName::from(note.name)),
                        lock: Some(PbLegacyLock::from(note.sig)),
                        source: Some(PbSource::from(note.source)),
                        assets: Some(PbNicks::from(note.assets)),
                    })
                }
                iris_nockchain_types::Note::V1(note) => {
                    crate::pb::common::v2::note::NoteVersion::V1(PbNoteV1 {
                        version: Some(PbNoteVersion::from(note.version)),
                        origin_page: Some(PbBlockHeight::from(note.origin_page)),
                        name: Some(PbName::from(note.name)),
                        note_data: Some(PbNoteData::from(note.note_data)),
                        assets: Some(PbNicks::from(note.assets)),
                    })
                }
            }),
        }
    }
}

impl From<Balance> for PbBalance {
    fn from(balance: Balance) -> Self {
        PbBalance {
            notes: balance
                .0
                .into_iter()
                .map(|(name, note)| PbBalanceEntry {
                    name: Some(PbName::from(name)),
                    note: Some(PbNote::from(note)),
                })
                .collect(),
            height: Some(PbBlockHeight { value: 0 }),
            block_id: Some(PbHash::from(Digest([Belt(0); 5]))),
            page: Some(crate::pb::common::v1::PageResponse {
                next_page_token: String::new(),
            }),
        }
    }
}

impl From<BalanceUpdate> for PbBalance {
    fn from(update: BalanceUpdate) -> Self {
        PbBalance {
            notes: update
                .notes
                .0
                .into_iter()
                .map(|(name, note)| PbBalanceEntry {
                    name: Some(PbName::from(name)),
                    note: Some(PbNote::from(note)),
                })
                .collect(),
            height: Some(PbBlockHeight::from(update.height)),
            block_id: Some(PbHash::from(update.block_id)),
            page: Some(crate::pb::common::v1::PageResponse {
                next_page_token: String::new(),
            }),
        }
    }
}

// Reverse conversions: protobuf -> native types

impl TryFrom<PbNoteDataEntry> for iris_nockchain_types::v1::NoteDataEntry {
    type Error = ConversionError;

    fn try_from(entry: PbNoteDataEntry) -> Result<Self, Self::Error> {
        Ok(iris_nockchain_types::v1::NoteDataEntry {
            key: entry.key,
            val: iris_ztd::cue(&entry.blob).ok_or(Self::Error::Invalid("cue failed"))?,
        })
    }
}

impl TryFrom<PbNoteData> for iris_nockchain_types::v1::NoteData {
    type Error = ConversionError;

    fn try_from(pb_data: PbNoteData) -> Result<Self, Self::Error> {
        let entries: Result<Vec<iris_nockchain_types::v1::NoteDataEntry>, ConversionError> =
            pb_data
                .entries
                .into_iter()
                .map(PbNoteDataEntry::try_into)
                .collect();
        Ok(iris_nockchain_types::v1::NoteData(entries?))
    }
}

impl TryFrom<PbNote> for iris_nockchain_types::Note {
    type Error = ConversionError;

    fn try_from(pb_note: PbNote) -> Result<Self, Self::Error> {
        match pb_note.note_version.required("Note", "note_version")? {
            crate::pb::common::v2::note::NoteVersion::V1(v1) => {
                Ok(iris_nockchain_types::Note::V1(v1::Note {
                    version: v1.version.required("NoteV1", "version")?.into(),
                    origin_page: v1.origin_page.required("NoteV1", "origin_page")?.into(),
                    name: v1.name.required("NoteV1", "name")?.try_into()?,
                    note_data: v1.note_data.required("NoteV1", "note_data")?.try_into()?,
                    assets: v1.assets.required("NoteV1", "assets")?.into(),
                }))
            }
            crate::pb::common::v2::note::NoteVersion::Legacy(legacy) => {
                let PbNoteV0 {
                    origin_page,
                    timelock,
                    name,
                    lock,
                    source,
                    assets,
                    version,
                } = legacy;

                let origin_page: BlockHeight =
                    origin_page.required("LegacyNote", "origin_page")?.into();
                let name: Name = name.required("LegacyNote", "name")?.try_into()?;
                let assets: Nicks = assets.required("LegacyNote", "assets")?.into();
                let version: Version = version.required("LegacyNote", "version")?.into();
                let source: Source = source.required("LegacyNote", "source")?.try_into()?;

                let sig: v0::Sig = lock.required("LegacyNote", "lock")?.try_into()?;

                let timelock: v0::TimelockIntent = if let Some(intent) = timelock {
                    intent.try_into()?
                } else {
                    v0::TimelockIntent { tim: None }
                };

                Ok(iris_nockchain_types::Note::V0(v0::Note::new(
                    version,
                    origin_page,
                    timelock,
                    name,
                    sig,
                    source,
                    assets,
                )))
            }
        }
    }
}

impl TryFrom<PbBalanceEntry> for (Name, iris_nockchain_types::Note) {
    type Error = ConversionError;

    fn try_from(entry: PbBalanceEntry) -> Result<Self, Self::Error> {
        let name = entry.name.required("BalanceEntry", "name")?.try_into()?;
        let note = entry.note.required("BalanceEntry", "note")?.try_into()?;
        Ok((name, note))
    }
}

impl TryFrom<PbBalance> for BalanceUpdate {
    type Error = ConversionError;

    fn try_from(pb_balance: PbBalance) -> Result<Self, Self::Error> {
        let notes: Result<Vec<(Name, iris_nockchain_types::Note)>, ConversionError> = pb_balance
            .notes
            .into_iter()
            .map(|entry| entry.try_into())
            .collect();

        Ok(BalanceUpdate {
            height: pb_balance.height.required("Balance", "height")?.into(),
            block_id: pb_balance
                .block_id
                .required("Balance", "block_id")?
                .try_into()?,
            notes: Balance(notes?),
        })
    }
}
impl TryFrom<PbPkhLock> for Pkh {
    type Error = ConversionError;
    fn try_from(pkh: PbPkhLock) -> Result<Self, Self::Error> {
        let hashes: Result<Vec<Digest>, ConversionError> =
            pkh.hashes.into_iter().map(|h| h.try_into()).collect();
        Ok(Pkh::new(pkh.m, hashes?))
    }
}

impl TryFrom<PbLockPrimitive> for LockPrimitive {
    type Error = ConversionError;
    fn try_from(primitive: PbLockPrimitive) -> Result<Self, Self::Error> {
        match primitive.primitive.required("LockPrimitive", "primitive")? {
            lock_primitive::Primitive::Pkh(pkh) => Ok(LockPrimitive::Pkh(pkh.try_into()?)),
            lock_primitive::Primitive::Tim(tim) => Ok(LockPrimitive::Tim(tim.try_into()?)),
            lock_primitive::Primitive::Hax(hax) => {
                let hashes: Result<Vec<Digest>, ConversionError> =
                    hax.hashes.into_iter().map(|h| h.try_into()).collect();
                Ok(LockPrimitive::Hax(Hax(hashes?)))
            }
            lock_primitive::Primitive::Burn(_) => Ok(LockPrimitive::Brn),
        }
    }
}

impl TryFrom<PbSpendCondition> for SpendCondition {
    type Error = ConversionError;
    fn try_from(condition: PbSpendCondition) -> Result<Self, Self::Error> {
        let primitives: Result<Vec<LockPrimitive>, ConversionError> = condition
            .primitives
            .into_iter()
            .map(|p| p.try_into())
            .collect();
        Ok(SpendCondition(primitives?))
    }
}

impl TryFrom<PbSeed> for Seed {
    type Error = ConversionError;
    fn try_from(seed: PbSeed) -> Result<Self, Self::Error> {
        Ok(Seed {
            output_source: seed.output_source.map(|s| s.try_into()).transpose()?,
            lock_root: seed.lock_root.required("Seed", "lock_root")?.try_into()?,
            note_data: seed.note_data.required("Seed", "note_data")?.try_into()?,
            gift: seed.gift.required("Seed", "gift")?.into(),
            parent_hash: seed
                .parent_hash
                .required("Seed", "parent_hash")?
                .try_into()?,
        })
    }
}

impl TryFrom<PbRawTransaction> for iris_nockchain_types::RawTx {
    type Error = ConversionError;
    fn try_from(tx: PbRawTransaction) -> Result<Self, Self::Error> {
        let version: Version = tx.version.required("RawTransaction", "version")?.into();
        let id: Digest = tx.id.required("RawTransaction", "id")?.try_into()?;
        let spends: Result<Vec<(Name, Spend)>, ConversionError> = tx
            .spends
            .into_iter()
            .map(|entry| {
                let name = entry.name.required("SpendEntry", "name")?.try_into()?;
                let spend_pb = entry.spend.required("SpendEntry", "spend")?;
                let spend = match spend_pb.spend_kind.required("Spend", "spend_kind")? {
                    spend::SpendKind::Witness(w) => {
                        let witness_pb = w.witness.required("WitnessSpend", "witness")?;
                        let pkh_signature = witness_pb
                            .pkh_signature
                            .required("Witness", "pkh_signature")?
                            .try_into()?;
                        let lock_merkle_proof = witness_pb
                            .lock_merkle_proof
                            .required("Witness", "lock_merkle_proof")?;
                        let spend_condition = lock_merkle_proof
                            .spend_condition
                            .required("LockMerkleProof", "spend_condition")?
                            .try_into()?;
                        let proof = lock_merkle_proof
                            .proof
                            .required("LockMerkleProof", "proof")?;

                        let witness = Witness {
                            lock_merkle_proof: LockMerkleProof {
                                spend_condition,
                                axis: lock_merkle_proof.axis,
                                proof: MerkleProof {
                                    root: proof.root.required("MerkleProof", "root")?.try_into()?,
                                    path: proof
                                        .path
                                        .into_iter()
                                        .map(|h| h.try_into())
                                        .collect::<Result<Vec<_>, _>>()?,
                                },
                            },
                            pkh_signature,
                            hax_map: {
                                let mut map = iris_ztd::ZMap::new();
                                for hax in witness_pb.hax {
                                    let hash: Digest =
                                        hax.hash.required("HaxPreimage", "hash")?.try_into()?;
                                    let noun = iris_ztd::cue(&hax.value).ok_or(
                                        ConversionError::Invalid("HaxPreimage value (invalid jam)"),
                                    )?;
                                    map.insert(hash, noun);
                                }
                                map
                            },
                            tim: (),
                        };

                        let seeds: Result<Vec<Seed>, ConversionError> =
                            w.seeds.into_iter().map(|s| s.try_into()).collect();

                        Spend::S1(Spend1 {
                            witness,
                            seeds: Seeds(seeds?),
                            fee: w.fee.required("WitnessSpend", "fee")?.into(),
                        })
                    }
                    spend::SpendKind::Legacy(l) => {
                        let signature: LegacySignature = l
                            .signature
                            .required("LegacySpend", "signature")?
                            .try_into()?;
                        let seeds: Result<Vec<Seed>, ConversionError> =
                            l.seeds.into_iter().map(|s| s.try_into()).collect();
                        Spend::S0(Spend0 {
                            signature,
                            seeds: Seeds(seeds?),
                            fee: l.fee.required("LegacySpend", "fee")?.into(),
                        })
                    }
                };
                Ok((name, spend))
            })
            .collect();

        match version {
            Version::V1 => Ok(RawTx::V1(v1::RawTx {
                id,
                spends: v1::Spends(spends?),
            })),
            _ => Err(ConversionError::Invalid("Unsupported RawTx version")),
        }
    }
}

// ============================================
// V0 Protobuf conversions (v1/blockchain.proto)
// ============================================

// V0 Seed conversion
impl From<v0::Seed> for PbSeedV0 {
    fn from(seed: v0::Seed) -> Self {
        PbSeedV0 {
            output_source: seed
                .output_source
                .map(|s| crate::pb::common::v1::OutputSource {
                    source: Some(PbSource::from(s)),
                }),
            recipient: Some(PbLegacyLock::from(seed.recipient)),
            timelock_intent: Some(PbTimeLockIntent::from(seed.timelock_intent)),
            gift: Some(PbNicks::from(seed.gift)),
            parent_hash: Some(PbHash::from(seed.parent_hash)),
        }
    }
}

impl TryFrom<PbSeedV0> for v0::Seed {
    type Error = ConversionError;

    fn try_from(seed: PbSeedV0) -> Result<Self, Self::Error> {
        Ok(v0::Seed {
            output_source: seed
                .output_source
                .and_then(|os| os.source)
                .map(|s| s.try_into())
                .transpose()?,
            recipient: seed.recipient.required("Seed", "recipient")?.try_into()?,
            timelock_intent: seed
                .timelock_intent
                .required("Seed", "timelock_intent")?
                .try_into()?,
            gift: seed.gift.required("Seed", "gift")?.into(),
            parent_hash: seed
                .parent_hash
                .required("Seed", "parent_hash")?
                .try_into()?,
        })
    }
}

// V0 Spend conversion
impl From<v0::Spend> for PbSpendV0 {
    fn from(spend: v0::Spend) -> Self {
        PbSpendV0 {
            signature: spend.signature.map(PbLegacySignature::from),
            seeds: spend.seeds.0.into_iter().map(PbSeedV0::from).collect(),
            miner_fee_nicks: Some(PbNicks::from(spend.fee)),
        }
    }
}

impl TryFrom<PbSpendV0> for v0::Spend {
    type Error = ConversionError;

    fn try_from(spend: PbSpendV0) -> Result<Self, Self::Error> {
        let signature: Option<LegacySignature> = if let Some(s) = spend.signature {
            Some(s.try_into()?)
        } else {
            None
        };
        let seeds: Result<Vec<v0::Seed>, ConversionError> =
            spend.seeds.into_iter().map(|s| s.try_into()).collect();
        Ok(v0::Spend {
            signature,
            seeds: v0::Seeds(seeds?),
            fee: spend
                .miner_fee_nicks
                .required("Spend", "miner_fee_nicks")?
                .into(),
        })
    }
}

// V0 Input conversion
impl From<v0::Input> for PbInputV0 {
    fn from(input: v0::Input) -> Self {
        PbInputV0 {
            note: Some(crate::pb::common::v1::Note::from(input.note)),
            spend: Some(PbSpendV0::from(input.spend)),
        }
    }
}

impl TryFrom<PbInputV0> for v0::Input {
    type Error = ConversionError;

    fn try_from(input: PbInputV0) -> Result<Self, Self::Error> {
        Ok(v0::Input {
            note: input.note.required("Input", "note")?.try_into()?,
            spend: input.spend.required("Input", "spend")?.try_into()?,
        })
    }
}

// V0 RawTransaction conversion
impl From<v0::RawTx> for PbRawTransactionV0 {
    fn from(tx: v0::RawTx) -> Self {
        PbRawTransactionV0 {
            named_inputs: tx
                .inputs
                .0
                .into_iter()
                .map(|(name, input)| PbNamedInputV0 {
                    name: Some(PbName::from(name)),
                    input: Some(PbInputV0::from(input)),
                })
                .collect(),
            timelock_range: Some(PbTimeLockRangeAbsolute {
                min: tx.timelock_range.min.map(|v| v.into()),
                max: tx.timelock_range.max.map(|v| v.into()),
            }),
            total_fees: Some(PbNicks::from(tx.total_fees)),
            id: Some(PbHash::from(tx.id)),
        }
    }
}

impl TryFrom<PbRawTransactionV0> for v0::RawTx {
    type Error = ConversionError;

    fn try_from(tx: PbRawTransactionV0) -> Result<Self, Self::Error> {
        let id: Digest = tx.id.required("RawTransaction", "id")?.try_into()?;
        let inputs: Result<Vec<(Name, v0::Input)>, ConversionError> = tx
            .named_inputs
            .into_iter()
            .map(|ni| {
                let name = ni.name.required("NamedInput", "name")?.try_into()?;
                let input = ni.input.required("NamedInput", "input")?.try_into()?;
                Ok((name, input))
            })
            .collect();

        let timelock_range = tx
            .timelock_range
            .map(|tr| tr.into())
            .unwrap_or_else(TimelockRange::none);
        let total_fees = tx.total_fees.map(|f| f.into()).unwrap_or(0u64);

        Ok(v0::RawTx {
            id,
            inputs: v0::Inputs(inputs?),
            timelock_range,
            total_fees,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_raw_tx() {
        let json = r#"{
   "version":{
      "value":"1"
   },
   "id":"4SUkdDJXU6qM6CvYXSXStHrb8Xc1Ej1dfm3DDiEQL4giEsgn3oGGPYG",
   "spends":[
      {
         "name":{
            "first":"4rc6HmGGdZjnGmBu7T9oPsonr1aPUSPbX3MsxUKntUCfQKXQSFHApB3",
            "last":"C5NQvzEBotZWiM55efVNsweKU5FMRsR9KQ6q3D32ioZwNxCV3FXpYoD"
         },
         "spend":{
            "spend_kind":{
               "Witness":{
                  "witness":{
                     "lock_merkle_proof":{
                        "spend_condition":{
                           "primitives":[
                              {
                                 "primitive":{
                                    "Pkh":{
                                       "m":1,
                                       "hashes":[
                                          "9zpwNfGdcPT1QUKw2Fnw2zvftzpAYEjzZfTqGW8KLnf3NmEJ7yR5t2Y"
                                       ]
                                    }
                                 }
                              }
                           ]
                        },
                        "axis":1,
                        "proof":{
                           "root":"66oU5Tv4ukTdcNTWHwWJeNP873vJW1MLCWooj4udDn1cq3Yw8mTS2wH",
                           "path":[
                              
                           ]
                        }
                     },
                     "pkh_signature":{
                        "entries":[
                           {
                              "hash":"9zpwNfGdcPT1QUKw2Fnw2zvftzpAYEjzZfTqGW8KLnf3NmEJ7yR5t2Y",
                              "pubkey":{
                                 "value":{
                                    "x":{
                                       "belt_1":{
                                          "value":"11448626479992112395"
                                       },
                                       "belt_2":{
                                          "value":"4069103203247753166"
                                       },
                                       "belt_3":{
                                          "value":"14083262135992179683"
                                       },
                                       "belt_4":{
                                          "value":"3912178729246839688"
                                       },
                                       "belt_5":{
                                          "value":"11796384286367449624"
                                       },
                                       "belt_6":{
                                          "value":"8532292594068841388"
                                       }
                                    },
                                    "y":{
                                       "belt_1":{
                                          "value":"3947181904495261620"
                                       },
                                       "belt_2":{
                                          "value":"923589050609273779"
                                       },
                                       "belt_3":{
                                          "value":"6533369759867423146"
                                       },
                                       "belt_4":{
                                          "value":"16899530554254371214"
                                       },
                                       "belt_5":{
                                          "value":"1879763587494859085"
                                       },
                                       "belt_6":{
                                          "value":"15936891756251089176"
                                       }
                                    },
                                    "inf":false
                                 }
                              },
                              "signature":{
                                 "chal":{
                                    "belt_1":{
                                       "value":"232346795"
                                    },
                                    "belt_2":{
                                       "value":"3400859460"
                                    },
                                    "belt_3":{
                                       "value":"114700114"
                                    },
                                    "belt_4":{
                                       "value":"633571327"
                                    },
                                    "belt_5":{
                                       "value":"1411156586"
                                    },
                                    "belt_6":{
                                       "value":"3759003710"
                                    },
                                    "belt_7":{
                                       "value":"2978302736"
                                    },
                                    "belt_8":{
                                       "value":"294106749"
                                    }
                                 },
                                 "sig":{
                                    "belt_1":{
                                       "value":"645928783"
                                    },
                                    "belt_2":{
                                       "value":"3130880521"
                                    },
                                    "belt_3":{
                                       "value":"2031785340"
                                    },
                                    "belt_4":{
                                       "value":"432223730"
                                    },
                                    "belt_5":{
                                       "value":"2223476374"
                                    },
                                    "belt_6":{
                                       "value":"3949686173"
                                    },
                                    "belt_7":{
                                       "value":"708033354"
                                    },
                                    "belt_8":{
                                       "value":"1410508543"
                                    }
                                 }
                              }
                           }
                        ]
                     },
                     "hax":[
                        
                     ]
                  },
                  "seeds":[
                     {
                        "lock_root":"66oU5Tv4ukTdcNTWHwWJeNP873vJW1MLCWooj4udDn1cq3Yw8mTS2wH",
                        "note_data":{
                           "entries":[
                              
                           ]
                        },
                        "gift":{
                           "value":"18210766"
                        },
                        "parent_hash":"9TmqsBWQmJoWg6ZABwLGu2WsHEzt5bbNWwga9hygVpax7UEscW7MCg2"
                     },
                     {
                        "lock_root":"9baDCLsAat7JD2YoBBZCxpZMeh3QhUnmSaBTBu1UNH9oqeybehthbLx",
                        "note_data":{
                           "entries":[
                              
                           ]
                        },
                        "gift":{
                           "value":"3276800"
                        },
                        "parent_hash":"9TmqsBWQmJoWg6ZABwLGu2WsHEzt5bbNWwga9hygVpax7UEscW7MCg2"
                     }
                  ],
                  "fee":{
                     "value":"3407872"
                  }
               }
            }
         }
      }
   ]
}"#;
        let pb_raw_tx: PbRawTransaction = serde_json::from_str(json).unwrap();
        println!("{pb_raw_tx:?}");
        let raw_tx: RawTx = pb_raw_tx.clone().try_into().unwrap();
        println!("{raw_tx:?}");
        let pb2_raw_tx: PbRawTransaction = raw_tx.try_into().unwrap();
        println!("{pb2_raw_tx:?}");
        assert_eq!(pb_raw_tx, pb2_raw_tx);
    }
}
