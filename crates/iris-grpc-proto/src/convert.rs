use iris_nockchain_types::*;
use iris_ztd::{jam, Belt, Digest};

use crate::common::{ConversionError, Required};
use crate::pb::common::v1::{
    BlockHeight as PbBlockHeight, Hash as PbHash, Name as PbName, Nicks as PbNicks,
    NoteVersion as PbNoteVersion, Source as PbSource,
    TimeLockRangeAbsolute as PbTimeLockRangeAbsolute,
    TimeLockRangeRelative as PbTimeLockRangeRelative,
};
use crate::pb::common::v2::{
    lock_primitive, spend, Balance as PbBalance, BalanceEntry as PbBalanceEntry,
    BurnLock as PbBurnLock, HaxLock as PbHaxLock, LockMerkleProof as PbLockMerkleProof,
    LockPrimitive as PbLockPrimitive, LockTim as PbLockTim, MerkleProof as PbMerkleProof,
    Note as PbNote, NoteData as PbNoteData, NoteDataEntry as PbNoteDataEntry, NoteV1 as PbNoteV1,
    PkhLock as PbPkhLock, PkhSignature as PbPkhSignature, RawTransaction as PbRawTransaction,
    Seed as PbSeed, Spend as PbSpend, SpendCondition as PbSpendCondition,
    SpendEntry as PbSpendEntry, Witness as PbWitness, WitnessSpend as PbWitnessSpend,
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

impl From<Digest> for PbHash {
    fn from(h: Digest) -> Self {
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

impl From<NoteDataEntry> for PbNoteDataEntry {
    fn from(data: NoteDataEntry) -> Self {
        Self {
            key: data.key,
            blob: jam(data.val),
        }
    }
}

impl From<NoteData> for PbNoteData {
    fn from(data: NoteData) -> Self {
        Self {
            entries: data.0.into_iter().map(PbNoteDataEntry::from).collect(),
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

impl From<Witness> for PbWitness {
    fn from(witness: Witness) -> Self {
        PbWitness {
            lock_merkle_proof: Some(PbLockMerkleProof::from(witness.lock_merkle_proof)),
            pkh_signature: Some(PbPkhSignature::from(witness.pkh_signature)),
            hax: Vec::new(),
        }
    }
}

impl From<Spend> for PbSpend {
    fn from(spend: Spend) -> Self {
        PbSpend {
            spend_kind: Some(spend::SpendKind::Witness(PbWitnessSpend {
                witness: Some(PbWitness::from(spend.witness)),
                seeds: seeds_to_pb(spend.seeds),
                fee: Some(PbNicks::from(spend.fee)),
            })),
        }
    }
}

impl From<RawTx> for PbRawTransaction {
    fn from(tx: RawTx) -> Self {
        PbRawTransaction {
            version: Some(PbNoteVersion::from(tx.version)),
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

// Balance and Note conversions

impl From<Note> for PbNote {
    fn from(note: Note) -> Self {
        PbNote {
            note_version: Some(crate::pb::common::v2::note::NoteVersion::V1(PbNoteV1 {
                version: Some(PbNoteVersion::from(note.version)),
                origin_page: Some(PbBlockHeight::from(note.origin_page)),
                name: Some(PbName::from(note.name)),
                note_data: Some(PbNoteData::from(note.note_data)),
                assets: Some(PbNicks::from(note.assets)),
            })),
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

impl TryFrom<PbNoteDataEntry> for NoteDataEntry {
    type Error = ConversionError;

    fn try_from(entry: PbNoteDataEntry) -> Result<Self, Self::Error> {
        Ok(NoteDataEntry {
            key: entry.key,
            val: iris_ztd::cue(&entry.blob).ok_or(Self::Error::Invalid("cue failed"))?,
        })
    }
}

impl TryFrom<PbNoteData> for NoteData {
    type Error = ConversionError;

    fn try_from(pb_data: PbNoteData) -> Result<Self, Self::Error> {
        let entries: Result<Vec<NoteDataEntry>, ConversionError> = pb_data
            .entries
            .into_iter()
            .map(PbNoteDataEntry::try_into)
            .collect();
        Ok(NoteData(entries?))
    }
}

impl TryFrom<PbNote> for Note {
    type Error = ConversionError;

    fn try_from(pb_note: PbNote) -> Result<Self, Self::Error> {
        match pb_note.note_version.required("Note", "note_version")? {
            crate::pb::common::v2::note::NoteVersion::V1(v1) => Ok(Note {
                version: v1.version.required("NoteV1", "version")?.into(),
                origin_page: v1.origin_page.required("NoteV1", "origin_page")?.into(),
                name: v1.name.required("NoteV1", "name")?.try_into()?,
                note_data: v1.note_data.required("NoteV1", "note_data")?.try_into()?,
                assets: v1.assets.required("NoteV1", "assets")?.into(),
            }),
            crate::pb::common::v2::note::NoteVersion::Legacy(_) => Err(
                ConversionError::UnsupportedVersion("Legacy note format not supported".to_string()),
            ),
        }
    }
}

impl TryFrom<PbBalanceEntry> for (Name, Note) {
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
        let notes: Result<Vec<(Name, Note)>, ConversionError> = pb_balance
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

impl TryFrom<PbRawTransaction> for RawTx {
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
                            pkh_signature: PkhSignature(Vec::new()), // Signature verification not needed for this use case
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

                        Spend {
                            witness,
                            seeds: Seeds(seeds?),
                            fee: w.fee.required("WitnessSpend", "fee")?.into(),
                        }
                    }
                    spend::SpendKind::Legacy(_) => {
                        return Err(ConversionError::Invalid("Legacy spends are not supported"));
                    }
                };
                Ok((name, spend))
            })
            .collect();

        Ok(RawTx {
            version,
            id,
            spends: Spends(spends?),
        })
    }
}
