use nbx_nockchain_types::*;
use nbx_ztd::{cue, Belt, Digest, Hashable as ZHashable, HashableString, ZMap};

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
    Note as PbNote, NoteData as PbNoteData, NoteDataEntry, NoteV1 as PbNoteV1,
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

impl From<NoteData> for PbNoteData {
    fn from(data: NoteData) -> Self {
        Self {
            entries: vec![NoteDataEntry {
                key: "lock".to_string(),
                blob: data.blob(),
            }],
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
        use nbx_ztd::Belt as ZBelt;

        PbPkhSignature {
            entries: signature
                .0
                .into_iter()
                .map(|(pubkey, sig)| {
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
                        hash: Some(PbHash::from(pubkey.hash())),
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
                note_data: Some(PbNoteData::from(NoteData(note.note_data))),
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

impl TryFrom<PbNote> for Note {
    type Error = ConversionError;

    fn try_from(pb_note: PbNote) -> Result<Self, Self::Error> {
        match pb_note.note_version.required("Note", "note_version")? {
            crate::pb::common::v2::note::NoteVersion::V1(v1) => {
                let note_data = v1.note_data.required("NoteV1", "note_data")?;
                let mut cued_note_data = vec![];
                for e in note_data.entries {
                    let name = HashableString::try_from(e.key)
                        .map_err(|_| ConversionError::Invalid("note-data key too long"))?;
                    cued_note_data.push((
                        name,
                        cue(&e.blob)
                            .ok_or(ConversionError::Invalid("Unable to unjam note-data"))?,
                    ));
                }
                let note_data = ZMap::from_iter(cued_note_data);
                Ok(Note {
                    version: v1.version.required("NoteV1", "version")?.into(),
                    origin_page: v1.origin_page.required("NoteV1", "origin_page")?.into(),
                    name: v1.name.required("NoteV1", "name")?.try_into()?,
                    note_data,
                    assets: v1.assets.required("NoteV1", "assets")?.into(),
                })
            }
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
