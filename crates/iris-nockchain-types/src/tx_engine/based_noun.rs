use alloc::sync::Arc;
#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};
use iris_ztd::{Belt, Digest, Hashable, Noun, NounDecode, NounEncode};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A noun whose atoms are valid field elements (`based`, in node terms).
///
/// This is the protocol's type for nouns that are hashed into commitments
/// (hax preimages, note-data values): the node embeds them structurally in a
/// `hashable:tip5` — `hash-varlen` per atom leaf, `hash-ten-cell` per cell —
/// and rejects non-based leaves (`based:witness`, tx-engine-1.hoon). Both
/// rules hold here by construction: `Hashable` is the structural hash, and
/// decoding fails on atoms outside the field.
///
/// A plain [`Noun`] hashes differently (`hash-noun-varlen` over the whole
/// noun); the two must not be conflated.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(
    feature = "wasm",
    tsify(into_wasm_abi, from_wasm_abi, type = "string | [BasedNoun]")
)]
#[iris_ztd::wasm_noun_codec(no_derive)]
pub enum BasedNoun {
    Atom(Belt),
    Cell(Arc<BasedNoun>, Arc<BasedNoun>),
}

impl PartialEq for BasedNoun {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (BasedNoun::Atom(a), BasedNoun::Atom(b)) => a == b,
            (BasedNoun::Cell(a1, b1), BasedNoun::Cell(a2, b2)) => {
                (Arc::ptr_eq(a1, a2) && Arc::ptr_eq(b1, b2)) || (a1 == a2 && b1 == b2)
            }
            _ => false,
        }
    }
}

impl Eq for BasedNoun {}

impl core::fmt::Display for BasedNoun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.to_noun(), f)
    }
}

impl NounEncode for BasedNoun {
    fn to_noun(&self) -> Noun {
        match self {
            BasedNoun::Atom(b) => b.to_noun(),
            BasedNoun::Cell(l, r) => Noun::Cell(l.to_noun().into(), r.to_noun().into()),
        }
    }
}

impl NounDecode for BasedNoun {
    fn from_noun(noun: &Noun) -> Option<Self> {
        match noun {
            Noun::Atom(a) => {
                let v = u64::try_from(a).ok()?;
                // NOTE: must go through &u64 to hit the based-checked
                // conversion; the owned TryFrom<u64> is the unchecked
                // blanket impl via From<u64>.
                Belt::try_from(&v).ok().map(BasedNoun::Atom)
            }
            Noun::Cell(l, r) => Some(BasedNoun::Cell(
                Arc::new(Self::from_noun(l)?),
                Arc::new(Self::from_noun(r)?),
            )),
        }
    }
}

// Serde delegates to Noun so the wire format stays identical and cannot
// drift; deserialization revalidates the based invariant.
impl Serialize for BasedNoun {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_noun().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BasedNoun {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let noun = Noun::deserialize(de)?;
        Self::from_noun(&noun)
            .ok_or_else(|| DeError::custom("noun atoms must be valid field elements"))
    }
}

impl Hashable for BasedNoun {
    fn hash(&self) -> Digest {
        match self {
            BasedNoun::Atom(a) => a.hash(),
            BasedNoun::Cell(left, right) => (left.hash(), right.hash()).hash(),
        }
    }

    fn leaf_count(&self) -> usize {
        match self {
            BasedNoun::Atom(_) => 1,
            BasedNoun::Cell(l, r) => l.leaf_count() + r.leaf_count(),
        }
    }

    fn hashable_pair<'a>(&'a self) -> Option<(impl Hashable + 'a, impl Hashable + 'a)> {
        match self {
            BasedNoun::Atom(_) => None,
            BasedNoun::Cell(l, r) => Some((&**l, &**r)),
        }
    }
}
