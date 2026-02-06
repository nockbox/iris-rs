use core::fmt;
use serde::{Deserialize, Serialize};

use crate::{
    belt::{Belt, PRIME},
    crypto::cheetah::CheetahPoint,
    tip5::hash::{hash_fixed, hash_varlen},
};

#[cfg(feature = "alloc")]
use crate::Noun;
#[cfg(feature = "alloc")]
use crate::Zeroable;
#[cfg(feature = "alloc")]
use alloc::{string::String, vec, vec::Vec};
#[cfg(feature = "alloc")]
use ibig::{ops::DivRem, UBig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Base58Belts<const N: usize>(pub [Belt; N]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Digest(pub [Belt; 5]);

impl From<[u64; 5]> for Digest {
    fn from(belts: [u64; 5]) -> Self {
        Digest(belts.map(Belt))
    }
}

impl From<Digest> for Base58Belts<5> {
    fn from(digest: Digest) -> Self {
        Base58Belts(digest.0)
    }
}

impl From<Base58Belts<5>> for Digest {
    fn from(belts: Base58Belts<5>) -> Self {
        Digest(belts.0)
    }
}

impl<const N: usize> From<[u64; N]> for Base58Belts<N> {
    fn from(belts: [u64; N]) -> Self {
        Base58Belts(belts.map(Belt))
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Base58Belts<N> {
    pub fn to_atom(&self) -> UBig {
        let p = UBig::from(PRIME);
        let mut result = UBig::from(0u64);
        let mut power = UBig::from(1u64);

        for belt in &self.0 {
            result += UBig::from(belt.0) * &power;
            power *= &p;
        }

        result
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let res = self.to_atom();
        let res_bytes = res.to_be_bytes();
        let expected_len = N * 8; // Each belt is 8 bytes

        let mut bytes = vec![0u8; expected_len];
        let start_offset = expected_len.saturating_sub(res_bytes.len());
        bytes[start_offset..].copy_from_slice(&res_bytes);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let p = UBig::from(PRIME);
        let num = UBig::from_be_bytes(bytes);

        let mut belts = Vec::with_capacity(N);
        let mut remainder = num;

        for _ in 0..N {
            let (quotient, rem) = remainder.div_rem(&p);
            belts.push(Belt(rem.try_into().unwrap()));
            remainder = quotient;
        }

        // Convert Vec to array
        let array: [Belt; N] = belts
            .try_into()
            .unwrap_or_else(|_| panic!("Invalid belt count"));
        Base58Belts(array)
    }
}

// Digest-specific implementations that delegate to Base58Belts<5>
#[cfg(feature = "alloc")]
impl Digest {
    pub fn to_atom(&self) -> UBig {
        Base58Belts::<5>::from(*self).to_atom()
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let vec = Base58Belts::<5>::from(*self).to_bytes();
        let mut arr = [0u8; 40];
        arr.copy_from_slice(&vec);
        arr
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Base58Belts::<5>::from_bytes(bytes).into()
    }
}

// Display and TryFrom implementations for Base58Belts<N>
#[cfg(feature = "alloc")]
impl<const N: usize> fmt::Display for Base58Belts<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "{}", bs58::encode(bytes).into_string())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> TryFrom<&str> for Base58Belts<N> {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Base58Belts::from_bytes(
            &bs58::decode(s)
                .into_vec()
                .map_err(|_| "unable to decode base58 belts")?,
        ))
    }
}

// Digest implementations delegate to Base58Belts<5>
#[cfg(feature = "alloc")]
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Base58Belts::<5>::from(*self).fmt(f)
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<&str> for Digest {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Base58Belts::<5>::try_from(s)?.into())
    }
}

#[cfg(feature = "alloc")]
pub fn hash_noun(leaves: &[Belt], dyck: &[Belt]) -> Digest {
    let mut combined = Vec::with_capacity(1 + leaves.len() + dyck.len());
    combined.push(Belt(leaves.len() as u64));
    combined.extend_from_slice(leaves);
    combined.extend_from_slice(dyck);
    Digest(hash_varlen(&mut combined).map(Belt))
}

pub trait Hashable {
    fn hash(&self) -> Digest;
}

impl Hashable for Belt {
    fn hash(&self) -> Digest {
        let mut v = [Belt(1), *self];
        Digest(hash_varlen(&mut v).map(Belt))
    }
}

impl Hashable for u64 {
    fn hash(&self) -> Digest {
        Belt(*self).hash()
    }
}

impl Hashable for usize {
    fn hash(&self) -> Digest {
        (*self as u64).hash()
    }
}

impl Hashable for i32 {
    fn hash(&self) -> Digest {
        (*self as u64).hash()
    }
}

impl Hashable for bool {
    fn hash(&self) -> Digest {
        (if *self { 0 } else { 1 }).hash()
    }
}

impl Hashable for Digest {
    fn hash(&self) -> Digest {
        *self
    }
}

impl<T: Hashable + ?Sized> Hashable for &T {
    fn hash(&self) -> Digest {
        (**self).hash()
    }
}

impl<T: Hashable> Hashable for Option<T> {
    fn hash(&self) -> Digest {
        match self {
            None => 0.hash(),
            Some(v) => (&0, v).hash(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: Hashable> Hashable for Zeroable<T> {
    fn hash(&self) -> Digest {
        match &self.0 {
            None => 0.hash(),
            Some(v) => v.hash(),
        }
    }
}

impl Hashable for () {
    fn hash(&self) -> Digest {
        0.hash()
    }
}

macro_rules! impl_hashable_for_tuple {
    ($T0:ident) => {};
    ($T0:ident, $T1:ident) => {
        impl<$T0: Hashable, $T1: Hashable> Hashable for ($T0, $T1) {
            fn hash(&self) -> Digest {
                let mut belts = [Belt(0); 10];
                belts[..5].copy_from_slice(&self.0.hash().0);
                belts[5..].copy_from_slice(&self.1.hash().0);
                Digest(hash_fixed(&mut belts).map(|u| Belt(u)))
            }
        }
    };
    ($T:ident, $($U:ident),+) => {
        impl<$T: Hashable, $($U: Hashable),*> Hashable for ($T, $($U),*) {
            fn hash(&self) -> Digest {
                #[allow(non_snake_case)]
                let ($T, $($U),*) = self;
                ($T, ($($U,)*)).hash()
            }
        }

        impl_hashable_for_tuple!($($U),*);
    };
}

impl_hashable_for_tuple!(A, B, C, D, E, F, G, H, I, J, K);

impl<T: Hashable> Hashable for &[T] {
    fn hash(&self) -> Digest {
        let (first, rest) = self.split_first().unwrap();
        if rest.is_empty() {
            first.hash()
        } else {
            (first.hash(), rest.hash()).hash()
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: Hashable> Hashable for Vec<T> {
    fn hash(&self) -> Digest {
        fn hash_slice<T: Hashable>(arr: &[T]) -> Digest {
            match arr.split_first() {
                None => 0.hash(),
                Some((first, rest)) => (first.hash(), hash_slice(rest)).hash(),
            }
        }
        hash_slice(self.as_slice())
    }
}

impl Hashable for &str {
    fn hash(&self) -> Digest {
        self.bytes()
            .enumerate()
            .fold(0u64, |acc, (i, byte)| acc | ((byte as u64) << (i * 8)))
            .hash()
    }
}

#[cfg(feature = "alloc")]
impl Hashable for String {
    fn hash(&self) -> Digest {
        self.bytes()
            .enumerate()
            .fold(0u64, |acc, (i, byte)| acc | ((byte as u64) << (i * 8)))
            .hash()
    }
}

#[cfg(feature = "alloc")]
impl Hashable for Noun {
    fn hash(&self) -> Digest {
        fn visit(noun: &Noun, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
            match noun {
                Noun::Atom(b) => leaves.push(Belt(b.try_into().expect("atom too large"))),
                Noun::Cell(left, right) => {
                    dyck.push(Belt(0));
                    visit(left, leaves, dyck);
                    dyck.push(Belt(1));
                    visit(right, leaves, dyck);
                }
            }
        }

        let mut leaves = Vec::new();
        let mut dyck = Vec::new();
        visit(self, &mut leaves, &mut dyck);
        hash_noun(&leaves, &dyck)
    }
}

impl Hashable for CheetahPoint {
    fn hash(&self) -> Digest {
        // This is equivalent to converting CheetahPoint to noun, and then hashing that.
        let dyck = [
            0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1,
        ]
        .map(Belt);
        let mut leaves = [Belt(0); 6 + 6 + 1];
        leaves[..6].copy_from_slice(&self.x.0);
        leaves[6..12].copy_from_slice(&self.y.0);
        leaves[12] = Belt(!self.inf as u64);
        let mut hash = [Belt(0); 1 + 24 + 6 + 6 + 1];
        hash[0] = Belt(leaves.len() as u64);
        hash[1..14].copy_from_slice(&leaves);
        hash[14..38].copy_from_slice(&dyck);
        Digest(hash_varlen(&mut hash).map(Belt))
    }
}
