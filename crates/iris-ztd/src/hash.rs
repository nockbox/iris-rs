#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};
use core::fmt;
use crypto_bigint::{nlimbs, NonZero, Uint};
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

#[cfg(feature = "alloc")]
pub fn belts_from_bytes(bytes: &[u8]) -> Vec<Belt> {
    belts_from_atom(UBig::from_be_bytes(bytes))
}

#[cfg(feature = "alloc")]
pub fn belts_from_atom(num: UBig) -> Vec<Belt> {
    let p = UBig::from(PRIME);
    let mut belts = Vec::new();
    let mut remainder = num;
    let zero = UBig::from(0u64);

    while remainder != zero {
        let (quotient, rem) = remainder.div_rem(&p);
        belts.push(Belt(rem.try_into().unwrap()));
        remainder = quotient;
    }

    belts
}

#[cfg(feature = "alloc")]
pub fn belts_to_bytes(belts: &[Belt]) -> Vec<u8> {
    belts_to_atom(belts).to_be_bytes()
}

#[cfg(feature = "alloc")]
pub fn belts_to_atom(belts: &[Belt]) -> UBig {
    let p = UBig::from(PRIME);
    let mut num = UBig::from(0u64);
    for belt in belts {
        num = num * &p + UBig::from(belt.0);
    }
    num
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Base58Belts<const N: usize>(pub [Belt; N]);

impl<const N: usize> Serialize for Base58Belts<N>
where
    Self: Limbable,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes_arr();
        let mut buf = <Self as Limbable>::bs58_buf();
        let len = bs58::encode(bytes.as_ref())
            .onto(buf.as_mut())
            .map_err(serde::ser::Error::custom)?;
        let s = core::str::from_utf8(&buf.as_ref()[..len]).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(s)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Base58Belts<N>
where
    Self: Limbable,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Base58Visitor<const M: usize>;

        impl<'de, const M: usize> serde::de::Visitor<'de> for Base58Visitor<M>
        where
            Base58Belts<M>: Limbable,
        {
            type Value = Base58Belts<M>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a base58-encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Base58Belts::<M>::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Base58Visitor::<N>)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[iris_ztd_derive::wasm_noun_codec]
#[cfg_attr(feature = "wasm", tsify(type = "string"))]
#[serde(from = "Base58Belts<5>")]
#[serde(into = "Base58Belts<5>")]
pub struct Digest(pub [Belt; 5]);

/// Convert big-endian bytes of any length to u64, asserting no overflow.
fn be_bytes_to_u64(bytes: &[u8]) -> u64 {
    if bytes.len() > 8 {
        assert!(
            bytes[..bytes.len() - 8].iter().all(|&x| x == 0),
            "value overflows u64"
        );
    }
    let mut buf = [0u8; 8];
    let start = 8usize.saturating_sub(bytes.len());
    buf[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(8)..]);
    u64::from_be_bytes(buf)
}

pub trait Limbable {
    const LIMBS: usize;
    const BYTES: usize;
    /// Buffer size for base58 encode/decode. Must be >= ceil(BYTES * 1.366).
    const BS58_BUF_SIZE: usize;
    type UintType: From<u64>
        + core::ops::MulAssign
        + core::ops::Mul<Output = Self::UintType>
        + core::ops::AddAssign
        + Copy
        + core::fmt::Debug;
    type BytesArray: AsRef<[u8]>
        + AsMut<[u8]>
        + core::ops::Index<usize, Output = u8>
        + core::ops::IndexMut<usize, Output = u8>;
    type Bs58Buf: AsRef<[u8]> + AsMut<[u8]>;
    fn bs58_buf() -> Self::Bs58Buf;
    fn to_be_bytes(uint: Self::UintType) -> Self::BytesArray;
    fn from_be_bytes(bytes: &[u8]) -> Self::UintType;
    fn div_rem(a: Self::UintType, b: Self::UintType) -> (Self::UintType, Self::UintType);
    fn is_zero(val: &Self::UintType) -> bool;
}

impl Limbable for Base58Belts<5> {
    const LIMBS: usize = nlimbs!(64 * 5);
    const BYTES: usize = 8 * 5;
    const BS58_BUF_SIZE: usize = Self::BYTES * 2;
    type UintType = Uint<{ Self::LIMBS }>;
    type BytesArray = [u8; Self::BYTES];
    type Bs58Buf = [u8; Self::BS58_BUF_SIZE];
    fn bs58_buf() -> Self::Bs58Buf {
        [0u8; Self::BS58_BUF_SIZE]
    }
    fn to_be_bytes(uint: Self::UintType) -> [u8; Self::BYTES] {
        uint.to_be_bytes()
    }
    fn from_be_bytes(bytes: &[u8]) -> Self::UintType {
        Self::UintType::from_be_slice(bytes)
    }
    fn div_rem(a: Self::UintType, b: Self::UintType) -> (Self::UintType, Self::UintType) {
        let nz = NonZero::new(b).expect("division by zero");
        a.div_rem(&nz)
    }
    fn is_zero(val: &Self::UintType) -> bool {
        *val == Self::UintType::from(0u64)
    }
}

impl Limbable for Base58Belts<6> {
    const LIMBS: usize = nlimbs!(64 * 6);
    const BYTES: usize = 8 * 6;
    const BS58_BUF_SIZE: usize = Self::BYTES * 2;
    type UintType = Uint<{ Self::LIMBS }>;
    type BytesArray = [u8; Self::BYTES];
    type Bs58Buf = [u8; Self::BS58_BUF_SIZE];
    fn bs58_buf() -> Self::Bs58Buf {
        [0u8; Self::BS58_BUF_SIZE]
    }
    fn to_be_bytes(uint: Self::UintType) -> [u8; Self::BYTES] {
        uint.to_be_bytes()
    }
    fn from_be_bytes(bytes: &[u8]) -> Self::UintType {
        Self::UintType::from_be_slice(bytes)
    }
    fn div_rem(a: Self::UintType, b: Self::UintType) -> (Self::UintType, Self::UintType) {
        let nz = NonZero::new(b).expect("division by zero");
        a.div_rem(&nz)
    }
    fn is_zero(val: &Self::UintType) -> bool {
        *val == Self::UintType::from(0u64)
    }
}

impl Limbable for Base58Belts<7> {
    const LIMBS: usize = nlimbs!(64 * 7);
    const BYTES: usize = 8 * 7;
    const BS58_BUF_SIZE: usize = Self::BYTES * 2;
    type UintType = Uint<{ Self::LIMBS }>;
    type BytesArray = [u8; Self::BYTES];
    type Bs58Buf = [u8; Self::BS58_BUF_SIZE];
    fn bs58_buf() -> Self::Bs58Buf {
        [0u8; Self::BS58_BUF_SIZE]
    }
    fn to_be_bytes(uint: Self::UintType) -> [u8; Self::BYTES] {
        uint.to_be_bytes()
    }
    fn from_be_bytes(bytes: &[u8]) -> Self::UintType {
        Self::UintType::from_be_slice(bytes)
    }
    fn div_rem(a: Self::UintType, b: Self::UintType) -> (Self::UintType, Self::UintType) {
        let nz = NonZero::new(b).expect("division by zero");
        a.div_rem(&nz)
    }
    fn is_zero(val: &Self::UintType) -> bool {
        *val == Self::UintType::from(0u64)
    }
}

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

impl<const N: usize> Base58Belts<N>
where
    Self: Limbable,
{
    pub fn to_uint(&self) -> <Self as Limbable>::UintType {
        let p = <Self as Limbable>::UintType::from(PRIME);
        let mut result = <Self as Limbable>::UintType::from(0u64);
        let mut power = <Self as Limbable>::UintType::from(1u64);

        for belt in &self.0 {
            result += <Self as Limbable>::UintType::from(belt.0) * power;
            power *= p;
        }

        result
    }

    pub fn to_bytes_arr(&self) -> <Self as Limbable>::BytesArray {
        Self::to_be_bytes(self.to_uint())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let p = <Self as Limbable>::UintType::from(PRIME);
        let num = <Self as Limbable>::from_be_bytes(bytes);

        let mut belts = [Belt(0); N];
        let mut remainder = num;

        for b in &mut belts[..] {
            let (quotient, rem) = <Self as Limbable>::div_rem(remainder, p);
            *b = Belt(be_bytes_to_u64(Self::to_be_bytes(rem).as_ref()));
            remainder = quotient;
        }

        assert!(
            <Self as Limbable>::is_zero(&remainder),
            "Invalid belt count"
        );

        Base58Belts(belts)
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

// Display and TryFrom implementations for Base58Belts<N> (no-alloc)
impl<const N: usize> fmt::Display for Base58Belts<N>
where
    Self: Limbable,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes_arr();
        let mut buf = <Self as Limbable>::bs58_buf();
        let len = bs58::encode(bytes.as_ref())
            .onto(buf.as_mut())
            .map_err(|_| fmt::Error)?;
        let s = core::str::from_utf8(&buf.as_ref()[..len]).map_err(|_| fmt::Error)?;
        f.write_str(s)
    }
}

impl<const N: usize> TryFrom<&str> for Base58Belts<N>
where
    Self: Limbable,
{
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let mut buf = <Self as Limbable>::bs58_buf();
        let len = bs58::decode(s)
            .onto(buf.as_mut())
            .map_err(|_| "unable to decode base58 belts")?;
        Ok(Base58Belts::from_bytes(&buf.as_ref()[..len]))
    }
}

// Digest implementations delegate to Base58Belts<5>
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Base58Belts::<5>::from(*self).fmt(f)
    }
}

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
    Digest(hash_varlen(&combined).map(Belt))
}

pub trait Hashable {
    fn hash(&self) -> Digest;
}

impl Hashable for Belt {
    fn hash(&self) -> Digest {
        let v = [Belt(1), *self];
        Digest(hash_varlen(&v).map(Belt))
    }
}

impl Hashable for u64 {
    fn hash(&self) -> Digest {
        Belt(*self).hash()
    }
}

impl Hashable for u32 {
    fn hash(&self) -> Digest {
        Belt(*self as u64).hash()
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
        Digest(hash_varlen(&hash).map(Belt))
    }
}
