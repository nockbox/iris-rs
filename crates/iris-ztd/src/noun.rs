use crate::belt::based_check;
use crate::crypto::cheetah::F6lt;
#[cfg(feature = "wasm")]
use alloc::format;
#[cfg(feature = "wasm")]
use alloc::string::ToString;
use alloc::{
    boxed::Box, collections::btree_map::BTreeMap, string::String, sync::Arc, vec, vec::Vec,
};
use bitvec::prelude::{BitSlice, BitVec, Lsb0};
use ibig::UBig;
use num_traits::Zero;
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{ser::SerializeSeq, Serialize, Serializer};
use serde::{Deserialize, Deserializer};

use crate::{belt::Belt, crypto::cheetah::CheetahPoint, Digest};

/// A transparent wrapper that encodes as a zero atom if the value is `None`.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Zeroable<T>(pub Option<T>);

impl<T> core::ops::Deref for Zeroable<T> {
    type Target = Option<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for Zeroable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn noun_serialize<T: NounEncode, S>(v: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    v.to_noun().serialize(serializer)
}

pub fn noun_deserialize<'de, T: NounDecode, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let r = Noun::deserialize(deserializer)?;
    T::from_noun(&r).ok_or_else(|| DeError::custom("unable to parse noun"))
}

const fn mug(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111ebu64);
    x ^ (x >> 31)
}

const fn mug_bytes(b: &[u8]) -> u64 {
    let mut ret = 0u64;

    let mut i = 0;

    while i < b.len() {
        ret = mug(ret.wrapping_add(b[i] as u64));
        i += 1;
    }

    mug(ret)
}

fn mug_noun(noun: &Noun) -> u32 {
    match noun {
        Noun::Atom(atom) => mug(mug_bytes(&atom.to_le_bytes())) as u32,
        Noun::Cell(left, right) => mug(left.0.mug as u64 | ((right.0.mug as u64) << 32)) as u32,
    }
}

fn weight_noun(noun: &Noun) -> u32 {
    match noun {
        Noun::Atom(_) => 1,
        Noun::Cell(left, right) => 1 + left.0.weight + right.0.weight,
    }
}

#[derive(Clone, Debug)]
struct HashNounContents {
    noun: Noun,
    mug: u32,
    weight: u32,
}

impl From<Noun> for HashNounContents {
    fn from(noun: Noun) -> Self {
        Self {
            mug: mug_noun(&noun),
            weight: weight_noun(&noun),
            noun,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HashNoun(Arc<HashNounContents>);

impl From<Noun> for HashNoun {
    fn from(noun: Noun) -> Self {
        Self(Arc::new(noun.into()))
    }
}

impl core::ops::Deref for HashNoun {
    type Target = Noun;

    fn deref(&self) -> &Self::Target {
        &self.0.noun
    }
}

/// Nock-native data structure
///
/// A Noun is an Atom or a Cell.
///
/// A Cell is a pair of Nouns.
///
/// An Atom is a natural number.
///
/// Specific to iris, serialized atoms are encoded as little-endian hex strings.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(
    feature = "wasm",
    tsify(into_wasm_abi, from_wasm_abi, type = "string | [Noun]")
)]
pub enum Noun {
    Atom(UBig),
    Cell(HashNoun, HashNoun),
}

impl PartialEq for Noun {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Noun::Atom(a), Noun::Atom(b)) => a == b,
            (Noun::Cell(a1, b1), Noun::Cell(a2, b2)) => {
                (Arc::as_ptr(&a1.0) == Arc::as_ptr(&a2.0)
                    && Arc::as_ptr(&b1.0) == Arc::as_ptr(&b2.0))
                    || (a1.0.mug == a2.0.mug
                        && b1.0.mug == b2.0.mug
                        && a1.0.weight == a2.0.weight
                        && b1.0.weight == b2.0.weight
                        && a1.0.noun == a2.0.noun
                        && b1.0.noun == b2.0.noun)
            }
            _ => false,
        }
    }
}

impl Eq for Noun {}

impl core::fmt::Display for Noun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        struct AutoCons<'a>(&'a Noun);
        impl<'a> core::fmt::Display for AutoCons<'a> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.0 {
                    Noun::Atom(a) => write!(f, "{}", a),
                    Noun::Cell(head, tail) => match &**tail {
                        Noun::Cell(_, _) => write!(f, "{} {}", AutoCons(head), AutoCons(tail)),
                        Noun::Atom(a) if a.is_zero() => AutoCons(head).fmt(f),
                        Noun::Atom(_) => write!(f, "{} . {}", AutoCons(head), AutoCons(tail)),
                    },
                }
            }
        }

        match self {
            Noun::Atom(a) => write!(f, "{}", a),
            Noun::Cell(_, _) => write!(f, "[{}]", AutoCons(self)),
        }
    }
}

impl Serialize for Noun {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Atom(v) => serializer.serialize_str(&alloc::format!("{v:x}")),
            Self::Cell(a, b) => {
                let mut seq = serializer.serialize_seq(None)?;

                seq.serialize_element(&**a)?;

                let mut b = b.clone();

                while let Self::Cell(left, right) = &*b {
                    seq.serialize_element(&**left)?;
                    b = right.clone();
                }

                seq.serialize_element(&*b)?;

                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Noun {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Noun;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("atom or cell")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let n = UBig::from_str_radix(s, 16).map_err(E::custom)?;
                Ok(Noun::Atom(n))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut stack = Vec::new();

                while let Some(noun) = seq.next_element::<Noun>()? {
                    stack.push(noun);
                }

                if stack.len() < 2 {
                    return Err(DeError::custom("expected at least 2 elements"));
                }

                let mut top = stack.pop().ok_or_else(|| DeError::custom("empty cell"))?;

                while let Some(noun) = stack.pop() {
                    top = Noun::Cell(noun.into(), top.into());
                }

                Ok(top)
            }
        }

        de.deserialize_any(V)
    }
}

pub trait NounCode: NounEncode + NounDecode {}
impl<T: NounEncode + NounDecode> NounCode for T {}

pub trait NounEncode {
    fn to_noun(&self) -> Noun;
}

pub trait NounDecode: Sized {
    fn from_noun(noun: &Noun) -> Option<Self>;
}

fn atom(value: u64) -> Noun {
    Noun::Atom(UBig::from(value))
}

fn cons(left: Noun, right: Noun) -> Noun {
    Noun::Cell(left.into(), right.into())
}

impl<T: NounEncode + ?Sized> NounEncode for &T {
    fn to_noun(&self) -> Noun {
        (**self).to_noun()
    }
}

impl<T: NounEncode + ?Sized> NounEncode for Arc<T> {
    fn to_noun(&self) -> Noun {
        (**self).to_noun()
    }
}

impl<T: NounDecode> NounDecode for Arc<T> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        Some(Arc::new(T::from_noun(noun)?))
    }
}

impl<T: NounEncode + ?Sized> NounEncode for Box<T> {
    fn to_noun(&self) -> Noun {
        (**self).to_noun()
    }
}

impl<T: NounDecode> NounDecode for Box<T> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        Some(Box::new(T::from_noun(noun)?))
    }
}

impl NounEncode for Noun {
    fn to_noun(&self) -> Noun {
        self.clone()
    }
}

impl NounDecode for Noun {
    fn from_noun(noun: &Noun) -> Option<Self> {
        Some(noun.clone())
    }
}

impl NounEncode for () {
    fn to_noun(&self) -> Noun {
        atom(0)
    }
}

impl NounDecode for () {
    fn from_noun(noun: &Noun) -> Option<Self> {
        if *noun == atom(0) {
            Some(())
        } else {
            None
        }
    }
}

impl NounEncode for Belt {
    fn to_noun(&self) -> Noun {
        atom(self.0)
    }
}

impl NounDecode for Belt {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let Noun::Atom(a) = noun else {
            return None;
        };
        let v = u64::try_from(a).ok()?;
        if based_check(v) {
            Some(Belt(v))
        } else {
            None
        }
    }
}

impl NounEncode for Digest {
    fn to_noun(&self) -> Noun {
        self.0.to_noun()
    }
}

impl NounDecode for Digest {
    fn from_noun(noun: &Noun) -> Option<Self> {
        Some(Digest(<[Belt; 5]>::from_noun(noun)?))
    }
}

impl NounEncode for CheetahPoint {
    fn to_noun(&self) -> Noun {
        (self.x.0, self.y.0, self.inf).to_noun()
    }
}

impl NounDecode for CheetahPoint {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (x, y, inf) = NounDecode::from_noun(noun)?;
        Some(Self {
            x: F6lt(x),
            y: F6lt(y),
            inf,
        })
    }
}

macro_rules! impl_nounable_for_int {
    ($($ty:ty),* $(,)?) => {
        $(
            impl NounEncode for $ty {
                fn to_noun(&self) -> Noun {
                    atom(*self as u64)
                }
            }

            impl NounDecode for $ty {
                fn from_noun(noun: &Noun) -> Option<$ty> {
                    let Noun::Atom(a) = noun else {
                        return None;
                    };
                    <$ty>::try_from(a).ok()
                }
            }
        )*
    };
}

impl_nounable_for_int!(i32, i64, isize, u32, u64, usize);

impl NounEncode for bool {
    fn to_noun(&self) -> Noun {
        atom(if *self { 0 } else { 1 })
    }
}

impl NounDecode for bool {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let Noun::Atom(a) = noun else {
            return None;
        };
        if a == &UBig::from(0u64) {
            Some(true)
        } else if a == &UBig::from(1u64) {
            Some(false)
        } else {
            None
        }
    }
}

impl<T: NounEncode> NounEncode for Option<T> {
    fn to_noun(&self) -> Noun {
        match self {
            None => atom(0),
            Some(value) => (0, value.to_noun()).to_noun(),
        }
    }
}

impl<T: NounDecode> NounDecode for Option<T> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        match noun {
            Noun::Cell(x, v) if **x == atom(0) => Some(Some(T::from_noun(v)?)),
            Noun::Atom(x) if x.is_zero() => Some(None),
            _ => None,
        }
    }
}

impl<T: NounEncode> NounEncode for Zeroable<T> {
    fn to_noun(&self) -> Noun {
        match &self.0 {
            None => atom(0),
            Some(value) => value.to_noun(),
        }
    }
}

impl<T: NounDecode> NounDecode for Zeroable<T> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        match noun {
            Noun::Atom(x) if x.is_zero() => Some(Zeroable(None)),
            Noun::Atom(_) => None,
            v => Some(Zeroable(Some(T::from_noun(v)?))),
        }
    }
}

macro_rules! impl_nounable_for_tuple {
    ($T0:ident => $i0:ident) => {};
    ($T:ident => $t:ident $( $U:ident => $u:ident )+) => {
        impl<$T: NounEncode, $($U: NounEncode),*> NounEncode for ($T, $($U),*) {
            fn to_noun(&self) -> Noun {
                let ($t, $($u),*) = self;
                cons($t.to_noun(), ($($u),*).to_noun())
            }
        }

        impl<$T: NounDecode, $($U: NounDecode),*> NounDecode for ($T, $($U),*) {
            fn from_noun(noun: &Noun) -> Option<($T, $($U),*)> {
                let Noun::Cell(a, b) = noun else {
                    return None;
                };
                let a = <$T>::from_noun(a)?;
                #[allow(unused_parens)]
                let ($($u),*) = <($($U),*)>::from_noun(b)?;
                Some((a, $($u),*))
            }
        }

        impl_nounable_for_tuple!($($U => $u)*);
    };
}

impl_nounable_for_tuple!(
    A => a
    B => b
    C => c
    D => d
    E => e
    F => f
    G => g
    H => h
    I => i
    J => j
    K => k
    L => l
    M => m
    N => n
    O => o
    P => p
    Q => q
    R => r
    S => s
    T => t
);

impl<T: NounEncode, const N: usize> NounEncode for [T; N] {
    fn to_noun(&self) -> Noun {
        match self.split_last() {
            None => self[0].to_noun(),
            Some((last, rest)) => {
                let mut acc = last.to_noun();
                for item in rest.iter().rev() {
                    acc = cons(item.to_noun(), acc);
                }
                acc
            }
        }
    }
}

impl<T: NounDecode, const N: usize> NounDecode for [T; N] {
    fn from_noun(mut noun: &Noun) -> Option<Self> {
        let mut ret: [Option<T>; N] = [(); N].map(|_| None);
        for (i, item) in ret.iter_mut().enumerate() {
            let decode = match noun {
                Noun::Cell(a, b) => {
                    noun = b;
                    a
                }
                v if i == N - 1 => v,
                _ => return None,
            };
            *item = Some(T::from_noun(decode)?);
        }

        Some(ret.map(|v| v.unwrap()))
    }
}

impl<T: NounEncode> NounEncode for &[T] {
    fn to_noun(&self) -> Noun {
        match self.split_last() {
            None => atom(0),
            Some((last, rest)) => {
                let mut acc = last.to_noun();
                for item in rest.iter().rev() {
                    acc = cons(item.to_noun(), acc);
                }
                acc
            }
        }
    }
}

impl<T: NounEncode> NounEncode for Vec<T> {
    fn to_noun(&self) -> Noun {
        let mut acc = atom(0);
        for item in self.iter().rev() {
            acc = cons(item.to_noun(), acc);
        }
        acc
    }
}

impl<T: NounDecode> NounDecode for Vec<T> {
    fn from_noun(mut noun: &Noun) -> Option<Self> {
        let mut ret = vec![];
        loop {
            match noun {
                Noun::Cell(a, b) => {
                    ret.push(T::from_noun(a)?);
                    noun = b;
                }
                Noun::Atom(v) => {
                    if v.is_zero() {
                        return Some(ret);
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}

impl NounEncode for &str {
    fn to_noun(&self) -> Noun {
        Noun::Atom(UBig::from_le_bytes(self.as_bytes()))
    }
}

impl NounEncode for String {
    fn to_noun(&self) -> Noun {
        self.as_str().to_noun()
    }
}

impl NounDecode for String {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let Noun::Atom(a) = noun else {
            return None;
        };
        String::from_utf8(a.to_le_bytes()).ok()
    }
}

/// Jam a noun into bytes vec
pub fn jam(noun: Noun) -> Vec<u8> {
    fn met0_u64_to_usize(value: u64) -> usize {
        (u64::BITS - value.leading_zeros()) as usize
    }

    fn met0_atom(atom: &UBig) -> usize {
        atom.bit_len()
    }

    fn mat_backref(writer: &mut BitWriter, backref: usize) {
        if backref == 0 {
            writer.write_bits_from_value(0b111, 3); // 1 1 1
            return;
        }
        let backref_sz = met0_u64_to_usize(backref as u64);
        let backref_sz_sz = met0_u64_to_usize(backref_sz as u64);
        // backref tag 1 1
        writer.write_bit(true);
        writer.write_bit(true);
        // write backref_sz_sz zeros
        writer.write_zeros(backref_sz_sz);
        // delimiter 1
        writer.write_bit(true);
        // write backref_sz_sz-1 bits of backref_sz (LSB first)
        writer.write_bits_from_value(backref_sz, backref_sz_sz - 1);
        // write backref bits (backref_sz bits)
        writer.write_bits_from_value(backref, backref_sz);
    }

    fn mat_atom(writer: &mut BitWriter, atom: &UBig) {
        if atom.is_zero() {
            writer.write_bits_from_value(0b10, 2); // 0 1
            return;
        }
        let atom_sz = met0_atom(atom);
        let atom_sz_sz = met0_u64_to_usize(atom_sz as u64);
        writer.write_bit(false); // atom tag 0
        writer.write_zeros(atom_sz_sz); // size zeros
        writer.write_bit(true); // delimiter
                                // write size bits (atom_sz_sz - 1)
        writer.write_bits_from_value(atom_sz, atom_sz_sz - 1);
        // write atom bits (little-endian order)
        writer.write_bits_from_le_bytes(&atom.to_le_bytes(), atom_sz);
    }

    fn find_backref(
        backrefs: &BTreeMap<(u32, u32), Vec<(Noun, usize)>>,
        weight: u32,
        mug: u32,
        target: &Noun,
    ) -> Option<usize> {
        backrefs
            .get(&(weight, mug))
            .and_then(|vec| vec.iter().find(|(n, _)| n == target))
            .map(|(_, offset)| *offset)
    }

    let mut backrefs: BTreeMap<(u32, u32), Vec<(Noun, usize)>> = BTreeMap::new();
    let mut stack = Vec::new();
    stack.push((weight_noun(&noun), mug_noun(&noun), noun));
    let mut buffer = BitWriter::new();

    while let Some((weight, mug, current)) = stack.pop() {
        if let Some(backref) = find_backref(&backrefs, weight, mug, &current) {
            match &current {
                Noun::Atom(atom) => {
                    if met0_u64_to_usize(backref as u64) < met0_atom(atom) {
                        mat_backref(&mut buffer, backref);
                    } else {
                        mat_atom(&mut buffer, atom);
                    }
                }
                Noun::Cell(_, _) => {
                    mat_backref(&mut buffer, backref);
                }
            }
        } else {
            let offset = buffer.bit_len();
            backrefs
                .entry((weight, mug))
                .or_default()
                .push((current.clone(), offset));
            match current {
                Noun::Atom(atom) => {
                    mat_atom(&mut buffer, &atom);
                }
                Noun::Cell(left, right) => {
                    buffer.write_bit(true);
                    buffer.write_bit(false);
                    stack.push((right.0.weight, right.0.mug, (*right).clone()));
                    stack.push((left.0.weight, left.0.mug, (*left).clone()));
                }
            }
        }
    }

    buffer.into_vec()
}

/// Cue jammed bytes into Noun (see `jam`)
pub fn cue(bytes: &[u8]) -> Option<Noun> {
    cue_bitslice(BitSlice::from_slice(bytes))
}

pub fn cue_bitslice(buffer: &BitSlice<u8, Lsb0>) -> Option<Noun> {
    #[derive(Copy, Clone)]
    enum CueStackEntry {
        DestinationPointer(*mut Noun),
        BackRef(u64, *mut Noun),
    }

    pub fn next_up_to_n_bits<'a>(
        cursor: &mut usize,
        slice: &'a BitSlice<u8, Lsb0>,
        n: usize,
    ) -> &'a BitSlice<u8, Lsb0> {
        let res = if (slice).len() >= *cursor + n {
            &slice[*cursor..*cursor + n]
        } else if slice.len() > *cursor {
            &slice[*cursor..]
        } else {
            BitSlice::<u8, Lsb0>::empty()
        };
        *cursor += n;
        res
    }

    pub fn rest_bits(cursor: usize, slice: &BitSlice<u8, Lsb0>) -> &BitSlice<u8, Lsb0> {
        if slice.len() > cursor {
            &slice[cursor..]
        } else {
            BitSlice::<u8, Lsb0>::empty()
        }
    }

    fn get_size(cursor: &mut usize, buffer: &BitSlice<u8, Lsb0>) -> Option<usize> {
        let buff_at_cursor = rest_bits(*cursor, buffer);
        let bitsize = buff_at_cursor.first_one()?;
        if bitsize == 0 {
            *cursor += 1;
            Some(0)
        } else {
            let mut size = [0u8; 8];
            *cursor += bitsize + 1;
            let size_bits = next_up_to_n_bits(cursor, buffer, bitsize - 1);
            BitSlice::from_slice_mut(&mut size)[0..bitsize - 1].copy_from_bitslice(size_bits);
            Some((u64::from_le_bytes(size) as usize) + (1 << (bitsize - 1)))
        }
    }

    fn rub_backref(cursor: &mut usize, buffer: &BitSlice<u8, Lsb0>) -> Option<u64> {
        // TODO: What's size here usually?
        let size = get_size(cursor, buffer)?;
        if size == 0 {
            Some(0)
        } else if size <= 64 {
            // TODO: Size <= 64, so we can fit the backref in a direct atom?
            let mut backref = [0u8; 8];
            BitSlice::from_slice_mut(&mut backref)[0..size]
                .copy_from_bitslice(&buffer[*cursor..*cursor + size]);
            *cursor += size;
            Some(u64::from_le_bytes(backref))
        } else {
            None
        }
    }

    fn rub_atom(cursor: &mut usize, buffer: &BitSlice<u8, Lsb0>) -> Option<UBig> {
        let size = get_size(cursor, buffer)?;
        let bits = next_up_to_n_bits(cursor, buffer, size);
        if size == 0 {
            Some(UBig::from(0u64))
        } else if size < 64 {
            // Fits in a direct atom
            let mut direct_raw = [0u8; 8];
            BitSlice::from_slice_mut(&mut direct_raw)[0..bits.len()].copy_from_bitslice(bits);
            Some(UBig::from(u64::from_le_bytes(direct_raw)))
        } else {
            // Need an indirect atom
            let wordsize = (size + 63) >> 6;
            let mut bytes = vec![0u8; wordsize * 8];
            BitSlice::from_slice_mut(&mut bytes)[0..bits.len()].copy_from_bitslice(bits);
            Some(UBig::from_le_bytes(&bytes))
        }
    }

    pub fn next_bit(cursor: &mut usize, slice: &BitSlice<u8, Lsb0>) -> bool {
        if (*slice).len() > *cursor {
            let res = slice[*cursor];
            *cursor += 1;
            res
        } else {
            false
        }
    }

    let mut backref_map = BTreeMap::<u64, *mut Noun>::new();
    let mut result = atom(0);
    let mut cursor = 0;

    let mut cue_stack = vec![];

    cue_stack.push(CueStackEntry::DestinationPointer(&mut result as *mut Noun));

    while let Some(stack_entry) = cue_stack.pop() {
        unsafe {
            // Capture the destination pointer and pop it off the stack
            match stack_entry {
                CueStackEntry::DestinationPointer(dest_ptr) => {
                    // 1 bit
                    if next_bit(&mut cursor, buffer) {
                        // 11 tag: backref
                        if next_bit(&mut cursor, buffer) {
                            let backref = rub_backref(&mut cursor, buffer)?;
                            *dest_ptr = (**backref_map.get(&backref)?).clone();
                        } else {
                            // 10 tag: cell
                            let head = HashNoun::from(atom(0));
                            let head_ptr = Arc::as_ptr(&head.0) as *mut _;
                            let tail = HashNoun::from(atom(0));
                            let tail_ptr = Arc::as_ptr(&tail.0) as *mut _;
                            *dest_ptr = Noun::Cell(head, tail);
                            let backref = (cursor - 2) as u64;
                            backref_map.insert(backref, dest_ptr);
                            cue_stack.push(CueStackEntry::BackRef(cursor as u64 - 2, dest_ptr));
                            cue_stack.push(CueStackEntry::DestinationPointer(tail_ptr));
                            cue_stack.push(CueStackEntry::DestinationPointer(head_ptr));
                        }
                    } else {
                        // 0 tag: atom
                        let backref: u64 = (cursor - 1) as u64;
                        *dest_ptr = Noun::Atom(rub_atom(&mut cursor, buffer)?);
                        backref_map.insert(backref, dest_ptr);
                    }
                }
                CueStackEntry::BackRef(backref, noun_ptr) => {
                    backref_map.insert(backref, noun_ptr);
                }
            }
        }
    }

    Some(result)
}

// Fast bit writer that appends bits LSB-first into an underlying Vec<u8>
pub struct BitWriter {
    buf: Vec<u8>,   // final byte buffer (little-endian bit order per byte)
    acc: u8,        // in-progress byte accumulator
    nbits: u8,      // number of bits currently stored in `acc` (0-7)
    bit_len: usize, // total number of bits written so far
}
impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl BitWriter {
    #[inline]
    pub fn new() -> Self {
        BitWriter {
            buf: Vec::with_capacity(1024),
            acc: 0,
            nbits: 0,
            bit_len: 0,
        }
    }

    #[inline]
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    #[inline]
    pub fn write_bit(&mut self, bit: bool) {
        if bit {
            self.acc |= 1 << self.nbits;
        }
        self.nbits += 1;
        self.bit_len += 1;
        if self.nbits == 8 {
            self.flush_acc();
        }
    }

    #[inline]
    pub fn write_zeros(&mut self, count: usize) {
        // produce `count` zero bits quickly
        // Fill partial acc first
        let mut remaining = count;
        if self.nbits != 0 {
            let space = 8 - self.nbits;
            if remaining < space as usize {
                // // just bump counters – acc already contains zeros in high bits
                // self.nbits += remaining as u8;
                // self.bit_len += remaining;
                // return;
                // keep the valid low bits we already had, clear the bits we are about to add
                let mask = (1u16 << self.nbits) - 1; // e.g. nbits = 3  -> 0b00000111
                self.acc &= mask as u8; // zero out bits [self.nbits .. 7]

                // now bump the cursors exactly as before
                self.nbits += remaining as u8;
                self.bit_len += remaining;
                return;
            } else {
                // fill acc with zeros and flush
                // self.nbits = 8;
                // self.bit_len += space as usize;
                // remaining -= space as usize;
                // zero-fill high bits we are about to claim
                let mask = (1u16 << self.nbits) - 1; // keep the `nbits` low bits
                self.acc &= mask as u8; // clear [self.nbits .. 7]

                // now top-off the byte and flush
                self.nbits = 8;
                self.bit_len += space as usize;
                remaining -= space as usize;
                self.flush_acc();
            }
        }
        // Now we are byte-aligned
        let full_bytes = remaining / 8;
        if full_bytes > 0 {
            self.buf.extend(core::iter::repeat_n(0u8, full_bytes));
            self.bit_len += full_bytes * 8;
            remaining -= full_bytes * 8;
        }
        // Remaining < 8, leave in acc (which is zero)
        self.nbits = remaining as u8;
        self.acc = 0; // already zero
        self.bit_len += remaining;
    }

    #[inline]
    pub fn write_bits_from_value(&mut self, mut value: usize, count: usize) {
        for _ in 0..count {
            self.write_bit((value & 1) == 1);
            value >>= 1;
        }
    }

    #[inline]
    pub fn write_bits_from_le_bytes(&mut self, bytes: &[u8], total_bits: usize) {
        if total_bits == 0 {
            return;
        }

        let full_bytes = total_bits / 8;
        let rem_bits: usize = total_bits % 8;

        if self.nbits == 0 {
            // Aligned path: copy full bytes directly
            if full_bytes > 0 {
                self.buf.extend_from_slice(&bytes[..full_bytes]);
                self.bit_len += full_bytes * 8;
            }
        } else if full_bytes > 0 {
            // Unaligned path: merge each byte with current accumulator
            let shift = self.nbits;
            let mut carry = self.acc;
            for &byte in &bytes[..full_bytes] {
                let combined = carry | (byte << shift);
                self.buf.push(combined);
                self.bit_len += 8;
                carry = byte >> (8 - shift);
            }
            self.acc = carry;
            // note: nbits unchanged
        }

        // Handle remaining bits (<8) from the next byte
        if rem_bits > 0 {
            let src_byte = if full_bytes < bytes.len() {
                bytes[full_bytes]
            } else {
                0
            };
            for i in 0..rem_bits {
                self.write_bit(((src_byte >> i) & 1) == 1);
            }
        }
        // Update bit_len to reflect the total number of bits written so far
        // This didn't work.
        // self.bit_len = self.buf.len() * 8 + self.nbits as usize;
    }

    #[inline]
    pub fn flush_acc(&mut self) {
        if self.nbits == 0 {
            return;
        }
        self.buf.push(self.acc);
        self.acc = 0;
        self.nbits = 0;
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            // Flush final partial byte (upper bits remain 0)
            self.flush_acc();
        }
        self.buf
    }
}
