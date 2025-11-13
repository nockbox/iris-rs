use alloc::collections::btree_map::BTreeMap;
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use bitvec::prelude::{BitSlice, BitVec, Lsb0};
use core::fmt;
use core::mem::MaybeUninit;
use ibig::UBig;
use num_traits::Zero;
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{ser::SerializeTuple, Serialize, Serializer};
use serde::{Deserialize, Deserializer};

use crate::belt::based_check;
use crate::{belt::Belt, crypto::cheetah::CheetahPoint, Digest};

/// A noun that may not be fully initialized yet
///
/// NOTE: it is critical that this noun type has compatible representation as Noun
#[derive(Clone, Debug)]
#[repr(C, u8)]
enum MaybeNoun {
    #[allow(dead_code)]
    Atom(UBig),
    Cell(Box<MaybeNoun>, Box<MaybeNoun>),
    Uninitialized,
}

impl From<Noun> for MaybeNoun {
    fn from(value: Noun) -> Self {
        unsafe { core::mem::transmute(value) }
    }
}

impl TryFrom<MaybeNoun> for Noun {
    type Error = ();

    fn try_from(value: MaybeNoun) -> Result<Self, Self::Error> {
        let mut stack = vec![&value];

        while let Some(e) = stack.pop() {
            match e {
                MaybeNoun::Uninitialized => return Err(()),
                MaybeNoun::Atom(_) => continue,
                MaybeNoun::Cell(a, b) => {
                    stack.push(&*a);
                    stack.push(&*b);
                }
            }
        }

        Ok(unsafe { core::mem::transmute(value) })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C, u8)]
pub enum Noun {
    Atom(UBig),
    Cell(Box<Noun>, Box<Noun>),
}

impl Serialize for Noun {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Atom(v) => serializer.serialize_str(&alloc::format!("{v:x}")),
            Self::Cell(a, b) => {
                let mut tup = serializer.serialize_tuple(2)?;
                tup.serialize_element(&*a)?;
                tup.serialize_element(&*b)?;
                tup.end()
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
                let a = seq
                    .next_element::<Noun>()?
                    .ok_or_else(|| DeError::custom("cell missing car"))?;
                let b = seq
                    .next_element::<Noun>()?
                    .ok_or_else(|| DeError::custom("cell missing cdr"))?;
                Ok(Noun::Cell(Box::new(a), Box::new(b)))
            }
        }

        de.deserialize_any(V)
    }
}

impl Noun {
    pub fn to_string(&self) -> String {
        match self {
            Noun::Atom(a) => format!("{}", a),
            Noun::Cell(left, right) => format!("[{} {}]", left.to_string(), right.to_string()),
        }
    }
}

impl fmt::Display for Noun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

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
    Noun::Cell(Box::new(left), Box::new(right))
}

impl<T: NounEncode + ?Sized> NounEncode for &T {
    fn to_noun(&self) -> Noun {
        (**self).to_noun()
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
        (self.x.0, (self.y.0, self.inf)).to_noun()
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
            Noun::Cell(x, v) if &**x == &atom(0) => Some(Some(T::from_noun(v)?)),
            Noun::Atom(x) if x.is_zero() => Some(None),
            _ => None,
        }
    }
}

impl<A: NounEncode, B: NounEncode> NounEncode for (A, B) {
    fn to_noun(&self) -> Noun {
        cons(self.0.to_noun(), self.1.to_noun())
    }
}

impl<A: NounDecode, B: NounDecode> NounDecode for (A, B) {
    fn from_noun(noun: &Noun) -> Option<(A, B)> {
        let Noun::Cell(a, b) = noun else {
            return None;
        };
        Some((A::from_noun(a)?, B::from_noun(b)?))
    }
}

impl<T: NounEncode, const N: usize> NounEncode for [T; N] {
    fn to_noun(&self) -> Noun {
        match self.split_last() {
            None => unreachable!(),
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
        let mut ret = [(); N].map(|_| MaybeUninit::<T>::uninit());
        for i in 0..N {
            let Noun::Cell(a, b) = noun else {
                return None;
            };
            ret[i] = MaybeUninit::<T>::new(T::from_noun(a)?);
            noun = b;
        }

        // SAFETY: already initialized everything
        Some(ret.map(|v| unsafe { v.assume_init() }))
    }
}

// TODO: always append ~ at the end
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
        atom(
            self.bytes()
                .enumerate()
                .fold(0u64, |acc, (i, byte)| acc | ((byte as u64) << (i * 8))),
        )
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

pub fn cue(bytes: &[u8]) -> Option<Noun> {
    cue_bitslice(BitSlice::from_slice(bytes))
}

pub fn cue_bitslice(buffer: &BitSlice<u8, Lsb0>) -> Option<Noun> {
    #[derive(Copy, Clone)]
    enum CueStackEntry {
        DestinationPointer(*mut MaybeNoun),
        BackRef(u64, *mut MaybeNoun),
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
            BitSlice::from_slice_mut(&mut bytes).copy_from_bitslice(bits);
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

    let mut backref_map = BTreeMap::<u64, *mut MaybeNoun>::new();
    let mut result = MaybeNoun::Atom(0u64.into());
    let mut cursor = 0;

    let mut cue_stack = vec![];

    cue_stack.push(CueStackEntry::DestinationPointer(
        &mut result as *mut MaybeNoun,
    ));

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
                            let mut head = Box::new(MaybeNoun::Uninitialized);
                            let head_ptr = (&mut *head) as *mut _;
                            let mut tail = Box::new(MaybeNoun::Uninitialized);
                            let tail_ptr = (&mut *tail) as *mut _;
                            *dest_ptr = MaybeNoun::Cell(head, tail);
                            let backref = (cursor - 2) as u64;
                            backref_map.insert(backref, dest_ptr);
                            cue_stack.push(CueStackEntry::BackRef(cursor as u64 - 2, dest_ptr));
                            cue_stack.push(CueStackEntry::DestinationPointer(tail_ptr));
                            cue_stack.push(CueStackEntry::DestinationPointer(head_ptr));
                        }
                    } else {
                        // 0 tag: atom
                        let backref: u64 = (cursor - 1) as u64;
                        *dest_ptr = MaybeNoun::Atom(rub_atom(&mut cursor, buffer)?);
                        backref_map.insert(backref, dest_ptr);
                    }
                }
                CueStackEntry::BackRef(backref, noun_ptr) => {
                    backref_map.insert(backref, noun_ptr);
                }
            }
        }
    }

    Some(Noun::try_from(result).ok().unwrap())
}

pub fn jam(noun: Noun) -> Vec<u8> {
    fn met0_u64_to_usize(value: u64) -> usize {
        (u64::BITS - value.leading_zeros()) as usize
    }

    fn met0_atom(atom: &UBig) -> usize {
        atom.bit_len()
    }

    fn mat_backref(buffer: &mut BitVec<u8, Lsb0>, backref: usize) {
        if backref == 0 {
            buffer.push(true);
            buffer.push(true);
            buffer.push(true);
            return;
        }
        let backref_sz = met0_u64_to_usize(backref as u64);
        let backref_sz_sz = met0_u64_to_usize(backref_sz as u64);
        buffer.push(true);
        buffer.push(true);
        let buffer_len = buffer.len();
        buffer.resize(buffer_len + backref_sz_sz, false);
        buffer.push(true);
        let size_bits = BitSlice::<usize, Lsb0>::from_element(&backref_sz);
        buffer.extend_from_bitslice(&size_bits[..backref_sz_sz - 1]);
        let backref_bits = BitSlice::<usize, Lsb0>::from_element(&backref);
        buffer.extend_from_bitslice(&backref_bits[..backref_sz]);
    }

    fn mat_atom(buffer: &mut BitVec<u8, Lsb0>, atom: &UBig) {
        if atom.is_zero() {
            buffer.push(false);
            buffer.push(true);
            return;
        }
        let atom_sz = met0_atom(atom);
        let atom_sz_sz = met0_u64_to_usize(atom_sz as u64);
        buffer.push(false);
        let buffer_len = buffer.len();
        buffer.resize(buffer_len + atom_sz_sz, false);
        buffer.push(true);
        let size_bits = BitSlice::<usize, Lsb0>::from_element(&atom_sz);
        buffer.extend_from_bitslice(&size_bits[..atom_sz_sz - 1]);
        let atom_bytes = atom.to_le_bytes();
        let atom_bits = BitSlice::<u8, Lsb0>::from_slice(&atom_bytes);
        buffer.extend_from_bitslice(&atom_bits[..atom_sz]);
    }

    fn find_backref(backrefs: &[(Noun, usize)], target: &Noun) -> Option<usize> {
        backrefs
            .iter()
            .find(|(noun, _)| noun == target)
            .map(|(_, offset)| *offset)
    }

    let mut backrefs: Vec<(Noun, usize)> = Vec::new();
    let mut stack = Vec::new();
    stack.push(noun);
    let mut buffer = BitVec::<u8, Lsb0>::new();

    while let Some(current) = stack.pop() {
        if let Some(backref) = find_backref(&backrefs, &current) {
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
            let offset = buffer.len();
            backrefs.push((current.clone(), offset));
            match current {
                Noun::Atom(atom) => {
                    mat_atom(&mut buffer, &atom);
                }
                Noun::Cell(left, right) => {
                    buffer.push(true);
                    buffer.push(false);
                    stack.push(*right);
                    stack.push(*left);
                }
            }
        }
    }

    buffer.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jam_0() {
        assert_eq!(jam(Noun::Atom(0u64.into())), [2]);
    }

    #[test]
    fn cue_0() {
        assert_eq!(cue(&[2]), Some(Noun::Atom(0u64.into())));
    }

    fn test_lock() -> Noun {
        (&[
            0.to_noun(),
            (&[
                6843248.to_noun(),
                1.to_noun(),
                (&[
                    17029647531805300191u64,
                    4174156824641024642,
                    5496717911288638641,
                    13599954738724847117,
                    7293187711808680100,
                ][..])
                    .to_noun(),
                0.to_noun(),
                0.to_noun(),
            ][..])
                .to_noun(),
            0.to_noun(),
        ][..])
            .to_noun()
    }

    #[test]
    fn jamque() {
        let test = test_lock();
        assert_eq!(cue(&jam(test.clone())), Some(test));
    }

    #[test]
    fn cue_lock() {
        let lock_hex = "54e5369b953a99b0a4fc05e5e5f63bd8adf068100662421e8a2717658fe01e7b65610c600ca0bd00f62abb1a03ae6aef81005c7435b83c059";
        let lock = UBig::from_str_radix(lock_hex, 16).unwrap();
        assert_eq!(cue(&lock.to_le_bytes()), Some(test_lock()));
    }
}
