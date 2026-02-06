use crate::belt::based_check;
use crate::crypto::cheetah::F6lt;
#[cfg(feature = "wasm")]
use alloc::string::ToString;
use alloc::{
    boxed::Box, collections::btree_map::BTreeMap, format, string::String, sync::Arc, vec, vec::Vec,
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(
    feature = "wasm",
    tsify(into_wasm_abi, from_wasm_abi, type = "string | [Noun]")
)]
pub enum Noun {
    Atom(UBig),
    Cell(Arc<Noun>, Arc<Noun>),
}

impl ToString for Noun {
    fn to_string(&self) -> String {
        fn autocons(cell: &Noun) -> String {
            match cell {
                Noun::Atom(a) => format!("{}", a),
                Noun::Cell(head, tail) => match &**tail {
                    Noun::Cell(_, _) => format!("{} {}", autocons(head), autocons(tail)),
                    Noun::Atom(a) if a.is_zero() => autocons(head),
                    Noun::Atom(_) => format!("{} . {}", autocons(head), autocons(tail)),
                },
            }
        }

        match self {
            Noun::Atom(a) => format!("{}", a),
            Noun::Cell(head, tail) => {
                format!("[{}]", autocons(&Noun::Cell(head.clone(), tail.clone())))
            }
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

                seq.serialize_element(&*a)?;

                let mut b = b.clone();

                while let Self::Cell(left, right) = b.as_ref() {
                    seq.serialize_element(&*left)?;
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
                    top = Noun::Cell(Arc::new(noun), Arc::new(top));
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
    Noun::Cell(Arc::new(left), Arc::new(right))
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
);

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
                    stack.push((*right).clone());
                    stack.push((*left).clone());
                }
            }
        }
    }

    buffer.into_vec()
}

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
                            let head = Arc::new(atom(0));
                            let head_ptr = Arc::as_ptr(&head) as *mut _;
                            let tail = Arc::new(atom(0));
                            let tail_ptr = Arc::as_ptr(&tail) as *mut _;
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
