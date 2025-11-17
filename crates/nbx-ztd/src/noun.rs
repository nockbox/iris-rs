use alloc::{boxed::Box, collections::btree_map::BTreeMap, format, string::String, vec, vec::Vec};
use bitvec::prelude::{BitSlice, BitVec, Lsb0};
use core::fmt;
use ibig::UBig;
use num_traits::Zero;

use crate::{belt::Belt, crypto::cheetah::CheetahPoint, Digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Noun {
    Atom(UBig),
    Cell(Box<Noun>, Box<Noun>),
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

impl NounEncode for Belt {
    fn to_noun(&self) -> Noun {
        atom(self.0)
    }
}

impl NounEncode for Digest {
    fn to_noun(&self) -> Noun {
        self.0.as_slice().to_noun()
    }
}

impl NounEncode for CheetahPoint {
    fn to_noun(&self) -> Noun {
        (self.x.0.as_slice(), (self.y.0.as_slice(), self.inf)).to_noun()
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
        )*
    };
}

impl_nounable_for_int!(i32, i64, isize, u32, u64, usize);

impl NounEncode for bool {
    fn to_noun(&self) -> Noun {
        atom(if *self { 0 } else { 1 })
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

impl<A: NounEncode, B: NounEncode> NounEncode for (A, B) {
    fn to_noun(&self) -> Noun {
        cons(self.0.to_noun(), self.1.to_noun())
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
                            let mut head = Box::new(atom(0));
                            let head_ptr = (&mut *head) as *mut _;
                            let mut tail = Box::new(atom(0));
                            let tail_ptr = (&mut *tail) as *mut _;
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

    Some(Noun::try_from(result).ok().unwrap())
}
