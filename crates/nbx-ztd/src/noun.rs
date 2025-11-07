use alloc::{boxed::Box, string::String, vec::Vec};
use bitvec::prelude::{BitSlice, BitVec, Lsb0};
use ibig::UBig;
use num_traits::Zero;

use crate::{belt::Belt, crypto::cheetah::CheetahPoint, Digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Noun {
    Atom(UBig),
    Cell(Box<Noun>, Box<Noun>),
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

impl<T: NounEncode> NounEncode for &T {
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
