use alloc::boxed::Box;
use alloc::{vec, vec::Vec};

use crate::belt::{Belt, PRIME};
use crate::tip5::hash::{hash_fixed, hash_varlen};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest(pub [Belt; 5]);

impl From<[u64; 5]> for Digest {
    fn from(belts: [u64; 5]) -> Self {
        Digest(belts.map(|b| Belt(b)))
    }
}

impl Digest {
    pub fn to_bytes(&self) -> [u8; 40] {
        use ibig::UBig;

        let p = UBig::from(PRIME);
        let p2 = &p * &p;
        let p3 = &p * &p2;
        let p4 = &p * &p3;

        let [a, b, c, d, e] = self.0.map(|b| UBig::from(b.0));
        let res = a + b * &p + c * p2 + d * p3 + e * p4;

        let mut bytes = [0u8; 40];
        let res_bytes = res.to_be_bytes();
        bytes[40 - res_bytes.len()..].copy_from_slice(&res_bytes);
        bytes
    }
}

pub fn to_b58(bytes: &[u8]) -> Vec<u8> {
    bs58::encode(bytes).into_vec()
}

pub fn from_b58(s: &str) -> Vec<u8> {
    bs58::decode(s).into_vec().unwrap()
}

pub fn hash_noun(leaves: &[Belt], dyck: &[Belt]) -> Digest {
    let mut combined = Vec::with_capacity(1 + leaves.len() + dyck.len());
    combined.push(Belt(leaves.len() as u64));
    combined.extend_from_slice(leaves);
    combined.extend_from_slice(dyck);
    Digest(hash_varlen(&mut combined).map(|u| Belt(u)))
}

pub fn hash_belt(input: Belt) -> Digest {
    hash_noun(&vec![input], &vec![])
}

pub fn hash_belt_list(input: &[Belt]) -> Digest {
    let mut leaves = Vec::with_capacity(input.len() + 1);
    leaves.extend_from_slice(input);
    leaves.push(Belt(0));

    let mut dyck = Vec::new();
    for _ in input {
        dyck.push(Belt(0));
        dyck.push(Belt(1));
    }

    hash_noun(&leaves, &dyck)
}

pub fn hash_hash_list(input: &[Digest]) -> Digest {
    let mut leaves = Vec::new();
    for h in input {
        leaves.extend_from_slice(&h.0);
    }
    leaves.push(Belt(0));

    let mut dyck = Vec::new();
    for _ in input {
        dyck.push(Belt(0));
        for _ in 0..4 {
            dyck.push(Belt(0));
            dyck.push(Belt(1));
        }
        dyck.push(Belt(1));
    }

    hash_noun(&leaves, &dyck)
}

/// Hashable DSL for tip5 hashing
#[derive(Debug, Clone)]
pub enum Hashable {
    Leaf(Belt),
    Hash(Digest),
    List(Vec<Hashable>),
    Cell(Box<Hashable>, Box<Hashable>),
}

impl Hashable {
    pub fn leaf(u: u64) -> Self {
        Hashable::Leaf(Belt(u))
    }

    pub fn cell(left: Hashable, right: Hashable) -> Self {
        Hashable::Cell(Box::new(left), Box::new(right))
    }

    pub fn hash(&self) -> Digest {
        match self {
            Hashable::Hash(h) => *h,
            Hashable::Leaf(belt) => hash_belt(*belt),
            Hashable::List(elements) => {
                hash_hash_list(&mut elements.into_iter().map(|e| e.hash()).collect::<Vec<_>>())
            }
            Hashable::Cell(l, r) => {
                let mut belts = Vec::<Belt>::with_capacity(10);
                belts.extend_from_slice(&l.hash().0);
                belts.extend_from_slice(&r.hash().0);
                Digest(hash_fixed(&mut belts).map(|u| Belt(u)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashable_vectors() {
        let leaf = Hashable::Leaf(Belt(42));
        assert_eq!(
            to_b58(&leaf.hash().to_bytes()),
            "mhVFxh4yzHZWzLENL4FDu6WKynrgcyx3p6kJbJ9Cg7m9DPbSEvZMMf".as_bytes(),
        );
        let cell = Hashable::cell(Hashable::Leaf(Belt(42)), Hashable::Leaf(Belt(69)));
        assert_eq!(
            to_b58(&cell.hash().to_bytes()),
            "4D62tFybemZW3YX4w16jFwT5pNUaGgYz3zyx32wMsuwtrZuYUnNCeGQ".as_bytes(),
        );
        let mut list = Vec::new();
        list.push(Hashable::Leaf(Belt(42)));
        list.push(Hashable::Leaf(Belt(69)));
        list.push(Hashable::Leaf(Belt(88)));
        assert_eq!(
            to_b58(&Hashable::List(list).hash().to_bytes()),
            "uANkACbninAKJgsKMr2jKaP2Qskqfvpbk2agiB45VDq8sxXf7NW9eT".as_bytes(),
        );
    }
}
