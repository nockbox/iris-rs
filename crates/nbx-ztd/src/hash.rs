use alloc::{vec, vec::Vec};

use crate::{
    belt::{Belt, PRIME},
    crypto::cheetah::CheetahPoint,
    tip5::hash::{hash_fixed, hash_varlen},
};

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

pub trait Hashable {
    fn hash(&self) -> Digest;
}

impl Hashable for Belt {
    fn hash(&self) -> Digest {
        hash_noun(&vec![*self], &vec![])
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

impl<T: Hashable> Hashable for &T {
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

impl<A: Hashable, B: Hashable> Hashable for (A, B) {
    fn hash(&self) -> Digest {
        let mut belts = Vec::<Belt>::with_capacity(10);
        belts.extend_from_slice(&self.0.hash().0);
        belts.extend_from_slice(&self.1.hash().0);
        Digest(hash_fixed(&mut belts).map(|u| Belt(u)))
    }
}

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

pub trait NounHashable {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>);

    fn noun_hash(&self) -> Digest {
        let mut leaves = Vec::new();
        let mut dyck = Vec::new();
        self.write_noun_parts(&mut leaves, &mut dyck);
        hash_noun(&leaves, &dyck)
    }
}

impl NounHashable for Belt {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, _dyck: &mut Vec<Belt>) {
        leaves.push(*self);
    }
}

impl NounHashable for u64 {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        Belt(*self).write_noun_parts(leaves, dyck)
    }
}

impl NounHashable for usize {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        (*self as u64).write_noun_parts(leaves, dyck)
    }
}

impl NounHashable for i32 {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        (*self as u64).write_noun_parts(leaves, dyck)
    }
}

impl NounHashable for bool {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        (if *self { 0 } else { 1 }).write_noun_parts(leaves, dyck)
    }
}

impl NounHashable for Digest {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        self.0.as_slice().write_noun_parts(leaves, dyck)
    }
}

impl NounHashable for CheetahPoint {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        (self.x.0.as_slice(), (self.y.0.as_slice(), self.inf)).write_noun_parts(leaves, dyck);
    }
}

impl<T: NounHashable> NounHashable for &T {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        (**self).write_noun_parts(leaves, dyck)
    }
}

impl<T: NounHashable> NounHashable for Option<T> {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        match self {
            None => 0.write_noun_parts(leaves, dyck),
            Some(v) => (&0, v).write_noun_parts(leaves, dyck),
        }
    }
}

impl<A: NounHashable, B: NounHashable> NounHashable for (A, B) {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        dyck.push(Belt(0));
        self.0.write_noun_parts(leaves, dyck);
        dyck.push(Belt(1));
        self.1.write_noun_parts(leaves, dyck);
    }
}

impl<T: NounHashable> NounHashable for &[T] {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        for i in 0..self.len() - 1 {
            dyck.push(Belt(0));
            self[i].write_noun_parts(leaves, dyck);
            dyck.push(Belt(1));
        }
        if let Some(item) = self.last() {
            item.write_noun_parts(leaves, dyck);
        }
    }
}

impl<T: NounHashable> NounHashable for Vec<T> {
    fn write_noun_parts(&self, leaves: &mut Vec<Belt>, dyck: &mut Vec<Belt>) {
        for item in self.iter() {
            dyck.push(Belt(0));
            item.write_noun_parts(leaves, dyck);
            dyck.push(Belt(1));
        }
        leaves.push(Belt(0)); // ~
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashable_vectors() {
        assert_eq!(
            to_b58(&42.hash().to_bytes()),
            "mhVFxh4yzHZWzLENL4FDu6WKynrgcyx3p6kJbJ9Cg7m9DPbSEvZMMf".as_bytes(),
        );
        assert_eq!(
            to_b58(&(42, 69).hash().to_bytes()),
            "4D62tFybemZW3YX4w16jFwT5pNUaGgYz3zyx32wMsuwtrZuYUnNCeGQ".as_bytes(),
        );
    }
}
