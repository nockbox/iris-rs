use alloc::{fmt, string::String, vec, vec::Vec};
use ibig::ops::DivRem;
use ibig::UBig;
use serde::{Deserialize, Serialize};

use crate::{
    belt::{Belt, PRIME},
    tip5::hash::{hash_fixed, hash_varlen},
    Noun,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Digest(pub [Belt; 5]);

impl From<[u64; 5]> for Digest {
    fn from(belts: [u64; 5]) -> Self {
        Digest(belts.map(|b| Belt(b)))
    }
}

impl Digest {
    pub fn to_atom(&self) -> UBig {
        let p = UBig::from(PRIME);
        let p2 = &p * &p;
        let p3 = &p * &p2;
        let p4 = &p * &p3;

        let [a, b, c, d, e] = self.0.map(|b| UBig::from(b.0));
        a + b * &p + c * p2 + d * p3 + e * p4
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let res = self.to_atom();
        let mut bytes = [0u8; 40];
        let res_bytes = res.to_be_bytes();
        bytes[40 - res_bytes.len()..].copy_from_slice(&res_bytes);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        use ibig::UBig;

        let p = UBig::from(PRIME);
        let num = UBig::from_be_bytes(bytes);

        let (q1, a) = num.div_rem(&p);
        let (q2, b) = q1.div_rem(&p);
        let (q3, c) = q2.div_rem(&p);
        let (q4, d) = q3.div_rem(&p);
        let e = q4;

        Digest([
            Belt(a.try_into().unwrap()),
            Belt(b.try_into().unwrap()),
            Belt(c.try_into().unwrap()),
            Belt(d.try_into().unwrap()),
            Belt(e.try_into().unwrap()),
        ])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "{}", bs58::encode(bytes).into_string())
    }
}

impl TryFrom<&str> for Digest {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(
            &bs58::decode(s)
                .into_vec()
                .map_err(|_| "unable to decode digest")?,
        ))
    }
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
                let mut belts = Vec::<Belt>::with_capacity(10);
                belts.extend_from_slice(&self.0.hash().0);
                belts.extend_from_slice(&self.1.hash().0);
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

impl Hashable for String {
    fn hash(&self) -> Digest {
        self.bytes()
            .enumerate()
            .fold(0u64, |acc, (i, byte)| acc | ((byte as u64) << (i * 8)))
            .hash()
    }
}

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
