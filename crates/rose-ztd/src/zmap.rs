use core::borrow::Borrow;

use crate::Zeroable;
use crate::{Digest, Hashable, Noun, NounDecode, NounEncode};
use alloc::boxed::Box;
use alloc::fmt::Debug;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZMap<K, V> {
    root: Zeroable<Box<Node<K, V>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node<K, V> {
    key: K,
    value: V,
    left: Zeroable<Box<Node<K, V>>>,
    right: Zeroable<Box<Node<K, V>>>,
}

impl<K, V> Default for ZMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> ZMap<K, V> {
    pub fn new() -> Self {
        ZMap {
            root: Zeroable(None),
        }
    }
}

impl<K: NounEncode, V: NounEncode> ZMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> bool {
        let (new_root, inserted) = Self::put(self.root.take(), key, value);
        self.root = Zeroable(Some(new_root));
        inserted
    }

    pub fn get<Q: NounEncode + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        Self::get_inner(self.root.0.as_ref()?, key)
    }

    fn get_inner<'a, Q: NounEncode + ?Sized>(n: &'a Node<K, V>, key: &Q) -> Option<&'a V>
    where
        K: Borrow<Q>,
    {
        if Self::tip_eq(&key, &n.key) {
            return Some(&n.value);
        }
        let go_left = Self::gor_tip(&key, &n.key);
        if go_left {
            Self::get_inner(n.left.as_ref()?, key)
        } else {
            Self::get_inner(n.right.as_ref()?, key)
        }
    }

    fn put(node: Option<Box<Node<K, V>>>, key: K, value: V) -> (Box<Node<K, V>>, bool) {
        match node {
            None => (
                Box::new(Node {
                    key,
                    value,
                    left: Zeroable(None),
                    right: Zeroable(None),
                }),
                true,
            ),
            Some(mut n) => {
                if Self::tip_eq(&key, &n.key) {
                    return (n, false);
                }
                let go_left = Self::gor_tip(&key, &n.key);
                if go_left {
                    let (new_left, inserted) = Self::put(n.left.take(), key, value);
                    n.left = Zeroable(Some(new_left));
                    if !Self::mor_tip(&n.key, &n.left.as_ref().unwrap().key) {
                        // Rotate right
                        let mut new_root = n.left.take().unwrap();
                        n.left = Zeroable(new_root.right.take());
                        new_root.right = Zeroable(Some(n));
                        (new_root, inserted)
                    } else {
                        (n, inserted)
                    }
                } else {
                    let (new_right, inserted) = Self::put(n.right.take(), key, value);
                    n.right = Zeroable(Some(new_right));
                    if !Self::mor_tip(&n.key, &n.right.as_ref().unwrap().key) {
                        // Rotate left
                        let mut new_root = n.right.take().unwrap();
                        n.right = Zeroable(new_root.left.take());
                        new_root.left = Zeroable(Some(n));
                        (new_root, inserted)
                    } else {
                        (n, inserted)
                    }
                }
            }
        }
    }

    fn tip_eq<Q: NounEncode + ?Sized>(a: &Q, b: &K) -> bool {
        a.to_noun().hash() == b.to_noun().hash()
    }

    fn gor_tip<Q: NounEncode + ?Sized>(a: &Q, b: &K) -> bool {
        a.to_noun().hash().to_bytes() < b.to_noun().hash().to_bytes()
    }

    fn mor_tip<Q: NounEncode + ?Sized>(a: &Q, b: &K) -> bool {
        Self::double_tip(a).to_bytes() < Self::double_tip(b).to_bytes()
    }

    fn double_tip<Q: NounEncode + ?Sized>(a: &Q) -> Digest {
        (a.to_noun().hash(), a.to_noun().hash()).hash()
    }
}

impl<K: NounEncode, V: NounEncode> core::iter::FromIterator<(K, V)> for ZMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut set = ZMap::new();
        for (k, v) in iter {
            set.insert(k, v);
        }
        set
    }
}

impl<K: NounEncode + Hashable, V: NounEncode + Hashable> Hashable for ZMap<K, V> {
    fn hash(&self) -> Digest {
        fn hash_node<K: NounEncode + Hashable, V: NounEncode + Hashable>(
            node: &Zeroable<Box<Node<K, V>>>,
        ) -> Digest {
            match &node.0 {
                None => 0.hash(),
                Some(n) => {
                    let left_hash = hash_node(&n.left);
                    let right_hash = hash_node(&n.right);
                    ((&n.key, &n.value), (left_hash, right_hash)).hash()
                }
            }
        }
        hash_node(&self.root)
    }
}

impl<K: NounEncode + Hashable, V: NounEncode> NounEncode for ZMap<K, V> {
    fn to_noun(&self) -> Noun {
        fn visit<K: NounEncode + Hashable, V: NounEncode>(
            node: &Zeroable<Box<Node<K, V>>>,
        ) -> Noun {
            match &node.0 {
                None => 0.to_noun(),
                Some(n) => {
                    let left_hash = visit(&n.left);
                    let right_hash = visit(&n.right);
                    ((&n.key, &n.value), (left_hash, right_hash)).to_noun()
                }
            }
        }
        visit(&self.root)
    }
}

impl<K: NounDecode, V: NounDecode> NounDecode for Node<K, V> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let ((key, value), left, right) = NounDecode::from_noun(noun)?;
        Some(Self {
            key,
            value,
            left,
            right,
        })
    }
}

impl<K: NounDecode, V: NounDecode> NounDecode for ZMap<K, V> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let root: Zeroable<Box<Node<K, V>>> = NounDecode::from_noun(noun)?;
        Some(Self { root })
    }
}

pub struct ZMapIntoIterator<K, V> {
    stack: Vec<Box<Node<K, V>>>,
}

impl<K, V> Iterator for ZMapIntoIterator<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.stack.pop()?;
        if let Some(n) = cur.left.0 {
            self.stack.push(n);
        }
        if let Some(n) = cur.right.0 {
            self.stack.push(n);
        }
        Some((cur.key, cur.value))
    }
}

impl<K, V> IntoIterator for ZMap<K, V> {
    type Item = (K, V);
    type IntoIter = ZMapIntoIterator<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = vec![];
        if let Some(n) = self.root.0 {
            stack.push(n);
        }
        ZMapIntoIterator { stack }
    }
}

impl<K, V> From<ZMap<K, V>> for Vec<(K, V)> {
    fn from(map: ZMap<K, V>) -> Self {
        map.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    #[test]
    fn test_zmap_encode_decode() {
        let mut zm = ZMap::<String, u64>::new();
        zm.insert("ver".to_string(), 10);
        zm.insert("ve2".to_string(), 11);
        let zm_noun = zm.to_noun();
        let zm_decode = ZMap::<String, u64>::from_noun(&zm_noun).unwrap();
        assert_eq!(Vec::from(zm), Vec::from(zm_decode));
    }
}
