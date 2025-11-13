use core::borrow::Borrow;

use crate::{Digest, Hashable, Noun, NounEncode};
use alloc::boxed::Box;
use alloc::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZMap<K, V> {
    root: Option<Box<Node<K, V>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node<K, V> {
    key: K,
    value: V,
    left: Option<Box<Node<K, V>>>,
    right: Option<Box<Node<K, V>>>,
}

impl<K, V> ZMap<K, V> {
    pub fn new() -> Self {
        ZMap { root: None }
    }
}

impl<K: NounEncode, V: NounEncode> ZMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> bool {
        let (new_root, inserted) = Self::put(self.root.take(), key, value);
        self.root = Some(new_root);
        inserted
    }
    
    pub fn get<Q: NounEncode + ?Sized>(&self, key: &Q) -> Option<&V> where K: Borrow<Q> {
        Self::get_inner(self.root.as_ref()?, key)
    }

    fn get_inner<'a, Q: NounEncode + ?Sized>(n: &'a Node<K, V>, key: &Q) -> Option<&'a V> where K: Borrow<Q> {
        if Self::tip_eq(&key, &n.key) {
            return Some(&n.value);
        }
        let go_left = Self::gor_tip(&key, &n.key);
        if go_left {
            return Self::get_inner(n.left.as_ref()?, key);
        } else {
            return Self::get_inner(n.right.as_ref()?, key);
        }
    }

    fn put(node: Option<Box<Node<K, V>>>, key: K, value: V) -> (Box<Node<K, V>>, bool) {
        match node {
            None => (
                Box::new(Node {
                    key,
                    value,
                    left: None,
                    right: None,
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
                    n.left = Some(new_left);
                    if !Self::mor_tip(&n.key, &n.left.as_ref().unwrap().key) {
                        // Rotate right
                        let mut new_root = n.left.take().unwrap();
                        n.left = new_root.right.take();
                        new_root.right = Some(n);
                        (new_root, inserted)
                    } else {
                        (n, inserted)
                    }
                } else {
                    let (new_right, inserted) = Self::put(n.right.take(), key, value);
                    n.right = Some(new_right);
                    if !Self::mor_tip(&n.key, &n.right.as_ref().unwrap().key) {
                        // Rotate left
                        let mut new_root = n.right.take().unwrap();
                        n.right = new_root.left.take();
                        new_root.left = Some(n);
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
        fn hash_node<K: NounEncode + Hashable, V: NounEncode + Hashable>(node: &Option<Box<Node<K, V>>>) -> Digest {
            match node {
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
        fn visit<K: NounEncode + Hashable, V: NounEncode>(node: &Option<Box<Node<K, V>>>) -> Noun {
            match node {
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
