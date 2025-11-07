use crate::{Digest, Hashable, Noun, NounEncode};
use alloc::boxed::Box;
use alloc::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZSet<T> {
    root: Option<Box<Node<T>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node<T> {
    value: T,
    left: Option<Box<Node<T>>>,
    right: Option<Box<Node<T>>>,
}

impl<T> ZSet<T> {
    pub fn new() -> Self {
        ZSet { root: None }
    }
}

impl<T: NounEncode> ZSet<T> {
    pub fn insert(&mut self, value: T) -> bool {
        let (new_root, inserted) = Self::put(self.root.take(), value);
        self.root = Some(new_root);
        inserted
    }

    fn put(node: Option<Box<Node<T>>>, value: T) -> (Box<Node<T>>, bool) {
        match node {
            None => (
                Box::new(Node {
                    value,
                    left: None,
                    right: None,
                }),
                true,
            ),
            Some(mut n) => {
                if Self::tip_eq(&value, &n.value) {
                    return (n, false);
                }
                let go_left = Self::gor_tip(&value, &n.value);
                if go_left {
                    let (new_left, inserted) = Self::put(n.left.take(), value);
                    n.left = Some(new_left);
                    if !Self::mor_tip(&n.value, &n.left.as_ref().unwrap().value) {
                        // Rotate right
                        let mut new_root = n.left.take().unwrap();
                        n.left = new_root.right.take();
                        new_root.right = Some(n);
                        (new_root, inserted)
                    } else {
                        (n, inserted)
                    }
                } else {
                    let (new_right, inserted) = Self::put(n.right.take(), value);
                    n.right = Some(new_right);
                    if !Self::mor_tip(&n.value, &n.right.as_ref().unwrap().value) {
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

    fn tip_eq(a: &T, b: &T) -> bool {
        a.to_noun().hash() == b.to_noun().hash()
    }

    fn gor_tip(a: &T, b: &T) -> bool {
        a.to_noun().hash().to_bytes() < b.to_noun().hash().to_bytes()
    }

    fn mor_tip(a: &T, b: &T) -> bool {
        Self::double_tip(a).to_bytes() < Self::double_tip(b).to_bytes()
    }

    fn double_tip(a: &T) -> Digest {
        (a.to_noun().hash(), a.to_noun().hash()).hash()
    }
}

impl<T: NounEncode> core::iter::FromIterator<T> for ZSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = ZSet::new();
        for item in iter {
            set.insert(item);
        }
        set
    }
}

impl<T: NounEncode + Hashable> Hashable for ZSet<T> {
    fn hash(&self) -> Digest {
        fn hash_node<T: NounEncode + Hashable>(node: &Option<Box<Node<T>>>) -> Digest {
            match node {
                None => 0.hash(),
                Some(n) => {
                    let left_hash = hash_node(&n.left);
                    let right_hash = hash_node(&n.right);
                    (&n.value, (left_hash, right_hash)).hash()
                }
            }
        }
        hash_node(&self.root)
    }
}

impl<T: NounEncode + Hashable> NounEncode for ZSet<T> {
    fn to_noun(&self) -> Noun {
        fn visit<T: NounEncode + Hashable>(node: &Option<Box<Node<T>>>) -> Noun {
            match node {
                None => 0.to_noun(),
                Some(n) => {
                    let left_hash = visit(&n.left);
                    let right_hash = visit(&n.right);
                    (&n.value, (left_hash, right_hash)).to_noun()
                }
            }
        }
        visit(&self.root)
    }
}
