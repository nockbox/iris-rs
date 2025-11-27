use crate::{Digest, Hashable, Noun, NounDecode, NounEncode, Zeroable};
use alloc::boxed::Box;
use alloc::fmt::Debug;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZSet<T> {
    root: Zeroable<Box<Node<T>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node<T> {
    value: T,
    left: Zeroable<Box<Node<T>>>,
    right: Zeroable<Box<Node<T>>>,
}

impl<T> Default for ZSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ZSet<T> {
    pub fn new() -> Self {
        ZSet {
            root: Zeroable(None),
        }
    }
}

impl<T: NounEncode> ZSet<T> {
    pub fn insert(&mut self, value: T) -> bool {
        let (new_root, inserted) = Self::put(self.root.take(), value);
        self.root = Zeroable(Some(new_root));
        inserted
    }

    fn put(node: Option<Box<Node<T>>>, value: T) -> (Box<Node<T>>, bool) {
        match node {
            None => (
                Box::new(Node {
                    value,
                    left: Zeroable(None),
                    right: Zeroable(None),
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
                    n.left = Zeroable(Some(new_left));
                    if !Self::mor_tip(&n.value, &n.left.as_ref().unwrap().value) {
                        // Rotate right
                        let mut new_root = n.left.take().unwrap();
                        n.left = Zeroable(new_root.right.take());
                        new_root.right = Zeroable(Some(n));
                        (new_root, inserted)
                    } else {
                        (n, inserted)
                    }
                } else {
                    let (new_right, inserted) = Self::put(n.right.take(), value);
                    n.right = Zeroable(Some(new_right));
                    if !Self::mor_tip(&n.value, &n.right.as_ref().unwrap().value) {
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

impl<T: NounEncode> NounEncode for ZSet<T> {
    fn to_noun(&self) -> Noun {
        fn visit<T: NounEncode>(node: &Zeroable<Box<Node<T>>>) -> Noun {
            match node.as_ref() {
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

impl<T: NounDecode> NounDecode for Node<T> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (value, left, right) = NounDecode::from_noun(noun)?;
        Some(Self { value, left, right })
    }
}

impl<T: NounDecode> NounDecode for ZSet<T> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let root: Zeroable<Box<Node<T>>> = NounDecode::from_noun(noun)?;
        Some(Self { root })
    }
}

pub struct ZSetIntoIterator<T> {
    stack: Vec<Box<Node<T>>>,
}

impl<T> Iterator for ZSetIntoIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.stack.pop()?;
        if let Some(n) = cur.left.0 {
            self.stack.push(n);
        }
        if let Some(n) = cur.right.0 {
            self.stack.push(n);
        }
        Some(cur.value)
    }
}

impl<T> IntoIterator for ZSet<T> {
    type Item = T;
    type IntoIter = ZSetIntoIterator<T>;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = vec![];
        if let Some(n) = self.root.0 {
            stack.push(n);
        }
        ZSetIntoIterator { stack }
    }
}

impl<T: NounEncode> From<ZSet<T>> for Vec<T> {
    fn from(set: ZSet<T>) -> Self {
        set.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    #[test]
    fn test_zset_encode_decode() {
        let mut zm = ZSet::<String>::new();
        zm.insert("ver".to_string());
        zm.insert("ve2".to_string());
        let zm_noun = zm.to_noun();
        let zm_decode = ZSet::<String>::from_noun(&zm_noun).unwrap();
        assert_eq!(Vec::from(zm), Vec::from(zm_decode));
    }
}
