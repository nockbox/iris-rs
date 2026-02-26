use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use core::borrow::Borrow;
use serde::de::{SeqAccess, Visitor};

use crate::Zeroable;
use crate::{Digest, Hashable, Noun, NounDecode, NounEncode};

use alloc::fmt::Debug;
use alloc::vec;
use alloc::vec::Vec;

pub trait ZEntry {
    type Key: NounEncode;
    type Value;
    type Pair;
    type BorrowPair<'a>: Hashable + NounEncode + 'a
    where
        Self: 'a;

    fn key(&self) -> &Self::Key;
    fn value(&self) -> &Self::Value;
    fn value_mut(&mut self) -> &mut Self::Value;
    fn pair(&self) -> Self::BorrowPair<'_>;

    fn into_key(self) -> Self::Key;
    fn into_value(self) -> Self::Value;
    fn into_pair(self) -> Self::Pair;

    fn from_pair(pair: Self::Pair) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi, type = "E[]"))]
pub struct ZBase<E> {
    root: Zeroable<Box<Node<E>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
struct Node<E> {
    entry: E,
    left: Zeroable<Box<Node<E>>>,
    right: Zeroable<Box<Node<E>>>,
}

impl<E: ZEntry> Default for ZBase<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: ZEntry> ZBase<E> {
    pub fn new() -> Self {
        ZBase {
            root: Zeroable(None),
        }
    }

    pub fn iter(&self) -> ZBaseIterator<'_, E> {
        <&Self as IntoIterator>::into_iter(self)
    }

    pub fn clear(&mut self) {
        self.root = Zeroable(None);
    }
}

impl<E: ZEntry> ZBase<E> {
    pub fn insert_entry(&mut self, entry: E) -> bool {
        let (new_root, inserted) = Self::put(self.root.take(), entry);
        self.root = Zeroable(Some(new_root));
        inserted
    }

    pub fn contains<Q: NounEncode + ?Sized>(&self, key: &Q) -> bool
    where
        E::Key: Borrow<Q>,
    {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    pub fn get<Q: NounEncode + ?Sized>(&self, key: &Q) -> Option<&E::Value>
    where
        E::Key: Borrow<Q>,
    {
        self.get_entry(key).map(|e| e.value())
    }

    pub fn get_mut<Q: NounEncode + ?Sized>(&mut self, key: &Q) -> Option<&mut E::Value>
    where
        E::Key: Borrow<Q>,
    {
        // No get_entry_mut, because we want keys to be immutable
        // TODO: disallow on ZSet, because ZSet's value is its key
        Self::get_inner_mut(self.root.0.as_mut()?, key).map(|e| e.value_mut())
    }

    fn get_inner_mut<'a, Q: NounEncode + ?Sized>(n: &'a mut Node<E>, key: &Q) -> Option<&'a mut E>
    where
        E::Key: Borrow<Q>,
    {
        if Self::tip_eq(&key, n.entry.key()) {
            return Some(&mut n.entry);
        }
        let go_left = Self::gor_tip(&key, n.entry.key());
        if go_left {
            Self::get_inner_mut(n.left.as_mut()?, key)
        } else {
            Self::get_inner_mut(n.right.as_mut()?, key)
        }
    }

    pub fn get_entry<Q: NounEncode + ?Sized>(&self, key: &Q) -> Option<&E>
    where
        E::Key: Borrow<Q>,
    {
        Self::get_inner(self.root.0.as_ref()?, key)
    }

    fn get_inner<'a, Q: NounEncode + ?Sized>(n: &'a Node<E>, key: &Q) -> Option<&'a E>
    where
        E::Key: Borrow<Q>,
    {
        if Self::tip_eq(&key, n.entry.key()) {
            return Some(&n.entry);
        }
        let go_left = Self::gor_tip(&key, n.entry.key());
        if go_left {
            Self::get_inner(n.left.as_ref()?, key)
        } else {
            Self::get_inner(n.right.as_ref()?, key)
        }
    }

    fn put(node: Option<Box<Node<E>>>, entry: E) -> (Box<Node<E>>, bool) {
        match node {
            None => (
                Box::new(Node {
                    entry,
                    left: Zeroable(None),
                    right: Zeroable(None),
                }),
                true,
            ),
            Some(mut n) => {
                if Self::tip_eq(&entry.key(), n.entry.key()) {
                    return (n, false);
                }
                let go_left = Self::gor_tip(&entry.key(), n.entry.key());
                if go_left {
                    let (new_left, inserted) = Self::put(n.left.take(), entry);
                    n.left = Zeroable(Some(new_left));
                    if !Self::mor_tip(n.entry.key(), n.left.as_ref().unwrap().entry.key()) {
                        // Rotate right
                        let mut new_root = n.left.take().unwrap();
                        n.left = Zeroable(new_root.right.take());
                        new_root.right = Zeroable(Some(n));
                        (new_root, inserted)
                    } else {
                        (n, inserted)
                    }
                } else {
                    let (new_right, inserted) = Self::put(n.right.take(), entry);
                    n.right = Zeroable(Some(new_right));
                    if !Self::mor_tip(n.entry.key(), n.right.as_ref().unwrap().entry.key()) {
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

    fn tip_eq<Q: NounEncode + ?Sized>(a: &Q, b: &E::Key) -> bool {
        a.to_noun().hash() == b.to_noun().hash()
    }

    fn gor_tip<Q: NounEncode + ?Sized>(a: &Q, b: &E::Key) -> bool {
        a.to_noun().hash().to_bytes() < b.to_noun().hash().to_bytes()
    }

    fn mor_tip<Q: NounEncode + ?Sized>(a: &Q, b: &E::Key) -> bool {
        Self::double_tip(a).to_bytes() < Self::double_tip(b).to_bytes()
    }

    fn double_tip<Q: NounEncode + ?Sized>(a: &Q) -> Digest {
        (a.to_noun().hash(), a.to_noun().hash()).hash()
    }
}

impl<E: ZEntry> core::iter::FromIterator<E::Pair> for ZBase<E> {
    fn from_iter<I: IntoIterator<Item = E::Pair>>(iter: I) -> Self {
        let mut set = ZBase::new();
        for pair in iter {
            set.insert_entry(E::from_pair(pair));
        }
        set
    }
}

impl<E: ZEntry> Hashable for ZBase<E> {
    fn hash(&self) -> Digest {
        fn hash_node<E: ZEntry>(node: &Zeroable<Box<Node<E>>>) -> Digest {
            match &node.0 {
                None => 0.hash(),
                Some(n) => {
                    let left_hash = hash_node(&n.left);
                    let right_hash = hash_node(&n.right);
                    (n.entry.pair(), (left_hash, right_hash)).hash()
                }
            }
        }
        hash_node(&self.root)
    }
}

impl<E: ZEntry> NounEncode for ZBase<E> {
    fn to_noun(&self) -> Noun {
        fn visit<E: ZEntry>(node: &Zeroable<Box<Node<E>>>) -> Noun {
            match &node.0 {
                None => 0.to_noun(),
                Some(n) => {
                    let left_hash = visit(&n.left);
                    let right_hash = visit(&n.right);
                    (n.entry.pair(), (left_hash, right_hash)).to_noun()
                }
            }
        }
        visit(&self.root)
    }
}

impl<E: ZEntry> NounDecode for Node<E>
where
    E::Pair: NounDecode,
{
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (entry, left, right) = NounDecode::from_noun(noun)?;
        Some(Self {
            entry: E::from_pair(entry),
            left,
            right,
        })
    }
}

impl<E: ZEntry> NounDecode for ZBase<E>
where
    E::Pair: NounDecode,
{
    fn from_noun(noun: &Noun) -> Option<Self> {
        let root: Zeroable<Box<Node<E>>> = NounDecode::from_noun(noun)?;
        Some(Self { root })
    }
}

pub struct ZBaseIntoIterator<E> {
    stack: Vec<Box<Node<E>>>,
}

impl<E: ZEntry> Iterator for ZBaseIntoIterator<E> {
    type Item = E::Pair;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.stack.pop()?;
        if let Some(n) = cur.left.0 {
            self.stack.push(n);
        }
        if let Some(n) = cur.right.0 {
            self.stack.push(n);
        }
        Some(cur.entry.into_pair())
    }
}

impl<E: ZEntry> IntoIterator for ZBase<E> {
    type Item = E::Pair;
    type IntoIter = ZBaseIntoIterator<E>;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = vec![];
        if let Some(n) = self.root.0 {
            stack.push(n);
        }
        ZBaseIntoIterator { stack }
    }
}

pub struct ZBaseIterator<'a, E> {
    stack: Vec<&'a Node<E>>,
}

impl<'a, E: ZEntry> Iterator for ZBaseIterator<'a, E> {
    type Item = E::BorrowPair<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.stack.pop()?;
        if let Some(n) = cur.left.0.as_deref() {
            self.stack.push(n);
        }
        if let Some(n) = cur.right.0.as_deref() {
            self.stack.push(n);
        }
        Some(cur.entry.pair())
    }
}

impl<E: ZEntry> From<ZBase<E>> for Vec<E::Pair> {
    fn from(map: ZBase<E>) -> Self {
        map.into_iter().collect()
    }
}

impl<'a, E: ZEntry> IntoIterator for &'a ZBase<E> {
    type Item = E::BorrowPair<'a>;
    type IntoIter = ZBaseIterator<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = vec![];
        if let Some(n) = self.root.0.as_deref() {
            stack.push(n);
        }
        ZBaseIterator { stack }
    }
}

impl<E: ZEntry> From<Vec<E::Pair>> for ZBase<E> {
    fn from(v: Vec<E::Pair>) -> Self {
        v.into_iter().collect()
    }
}

impl<E: ZEntry, const N: usize> From<[E::Pair; N]> for ZBase<E> {
    fn from(v: [E::Pair; N]) -> Self {
        v.into_iter().collect()
    }
}

impl<E: ZEntry> serde::Serialize for ZBase<E>
where
    for<'a> E::BorrowPair<'a>: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;
        for entry in self.iter() {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }
}

impl<'de, E: ZEntry> serde::Deserialize<'de> for ZBase<E>
where
    E::Pair: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ZBaseVisitor<E>(core::marker::PhantomData<E>);

        impl<'de, E: ZEntry> Visitor<'de> for ZBaseVisitor<E>
        where
            E::Pair: serde::Deserialize<'de>,
        {
            type Value = ZBase<E>;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = ZBase::new();

                while let Some(pair) = seq.next_element::<E::Pair>()? {
                    out.insert_entry(E::from_pair(pair));
                }

                Ok(out)
            }
        }

        deserializer.deserialize_seq(ZBaseVisitor(core::marker::PhantomData))
    }
}
