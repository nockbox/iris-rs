use crate::{Digest, Hashable, NounHashable};
use alloc::boxed::Box;
use alloc::fmt::Debug;
use alloc::vec::Vec;

/// A tree-based ordered set that matches the z-set type from Hoon.
///
/// ZSet is implemented as a treap (tree + heap) where:
/// - Elements are ordered by `gor_tip` (hash-based ordering with Ord fallback)
/// - Tree balancing is maintained by `mor_tip` (double-hash based priority)
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

impl<T> Node<T> {
    fn new(value: T) -> Self {
        Node {
            value,
            left: None,
            right: None,
        }
    }
}

impl<T> Default for ZSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ZSet<T> {
    /// Creates a new empty ZSet.
    pub fn new() -> Self {
        ZSet { root: None }
    }

    /// Returns true if the set contains no elements.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Returns the number of elements in the set.
    pub fn len(&self) -> usize {
        Self::len_recursive(&self.root)
    }

    fn len_recursive(node: &Option<Box<Node<T>>>) -> usize {
        match node {
            None => 0,
            Some(n) => 1 + Self::len_recursive(&n.left) + Self::len_recursive(&n.right),
        }
    }
}

impl<T: NounHashable> ZSet<T> {
    /// Inserts a value into the set.
    ///
    /// If the set did not have this value present, returns true.
    /// If the set did have this value present, returns false.
    pub fn insert(&mut self, value: T) -> bool {
        let (new_root, inserted) = Self::put(self.root.take(), value);
        self.root = Some(new_root);
        inserted
    }

    /// Internal recursive insert operation matching Hoon's ++put.
    ///
    /// Returns the new tree and whether a new element was inserted.
    fn put(node: Option<Box<Node<T>>>, value: T) -> (Box<Node<T>>, bool) {
        match node {
            None => {
                // Base case: empty tree, create new node
                (Box::new(Node::new(value)), true)
            }
            Some(mut n) => {
                // Check if value already exists
                if Self::tip_eq(&value, &n.value) {
                    // Value already exists, return unchanged
                    return (n, false);
                }

                // Determine which subtree to insert into based on gor_tip ordering
                let go_left = Self::gor_tip(&value, &n.value);

                if go_left {
                    // Insert into left subtree
                    let (new_left, inserted) = Self::put(n.left.take(), value);
                    n.left = Some(new_left);

                    // Check if rotation is needed (mor_tip comparison)
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
                    // Insert into right subtree
                    let (new_right, inserted) = Self::put(n.right.take(), value);
                    n.right = Some(new_right);

                    // Check if rotation is needed
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
        a.noun_hash() == b.noun_hash()
    }

    fn gor_tip(a: &T, b: &T) -> bool {
        a.noun_hash().to_bytes() < b.noun_hash().to_bytes()
    }

    fn mor_tip(a: &T, b: &T) -> bool {
        Self::double_tip(a).to_bytes() < Self::double_tip(b).to_bytes()
    }

    fn double_tip(a: &T) -> Digest {
        (a.noun_hash(), a.noun_hash()).hash()
    }

    /// Checks if the set contains a value.
    pub fn contains(&self, value: &T) -> bool {
        Self::has(&self.root, value)
    }

    fn has(node: &Option<Box<Node<T>>>, value: &T) -> bool {
        match node {
            None => false,
            Some(n) => {
                if Self::tip_eq(value, &n.value) {
                    true
                } else if Self::gor_tip(value, &n.value) {
                    Self::has(&n.left, value)
                } else {
                    Self::has(&n.right, value)
                }
            }
        }
    }

    /// Converts the set to a vector (in-order traversal).
    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        let mut result = Vec::new();
        Self::collect_inorder(&self.root, &mut result);
        result
    }

    fn collect_inorder(node: &Option<Box<Node<T>>>, result: &mut Vec<T>)
    where
        T: Clone,
    {
        if let Some(n) = node {
            Self::collect_inorder(&n.left, result);
            result.push(n.value.clone());
            Self::collect_inorder(&n.right, result);
        }
    }

    /// Pretty-prints the tree structure as nested tuples.
    /// Each node shows the first 4 bytes of its hash, or "0" for None nodes.
    /// Format: (hash, (left, right))
    pub fn pretty_print(&self) -> alloc::string::String
    where
        T: Debug,
    {
        Self::pretty_print_node(&self.root)
    }

    fn pretty_print_node(node: &Option<Box<Node<T>>>) -> alloc::string::String
    where
        T: Debug,
    {
        match node {
            None => alloc::string::String::from("0"),
            Some(n) => {
                let left = Self::pretty_print_node(&n.left);
                let right = Self::pretty_print_node(&n.right);
                alloc::format!("[{:?} {} {}]", n.value, left, right)
            }
        }
    }
}

/// Allows collecting an iterator into a ZSet.
impl<T: NounHashable> core::iter::FromIterator<T> for ZSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = ZSet::new();
        for item in iter {
            set.insert(item);
        }
        set
    }
}

impl<T: NounHashable + Hashable> Hashable for ZSet<T> {
    fn hash(&self) -> Digest {
        fn hash_node<T: NounHashable + Hashable>(node: &Option<Box<Node<T>>>) -> Digest {
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
