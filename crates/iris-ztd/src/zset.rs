use super::{Hashable, NounDecode, NounEncode};
use crate::zbase::{ZBase, ZEntry};
use alloc::fmt::Debug;
#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, NounDecode, NounEncode, Hashable)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ZSetEntry<T> {
    key: T,
}

impl<T: Hashable + NounEncode> ZEntry for ZSetEntry<T> {
    type Key = T;
    type Value = T;
    type Pair = T;
    type BorrowPair<'a>
        = &'a T
    where
        T: 'a;

    fn key(&self) -> &Self::Key {
        &self.key
    }

    fn value(&self) -> &Self::Value {
        &self.key
    }

    fn pair(&self) -> Self::BorrowPair<'_> {
        &self.key
    }

    fn into_key(self) -> Self::Key {
        self.key
    }

    fn into_value(self) -> Self::Value {
        self.key
    }

    fn into_pair(self) -> Self::Pair {
        self.key
    }

    fn from_pair(pair: Self::Pair) -> Self {
        Self { key: pair }
    }
}

pub type ZSet<T> = ZBase<ZSetEntry<T>>;

impl<T: Hashable + NounEncode> ZSet<T> {
    pub fn insert(&mut self, key: T) {
        self.insert_entry(ZSetEntry { key });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    #[test]
    fn test_zset_encode_decode() {
        let mut zm = ZSet::<&str>::new();
        let s1 = "ver".to_string();
        let s2 = "ve2".to_string();
        zm.insert(&s1);
        zm.insert(&s2);
        let zm_noun = zm.to_noun();
        let zm_decode = ZSet::<String>::from_noun(&zm_noun).unwrap();
        assert_eq!(Vec::from(zm), Vec::from(zm_decode));
    }
}
