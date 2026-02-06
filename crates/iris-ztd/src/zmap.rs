use core::borrow::Borrow;

use crate::zbase::{ZBase, ZEntry};
use crate::{Hashable, NounDecode, NounEncode};
use alloc::fmt::Debug;
#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, NounDecode, NounEncode, Hashable)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ZMapEntry<K, V> {
    key: K,
    value: V,
}

impl<K: Hashable + NounEncode, V: Hashable + NounEncode> ZEntry for ZMapEntry<K, V> {
    type Key = K;
    type Value = V;
    type Pair = (K, V);
    type BorrowPair<'a>
        = (&'a K, &'a V)
    where
        K: 'a,
        V: 'a;

    fn key(&self) -> &Self::Key {
        &self.key
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }

    fn pair(&self) -> Self::BorrowPair<'_> {
        (&self.key, &self.value)
    }

    fn into_key(self) -> Self::Key {
        self.key
    }

    fn into_value(self) -> Self::Value {
        self.value
    }

    fn into_pair(self) -> Self::Pair {
        (self.key, self.value)
    }

    fn from_pair((key, value): Self::Pair) -> Self {
        Self { key, value }
    }
}

pub type ZMap<K, V> = ZBase<ZMapEntry<K, V>>;

impl<K: Hashable + NounEncode, V: Hashable + NounEncode> ZMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) {
        self.insert_entry(ZMapEntry { key, value });
    }

    pub fn get_key_value<Q: NounEncode + ?Sized>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
    {
        self.get_entry(key).map(|e| e.pair())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

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
