use core::borrow::Borrow;

use crate::zbase::{ZBase, ZEntry};
use crate::{Hashable, NounDecode, NounEncode};
use alloc::fmt::Debug;
#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, NounDecode, NounEncode, Hashable)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi, type = "[K, V]"))]
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

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.value
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

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, NounDecode, NounEncode, Hashable)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ZMap<K, V>(pub ZBase<ZMapEntry<K, V>>);

// Unfortunately, we need to reimplement this, because type/lifetime limitations.
impl<K, V> serde::Serialize for ZMap<K, V>
where
    K: Hashable + NounEncode + serde::Serialize,
    V: Hashable + NounEncode + serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;
        for entry in self.0.iter() {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }
}

impl<'de, K, V> serde::Deserialize<'de> for ZMap<K, V>
where
    K: Hashable + NounEncode + serde::Deserialize<'de>,
    V: Hashable + NounEncode + serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self(ZBase::deserialize(deserializer)?))
    }
}

impl<K, V> Default for ZMap<K, V>
where
    K: Hashable + NounEncode,
    V: Hashable + NounEncode,
{
    fn default() -> Self {
        Self(ZBase::default())
    }
}

impl<K, V> core::ops::Deref for ZMap<K, V> {
    type Target = ZBase<ZMapEntry<K, V>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> core::ops::DerefMut for ZMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> IntoIterator for ZMap<K, V>
where
    K: Hashable + NounEncode,
    V: Hashable + NounEncode,
{
    type Item = (K, V);
    type IntoIter = crate::zbase::ZBaseIntoIterator<ZMapEntry<K, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<K, V> FromIterator<(K, V)> for ZMap<K, V>
where
    K: Hashable + NounEncode,
    V: Hashable + NounEncode,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self(ZBase::from_iter(iter))
    }
}

impl<K, V> From<ZMap<K, V>> for alloc::vec::Vec<(K, V)>
where
    K: Hashable + NounEncode,
    V: Hashable + NounEncode,
{
    fn from(map: ZMap<K, V>) -> Self {
        map.into_iter().collect()
    }
}

impl<'a, K, V> IntoIterator for &'a ZMap<K, V>
where
    K: Hashable + NounEncode,
    V: Hashable + NounEncode,
{
    type Item = (&'a K, &'a V);
    type IntoIter = crate::zbase::ZBaseIterator<'a, ZMapEntry<K, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<K, V> From<alloc::vec::Vec<(K, V)>> for ZMap<K, V>
where
    K: Hashable + NounEncode,
    V: Hashable + NounEncode,
{
    fn from(v: alloc::vec::Vec<(K, V)>) -> Self {
        Self(crate::zbase::ZBase::from(v))
    }
}

impl<K, V, const N: usize> From<[(K, V); N]> for ZMap<K, V>
where
    K: Hashable + NounEncode,
    V: Hashable + NounEncode,
{
    fn from(v: [(K, V); N]) -> Self {
        Self(crate::zbase::ZBase::from(v))
    }
}

impl<K: Hashable + NounEncode, V: Hashable + NounEncode> ZMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: K, value: V) {
        self.0.insert_entry(ZMapEntry { key, value });
    }

    pub fn get_key_value<Q: NounEncode + ?Sized>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
    {
        self.0.get_entry(key).map(|e| e.pair())
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
