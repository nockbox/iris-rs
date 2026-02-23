use super::{Hashable, NounDecode, NounEncode};
use crate::zbase::{ZBase, ZEntry};
use alloc::fmt::Debug;
#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, NounDecode, NounEncode, Hashable)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi, type = "T"))]
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

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.key
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

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, NounDecode, NounEncode, Hashable)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ZSet<T>(pub ZBase<ZSetEntry<T>>);

// Unfortunately, we need to reimplement this, because type/lifetime limitations.
impl<T> serde::Serialize for ZSet<T>
where
    T: Hashable + NounEncode + serde::Serialize,
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

impl<'de, T> serde::Deserialize<'de> for ZSet<T>
where
    T: Hashable + NounEncode + serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self(ZBase::deserialize(deserializer)?))
    }
}

impl<T> Default for ZSet<T>
where
    T: Hashable + NounEncode,
{
    fn default() -> Self {
        Self(ZBase::default())
    }
}

impl<T> core::ops::Deref for ZSet<T> {
    type Target = ZBase<ZSetEntry<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for ZSet<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> IntoIterator for ZSet<T>
where
    T: Hashable + NounEncode,
{
    type Item = T;
    type IntoIter = crate::zbase::ZBaseIntoIterator<ZSetEntry<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> FromIterator<T> for ZSet<T>
where
    T: Hashable + NounEncode,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(ZBase::from_iter(iter))
    }
}

impl<T> From<ZSet<T>> for alloc::vec::Vec<T>
where
    T: Hashable + NounEncode,
{
    fn from(set: ZSet<T>) -> Self {
        set.into_iter().collect()
    }
}

impl<'a, T> IntoIterator for &'a ZSet<T>
where
    T: Hashable + NounEncode,
{
    type Item = &'a T;
    type IntoIter = crate::zbase::ZBaseIterator<'a, ZSetEntry<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> From<alloc::vec::Vec<T>> for ZSet<T>
where
    T: Hashable + NounEncode,
{
    fn from(v: alloc::vec::Vec<T>) -> Self {
        Self(crate::zbase::ZBase::from(v))
    }
}

impl<T, const N: usize> From<[T; N]> for ZSet<T>
where
    T: Hashable + NounEncode,
{
    fn from(v: [T; N]) -> Self {
        Self(crate::zbase::ZBase::from(v))
    }
}

impl<T: Hashable + NounEncode> ZSet<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: T) {
        self.0.insert_entry(ZSetEntry { key });
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
