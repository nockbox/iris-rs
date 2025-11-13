use alloc::string::{String, ToString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

use crate::{Digest, Hashable, NounEncode};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashableStr(str);

impl NounEncode for HashableStr {
    fn to_noun(&self) -> crate::Noun {
        (&self.0).to_noun()
    }
}

impl Hashable for HashableStr {
    fn hash(&self) -> Digest {
        (&self.0).hash()
    }
}

pub const fn hs<'a>(v: &'a str) -> &'a HashableStr {
    if v.len() >= 8 {
        panic!("string is too long to be hashable");
    }
    unsafe { core::mem::transmute(v) }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashableString(String);

impl TryFrom<String> for HashableString {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() >= 8 {
            Err(())
        } else {
            Ok(Self(value))
        }
    }
}

impl<'a> From<&'a HashableStr> for HashableString {
    fn from(value: &'a HashableStr) -> Self {
        Self(value.0.to_string())
    }
}

impl AsRef<HashableStr> for HashableString {
    fn as_ref(&self) -> &HashableStr {
        unsafe { core::mem::transmute(&*self.0) }
    }
}

impl Hashable for HashableString {
    fn hash(&self) -> Digest {
        (&*self.0).hash()
    }
}

impl NounEncode for HashableString {
    fn to_noun(&self) -> crate::Noun {
        (&*self.0).to_noun()
    }
}

impl core::borrow::Borrow<String> for HashableString {
    fn borrow(&self) -> &String {
        &self.0
    }
}

impl core::borrow::Borrow<HashableStr> for HashableString {
    fn borrow(&self) -> &HashableStr {
        self.as_ref()
    }
}

impl Serialize for HashableString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HashableString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        HashableString::try_from(s).map_err(|_| {
            D::Error::custom("HashableString too long")
        })
    }
}
