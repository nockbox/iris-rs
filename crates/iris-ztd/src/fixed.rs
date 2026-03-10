use crate::{Digest, Hashable, Noun, NounDecode, NounEncode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! fixed_noun {
    ($n:ident, $t:ty, $d:ty) => {
        #[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $n<const V: $t>;

        impl<const V: $t> $n<V> {
            pub const VALUE: $t = V;

            pub fn value(self) -> $t {
                V
            }
        }

        impl<const V: $t> core::ops::Deref for $n<V> {
            type Target = $t;

            fn deref(&self) -> &$t {
                &V
            }
        }

        impl<const V: $t> Serialize for $n<V> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                V.serialize(serializer)
            }
        }

        impl<'de, const V: $t> Deserialize<'de> for $n<V> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let v = <$d>::deserialize(deserializer)?;
                if v != V {
                    return Err(serde::de::Error::custom("Invalid value"));
                }
                Ok($n)
            }
        }

        impl<const V: $t> NounEncode for $n<V> {
            fn to_noun(&self) -> Noun {
                V.to_noun()
            }
        }

        impl<const V: $t> NounDecode for $n<V> {
            fn from_noun(noun: &Noun) -> Option<Self> {
                let v: $d = NounDecode::from_noun(noun)?;

                if v != V {
                    return None;
                }

                Some($n)
            }
        }

        impl<const V: $t> Hashable for $n<V> {
            fn hash(&self) -> Digest {
                V.hash()
            }

            fn leaf_count(&self) -> usize {
                1
            }

            fn hashable_pair(&self) -> Option<(impl Hashable + '_, impl Hashable + '_)> {
                Option::<((), ())>::None
            }
        }
    };
    ($n: ident, $t:ty, $d:ty; $($tt:tt)*) => {
        fixed_noun!($n, $t, $d);
        fixed_noun!($($tt)*);
    };
}

fixed_noun! {
    FixedU32, u32, u32;
    FixedU64, u64, u64
}

/// Converts a string to 64-bit value, in little-endian. Max 8 characters.
#[macro_export]
macro_rules! tas {
    ($b: expr) => {{
        let b = $b.as_bytes();
        let mut o = 0u64;
        let mut i = 0;
        while i < b.len() {
            o |= (b[i] as u64) << (i * 8);
            i += 1;
        }
        o
    }};
}

/// FixedU64 of the bytes of a string
#[macro_export]
macro_rules! ftas {
    ($b: expr) => {
        $crate::FixedTas<{ $crate::tas!($b) }>
    };
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedTas<const N: u64>;

impl<const V: u64> FixedTas<V> {
    pub const VALUE_U64: u64 = V;
    pub const VALUE_LE_BYTES: [u8; 8] = const {
        let mut b = [0u8; 8];
        b.copy_from_slice(&V.to_le_bytes());
        b
    };
    pub const VALUE_STR: &str = const {
        let mut cnt = 0;
        while cnt < 8 && Self::VALUE_LE_BYTES[cnt] != 0 {
            cnt += 1;
        }
        unsafe { core::str::from_utf8_unchecked(Self::VALUE_LE_BYTES.split_at(cnt).0) }
    };

    pub fn value_u64(self) -> u64 {
        V
    }
}

impl<const V: u64> core::ops::Deref for FixedTas<V> {
    type Target = str;

    fn deref(&self) -> &str {
        Self::VALUE_STR
    }
}

impl<const V: u64> Serialize for FixedTas<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::VALUE_STR.serialize(serializer)
    }
}

#[cfg(feature = "alloc")]
impl<'de, const V: u64> Deserialize<'de> for FixedTas<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = alloc::string::String::deserialize(deserializer)?;
        if v != Self::VALUE_STR {
            return Err(serde::de::Error::custom("Invalid value"));
        }
        Ok(FixedTas)
    }
}

impl<const V: u64> NounEncode for FixedTas<V> {
    fn to_noun(&self) -> Noun {
        V.to_noun()
    }
}

impl<const V: u64> NounDecode for FixedTas<V> {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let v: u64 = NounDecode::from_noun(noun)?;

        if v != V {
            return None;
        }

        Some(FixedTas)
    }
}

impl<const V: u64> Hashable for FixedTas<V> {
    fn hash(&self) -> Digest {
        V.hash()
    }

    fn leaf_count(&self) -> usize {
        1
    }

    fn hashable_pair(&self) -> Option<(impl Hashable + '_, impl Hashable + '_)> {
        Option::<((), ())>::None
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn test_tas() {
        let a = <ftas!("testing")>::VALUE_STR;
        assert_eq!("testing", a);
        let b = a.to_noun();
        let c: alloc::string::String = NounDecode::from_noun(&b).unwrap();
        assert_eq!("testing", c);
    }
}
