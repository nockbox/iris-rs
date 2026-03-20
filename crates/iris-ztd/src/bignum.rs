use crate::ftas;
#[cfg(feature = "wasm")]
use alloc::{boxed::Box, string::ToString};
use alloc::{format, vec, vec::Vec};
use core::fmt;
use ibig::UBig;
use iris_ztd_derive::*;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Big integer, with noun encoding as 32-bit sized limbs in LSB
///
/// In wasm, this is encoded as a string of hex digits, with no padding. This is the same as Noun's atom case.
#[derive(NounEncode, NounDecode, Hashable, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[wasm_noun_codec]
#[cfg_attr(feature = "wasm", tsify(type = "string & { __tag_bignum: undefined }"))]
pub struct Bignum {
    tag: ftas!("bn"),
    vals: Vec<u32>,
}

impl From<Vec<u32>> for Bignum {
    fn from(vals: Vec<u32>) -> Self {
        Bignum {
            tag: Default::default(),
            vals,
        }
    }
}

impl From<&UBig> for Bignum {
    fn from(ibig: &UBig) -> Self {
        let bytes = ibig.to_le_bytes();
        let mut vals = vec![];
        for b in bytes.chunks(4) {
            let mut val = [0u8; 4];
            val[..b.len()].copy_from_slice(b);
            vals.push(u32::from_le_bytes(val));
        }
        Bignum {
            tag: Default::default(),
            vals,
        }
    }
}

impl From<&Bignum> for UBig {
    fn from(bignum: &Bignum) -> Self {
        let bytes = unsafe { bignum.vals.align_to::<u8>().1 };
        ibig::UBig::from_le_bytes(bytes)
    }
}

impl Serialize for Bignum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:x}", UBig::from(self)))
    }
}

impl<'de> Deserialize<'de> for Bignum {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BnVisitor;
        impl<'de> de::Visitor<'de> for BnVisitor {
            type Value = Bignum;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a hex string representing the big integer")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bigint = ibig::UBig::from_str_radix(s, 16)
                    .map_err(|_| de::Error::custom("not hex string"))?;
                Ok(Bignum::from(&bigint))
            }
        }

        de.deserialize_str(BnVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bignum() {
        let bignum = Bignum::from(&UBig::from(12345678901234567890u128));
        assert_eq!(UBig::from(&bignum), UBig::from(12345678901234567890u128));
        let json = serde_json::to_string(&bignum).unwrap();
        assert_eq!(json, "\"ab54a98ceb1f0ad2\"");
        let bignum2 = serde_json::from_str(&json).unwrap();
        assert_eq!(bignum, bignum2);
    }

    #[test]
    fn test_bignum_p3() {
        let bignum = Bignum::from(vec![1, 4294967293, 5, 4294967289, 5, 4294967293]);
        let json = serde_json::to_string(&bignum).unwrap();
        assert_eq!(json, "\"fffffffd00000005fffffff900000005fffffffd00000001\"");
        let bignum2 = serde_json::from_str(&json).unwrap();
        assert_eq!(bignum, bignum2);
    }
}
