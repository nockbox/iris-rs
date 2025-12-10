#![allow(clippy::doc_overindented_list_items)]
//! gRPC protobuf definitions and conversions for nockbox-wallet
//!
//! This crate provides protobuf type definitions compatible with nockchain's
//! gRPC API, along with conversion traits to/from nbx-nockchain-types.

// Generated code requires std features from tonic
// We keep this as a std crate since it's only used in non-WASM contexts

use iris_ztd::Base58Belts;

// Serde helper for serializing u64 as strings (for JavaScript compatibility)
pub mod serde_u64_as_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// Serde helper for serializing u32 as strings (for JavaScript compatibility)
pub mod serde_u32_as_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// Serde helper for serializing Hash as base58 string (for JavaScript compatibility)
//pub struct SerdeBeltsAsBase58<const N: usize>(pub [Belt; N]);

impl TryFrom<pb::common::v1::Hash> for Base58Belts<5> {
    type Error = ();

    fn try_from(value: pb::common::v1::Hash) -> Result<Self, Self::Error> {
        Ok(Base58Belts([
            iris_ztd::Belt(value.belt_1.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_2.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_3.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_4.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_5.as_ref().map(|b| b.value).ok_or(())?),
        ]))
    }
}

impl<'a> TryFrom<&'a pb::common::v1::Hash> for Base58Belts<5> {
    type Error = ();

    fn try_from(value: &'a pb::common::v1::Hash) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<pb::common::v1::EightBelt> for Base58Belts<8> {
    type Error = ();

    fn try_from(value: pb::common::v1::EightBelt) -> Result<Self, Self::Error> {
        Ok(Base58Belts([
            iris_ztd::Belt(value.belt_1.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_2.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_3.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_4.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_5.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_6.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_7.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_8.as_ref().map(|b| b.value).ok_or(())?),
        ]))
    }
}

impl<'a> TryFrom<&'a pb::common::v1::EightBelt> for Base58Belts<8> {
    type Error = ();

    fn try_from(value: &'a pb::common::v1::EightBelt) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl From<Base58Belts<8>> for pb::common::v1::EightBelt {
    fn from(value: Base58Belts<8>) -> Self {
        pb::common::v1::EightBelt {
            belt_1: Some(pb::common::v1::Belt {
                value: value.0[0].0,
            }),
            belt_2: Some(pb::common::v1::Belt {
                value: value.0[1].0,
            }),
            belt_3: Some(pb::common::v1::Belt {
                value: value.0[2].0,
            }),
            belt_4: Some(pb::common::v1::Belt {
                value: value.0[3].0,
            }),
            belt_5: Some(pb::common::v1::Belt {
                value: value.0[4].0,
            }),
            belt_6: Some(pb::common::v1::Belt {
                value: value.0[5].0,
            }),
            belt_7: Some(pb::common::v1::Belt {
                value: value.0[6].0,
            }),
            belt_8: Some(pb::common::v1::Belt {
                value: value.0[7].0,
            }),
        }
    }
}

impl TryFrom<pb::common::v1::SixBelt> for Base58Belts<6> {
    type Error = ();

    fn try_from(value: pb::common::v1::SixBelt) -> Result<Self, Self::Error> {
        Ok(Base58Belts([
            iris_ztd::Belt(value.belt_1.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_2.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_3.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_4.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_5.as_ref().map(|b| b.value).ok_or(())?),
            iris_ztd::Belt(value.belt_6.as_ref().map(|b| b.value).ok_or(())?),
        ]))
    }
}

impl<'a> TryFrom<&'a pb::common::v1::SixBelt> for Base58Belts<6> {
    type Error = ();

    fn try_from(value: &'a pb::common::v1::SixBelt) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl From<Base58Belts<6>> for pb::common::v1::SixBelt {
    fn from(value: Base58Belts<6>) -> Self {
        pb::common::v1::SixBelt {
            belt_1: Some(pb::common::v1::Belt {
                value: value.0[0].0,
            }),
            belt_2: Some(pb::common::v1::Belt {
                value: value.0[1].0,
            }),
            belt_3: Some(pb::common::v1::Belt {
                value: value.0[2].0,
            }),
            belt_4: Some(pb::common::v1::Belt {
                value: value.0[3].0,
            }),
            belt_5: Some(pb::common::v1::Belt {
                value: value.0[4].0,
            }),
            belt_6: Some(pb::common::v1::Belt {
                value: value.0[5].0,
            }),
        }
    }
}

pub mod serde_hash_as_base58 {
    use iris_ztd::Base58Belts;
    use serde::{
        de::Error as DeError, ser::Error as SeError, Deserialize, Deserializer, Serialize,
        Serializer,
    };

    pub fn serialize<S, T, const N: usize>(
        hash: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        for<'a> &'a T: TryInto<Base58Belts<N>>,
    {
        match hash {
            None => serializer.serialize_none(),
            Some(h) => {
                // Convert Hash to Digest
                let belts: Base58Belts<N> = h
                    .try_into()
                    .map_err(|_| S::Error::custom("Unable to serialize".to_string()))?;
                belts.to_string().serialize(serializer)
            }
        }
    }

    pub fn deserialize<'de, D, T, const N: usize>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        Base58Belts<N>: Into<T>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        match s {
            None => Ok(None),
            Some(s) => {
                let belts = Base58Belts::<N>::try_from(s.as_str())
                    .map_err(|_| DeError::custom("Unable to deserialize".to_string()))?;
                Ok(Some(belts.into()))
            }
        }
    }
}

// Serde helper for serializing Vec<Hash> as array of base58 strings
pub mod serde_hash_vec_as_base58 {
    use super::pb::common::v1::{Belt, Hash};
    use iris_ztd::Digest;
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(hashes: &Vec<Hash>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(hashes.len()))?;
        for hash in hashes {
            let digest = Digest([
                iris_ztd::Belt(hash.belt_1.as_ref().map(|b| b.value).unwrap_or(0)),
                iris_ztd::Belt(hash.belt_2.as_ref().map(|b| b.value).unwrap_or(0)),
                iris_ztd::Belt(hash.belt_3.as_ref().map(|b| b.value).unwrap_or(0)),
                iris_ztd::Belt(hash.belt_4.as_ref().map(|b| b.value).unwrap_or(0)),
                iris_ztd::Belt(hash.belt_5.as_ref().map(|b| b.value).unwrap_or(0)),
            ]);
            seq.serialize_element(&digest.to_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings = Vec::<String>::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let digest = Digest::try_from(s.as_str()).map_err(DeError::custom)?;
                Ok(Hash {
                    belt_1: Some(Belt {
                        value: digest.0[0].0,
                    }),
                    belt_2: Some(Belt {
                        value: digest.0[1].0,
                    }),
                    belt_3: Some(Belt {
                        value: digest.0[2].0,
                    }),
                    belt_4: Some(Belt {
                        value: digest.0[3].0,
                    }),
                    belt_5: Some(Belt {
                        value: digest.0[4].0,
                    }),
                })
            })
            .collect()
    }
}

// Include the generated protobuf code
pub mod pb {
    pub mod common {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/nockchain.common.v1.rs"));
        }
        pub mod v2 {
            include!(concat!(env!("OUT_DIR"), "/nockchain.common.v2.rs"));
        }
    }
    pub mod public {
        pub mod v2 {
            include!(concat!(env!("OUT_DIR"), "/nockchain.public.v2.rs"));
        }
    }

    pub const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/nockchain_descriptor.bin"));
}

#[cfg(not(target_arch = "wasm32"))]
pub mod client;
pub mod common;
pub mod convert;
