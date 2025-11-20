//! gRPC protobuf definitions and conversions for nockbox-wallet
//!
//! This crate provides protobuf type definitions compatible with nockchain's
//! gRPC API, along with conversion traits to/from nbx-nockchain-types.

// Generated code requires std features from tonic
// We keep this as a std crate since it's only used in non-WASM contexts

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
pub mod serde_hash_as_base58 {
    use super::pb::common::v1::{Belt, Hash};
    use nbx_ztd::Digest;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

    pub fn serialize<S>(hash: &Option<Hash>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match hash {
            None => serializer.serialize_none(),
            Some(h) => {
                // Convert Hash to Digest
                let digest = Digest([
                    nbx_ztd::Belt(h.belt_1.as_ref().map(|b| b.value).unwrap_or(0)),
                    nbx_ztd::Belt(h.belt_2.as_ref().map(|b| b.value).unwrap_or(0)),
                    nbx_ztd::Belt(h.belt_3.as_ref().map(|b| b.value).unwrap_or(0)),
                    nbx_ztd::Belt(h.belt_4.as_ref().map(|b| b.value).unwrap_or(0)),
                    nbx_ztd::Belt(h.belt_5.as_ref().map(|b| b.value).unwrap_or(0)),
                ]);
                digest.to_string().serialize(serializer)
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        match s {
            None => Ok(None),
            Some(s) => {
                let digest = Digest::try_from(s.as_str()).map_err(DeError::custom)?;
                Ok(Some(Hash {
                    belt_1: Some(Belt { value: digest.0[0].0 }),
                    belt_2: Some(Belt { value: digest.0[1].0 }),
                    belt_3: Some(Belt { value: digest.0[2].0 }),
                    belt_4: Some(Belt { value: digest.0[3].0 }),
                    belt_5: Some(Belt { value: digest.0[4].0 }),
                }))
            }
        }
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
