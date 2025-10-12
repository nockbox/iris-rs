#![no_std]
#![allow(clippy::len_without_is_empty)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod belt;
pub mod bpoly;
pub mod crypto;
pub mod poly;
pub mod tip5;

pub use belt::Belt;
pub use crypto::cheetah::{
    ch_add, ch_scal_big, trunc_g_order, CheetahError, CheetahPoint, F6lt, A_GEN, A_ID, G_ORDER,
};
pub use tip5::hash::hash_varlen;
