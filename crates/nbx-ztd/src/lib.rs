#![no_std]

extern crate alloc;

pub mod crypto;
pub mod tip5;

mod belt;
mod hash;
pub use belt::Belt;
pub use hash::*;

pub struct ZMap {}

impl ZMap {
    // TODO: impl put/get with tip5 hashing
}
