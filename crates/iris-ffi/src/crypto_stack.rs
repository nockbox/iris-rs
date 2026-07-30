//! Run stack-heavy crypto / tx-engine work off the React Native JS thread.
//!
//! Hermes invokes UBRN exports synchronously on a small (~512 KiB) pthread
//! stack. Cheetah curve ops, SLIP-10 derivation, Noun hashing, and tx
//! building can overflow that guard region in release/TestFlight builds.
//! Every such export should delegate through `run_on_crypto_stack`.

use std::thread;

use crate::{FfiError, Result};

/// Stack size for dedicated crypto worker threads (4 MiB).
pub const CRYPTO_STACK_SIZE: usize = 4 * 1024 * 1024;

/// Execute `f` on a scoped thread with an enlarged stack.
pub(crate) fn run_on_crypto_stack<T, F>(name: &str, f: F) -> Result<T>
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    thread::scope(|scope| {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(CRYPTO_STACK_SIZE)
            .spawn_scoped(scope, f)
            .map_err(|e| FfiError::msg(format!("Failed to spawn {name} thread: {e}")))?;
        handle
            .join()
            .map_err(|_| FfiError::msg(format!("{name} panicked")))
    })
}
