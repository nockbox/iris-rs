# iris-ffi

Native (uniffi) bindings for the Iris wallet core — **API-parallel to
[`iris-wasm`](../iris-wasm)** so the React Native app's TypeScript adapter can
fulfill the `@nockbox/iris-sdk/wasm` module surface 1:1. Consumed by
`nockbox/iris-mobile` via
[uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native)
(see iris-mobile's `docs/MOBILE_STRATEGY.md` §3 for the strategy and the
2a/2b trade-off analysis).

## Boundary conventions

- The workspace's `tsify` is configured in **JSON mode**, so every complex
  type already crosses the wasm boundary as serde-JSON. Here the same types
  cross as **JSON strings**; after `JSON.parse` the JS side sees byte-identical
  object shapes to the wasm build.
- `Digest` and `Nicks` cross as bare strings (base58 / decimal), exactly as
  their tsify branded-string types.
- Byte buffers cross as `Vec<u8>` ↔ `ArrayBuffer`; scalars natively.
- Stateful wasm classes (`PrivateKey`, `TxBuilder`, `SpendBuilder`,
  `GrpcClient`) are uniffi objects. `ExtendedKey` is a plain record; the TS
  adapter wraps it in a class exposing `deriveChild` for wasm parity.

## gRPC transport

`FfiGrpcClient` speaks **plain gRPC over HTTP/2 + TLS** via tonic. Verified
live (2026-06-12) against both `https://rpc.nockbox.org` (the extension's
default endpoint — its proxy passes plain gRPC through) and
`https://nockchain-api.zorp.io` (the upstream). Response JSON shapes are
identical to the wasm client's (same pb types, serde-serialized).

## Scope (v0)

Implements the surface actually consumed by the iris extension / iris-mobile
TS layer (~30 functions + 4 objects), not all of `iris-wasm`'s 277
macro-generated exports. Known deferred items:

- `TxBuilder.spend(spendBuilder)` / `allSpends()` (object-passing between
  handles; settle conventions during UBRN integration)
- peek/poke (`private-api`) — the extension never calls them
- balance pagination with snapshot-changed retry (wasm client doesn't paginate
  either; port from `iris-grpc-proto::client` when needed)

## Parity gate

The unit tests pin the same golden vectors as `iris-crypto`'s tests and
iris-mobile's jest suite (mnemonic → key material → pkh, sign/verify,
jam/cue, atom↔belts round-trip). The same fixtures must pass against
`iris-wasm` in Node and `iris-ffi` on device — that is the cross-runtime
parity gate (MOBILE_STRATEGY.md §6 R1/R3).

Keep this crate's surface in lockstep with `iris-wasm`: any PR changing
`crates/iris-wasm`'s exports should change `iris-ffi` in the same PR.

## React Native stack safety

Hermes invokes UBRN exports **synchronously on a small (~512 KiB) pthread
stack**. Cheetah curve ops, SLIP-10 derivation, Noun hashing, and tx
building can overflow that guard region in release/TestFlight builds (SIGBUS
at stack guard).

All stack-sensitive exports delegate through `crypto_stack::run_on_crypto_stack`
(4 MiB scoped thread). When adding new FFI exports that touch crypto or tx
engine code, wrap them through that helper — do not run heavy work inline on
the JS thread.

High-risk patterns to always wrap:

- `PrivateKey::public_key`, `PrivateKey::sign`, `ExtendedKey::derive_child`
- `Hashable::hash`, `NounEncode` / `NounDecode`, `Belt` → Noun → hash
- `TxBuilder::{simple_spend, recalc_and_set_fee, sign, validate, build}`
- Raw tx projection / protobuf conversion

## TestFlight release (iris-mobile)

After changing `iris-ffi`:

1. Commit/push the Rust fix in `iris-rs` (the generated `.xcframework` is
   gitignored in iris-mobile).
2. From `IrisWallet/`, point `modules/iris-core/ubrn.config.yaml` at the
   patched `iris-rs` worktree and run `npm run ubrn:ios`.
3. Restore `ubrn.config.yaml` to the canonical `iris-rs` path.
4. Increment `CURRENT_PROJECT_VERSION` in the Xcode project.
5. Archive with **Release** configuration and upload to TestFlight.
6. If a crash occurs, symbolicate against the archive's dSYM:
   `atos -arch arm64 -o IrisWallet.app.dSYM/Contents/Resources/DWARF/IrisWallet -l <load_addr> <pc>`
