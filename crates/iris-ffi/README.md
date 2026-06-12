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
