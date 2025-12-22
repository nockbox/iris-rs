# Rose

[![Build and test]][workflows] [![Rustc 1.85]][rust] [![MIT licensed]][license]

[Build and test]: https://github.com/nocktoshi/rose-rs/actions/workflows/test.yml/badge.svg
[workflows]: https://github.com/nocktoshi/rose-rs/actions/workflows/test.yml
[MIT licensed]: https://img.shields.io/badge/license-MIT-blue.svg
[license]: LICENSE
[Rustc 1.85]: https://img.shields.io/badge/rustc-1.85+-lightgray.svg
[rust]: https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/

> [!WARNING]
> **This software is unaudited and provided with no security or privacy guarantees.**
> Use at your own risk.

## Cryptographic and Wallet Primitives for Nockchain

Rose provides a comprehensive set of Rust libraries for building lightweight wallets for the Nockchain network. It includes cryptographic primitives, data structures, and WASM bindings for web integration.

> [!NOTE]
> This library does not support V0 addresses.

## gRPC Support

The gRPC client requires a gRPC-web proxy, such as Envoy, connected to a public Nockchain gRPC server.

## Crates

The project is split into several crates:

| Crate | Purpose | Status |
|-------|---------|--------|
| [rose-crypto](crates/rose-crypto) | Cryptographic primitives | Beta |
| [rose-grpc-proto](crates/rose-grpc-proto) | gRPC protobuf definitions | Beta |
| [rose-nockchain-types](crates/rose-nockchain-types) | Core Nockchain types | Beta |
| [rose-wasm](crates/rose-wasm) | WASM bindings for web | Beta |
| [rose-ztd](crates/rose-ztd) | Base Zero-knowledge data structures and noun-lib | Beta |
| [rose-ztd-derive](crates/rose-ztd-derive) | Derive macros for rose-ztd | Beta |

## no_std Support

Most crates in this workspace support `no_std` environments (with `alloc` required) to facilitate usage in WASM and embedded contexts.

> [!NOTE]
> This repository is a fork. Modifications are © 2026 nockchain.net LLC <oss@nockchain.net>.

## Release process

- **Merge the release PR**: Release Please opens/updates a release PR based on Conventional Commits. Merge it into `main`/`master`.
- **Release is published**: Merging triggers Release Please to create a GitHub Release / tag.
- **Publish job runs**: The `Publish (crates.io + npm)` workflow runs on the published release and publishes:
  - crates to **crates.io**
  - `@nockchain/rose-wasm` to **npmjs**