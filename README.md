# Iris

[![Build and test]][workflows] [![Rustc 1.88]][rust] [![MIT licensed]][license]

[Build and test]: https://github.com/nockbox/iris-rs/actions/workflows/test.yml/badge.svg
[workflows]: https://github.com/nockbox/iris-rs/actions/workflows/test.yml
[MIT licensed]: https://img.shields.io/badge/license-MIT-blue.svg
[license]: LICENSE
[Rustc 1.88]: https://img.shields.io/badge/rustc-1.88+-lightgray.svg
[rust]: https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/

> [!WARNING]
> **This software is unaudited and provided with no security or privacy guarantees.**
> Use at your own risk.

## Cryptographic and Wallet Primitives for Nockchain

Iris provides a comprehensive set of Rust libraries for building lightweight wallets for the Nockchain network. It includes cryptographic primitives, data structures, and WASM bindings for web integration.

> [!NOTE]
> This library does not support V0 addresses.

## gRPC Support

The gRPC client requires a gRPC-web proxy, such as Envoy, connected to a public Nockchain gRPC server.

## Crates

The project is split into several crates:

| Crate | Purpose | Status |
|-------|---------|--------|
| [iris-crypto](crates/iris-crypto) | Cryptographic primitives | Beta |
| [iris-grpc-proto](crates/iris-grpc-proto) | gRPC protobuf definitions | Beta |
| [iris-nockchain-types](crates/iris-nockchain-types) | Core Nockchain types | Beta |
| [iris-wasm](crates/iris-wasm) | WASM bindings for web | Beta |
| [iris-ztd](crates/iris-ztd) | Base Zero-knowledge data structures and noun-lib | Beta |
| [iris-ztd-derive](crates/iris-ztd-derive) | Derive macros for iris-ztd | Beta |

## no_std Support

Most crates in this workspace support `no_std` environments (with `alloc` required) to facilitate usage in WASM and embedded contexts.
