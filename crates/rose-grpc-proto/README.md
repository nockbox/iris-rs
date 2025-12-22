# rose-grpc-proto

gRPC protobuf definitions and conversions for nockchain-wallet.

This crate provides protobuf type definitions compatible with nockchain's gRPC API, along with conversion traits to/from `rose-nockchain-types`.

## Overview

This crate bridges the gap between:
- **nockchain's gRPC server** - Full-featured blockchain node with Nock VM
- **nockchain-wallet** - Lightweight, no_std compatible wallet client

## Architecture

```
rose-nockchain-types (no_std, custom types)
          ↕ conversion layer
    rose-grpc-proto (std, protobuf)
          ↕ tonic/gRPC
    nockchain server (nockchain-types)
```

## Key Differences Handled

### Type Mappings

| rose-nockchain-types | Protobuf | nockchain-types |
|---------------------|----------|-----------------|
| `rose_ztd::Belt` | `Belt { value: u64 }` | `nockchain_math::Belt` |
| `rose_ztd::Digest` ([Belt; 5]) | `Hash` (5 Belt fields) | `Hash` ([Belt; 5]) |
| `Nicks` (usize) | `Nicks { value: u64 }` | `Nicks` (usize) |
| `BlockHeight` (usize) | `BlockHeight { value: u64 }` | `BlockHeight(Belt)` |
| `Version` enum | `NoteVersion { value: u32 }` | `Version` enum |

### Implementation Notes

1. **NoteData Serialization**: Currently simplified - full implementation requires proper noun serialization
2. **Public Fields**: Made key fields public in rose-nockchain-types for gRPC conversions:
   - `Name`: `first`, `last`
   - `Pkh`: `m`, `hashes`
   - `PkhSignature`: tuple field (Vec of PublicKey/Signature pairs)
   - `MerkleProof`: `root`, `path`
   - `Hax`: tuple field (Vec of Digest)
3. **Signature Conversion**: Converts between `rose_crypto::Signature` (UBig c/s fields) and protobuf EightBelt arrays

## Usage

### gRPC Client

```rust
use rose_grpc_proto::client::{PublicNockchainGrpcClient, BalanceRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Nockchain server
    let mut client = PublicNockchainGrpcClient::connect("http://localhost:50051").await?;

    // Get balance for an address
    let balance = client.wallet_get_balance(
        &BalanceRequest::Address("address_base58".to_string())
    ).await?;

    println!("Found {} notes", balance.notes.len());

    // Send a transaction
    let raw_tx = /* build your RawTx */;
    let response = client.wallet_send_transaction(raw_tx).await?;

    Ok(())
}
```

### Type Conversions

```rust
use rose_grpc_proto::{pb, convert};
use rose_nockchain_types::RawTx;

// Convert wallet transaction to protobuf
let raw_tx: RawTx = /* ... */;
let pb_tx: pb::common::v2::RawTransaction = raw_tx.into();
```

## Proto Files

The `.proto` files are copied from nockchain's `nockapp-grpc-proto` crate:
- `nockchain/common/v1/primitives.proto` - Basic types (Belt, Hash, etc.)
- `nockchain/common/v1/blockchain.proto` - V0 transaction types
- `nockchain/common/v2/blockchain.proto` - V1 transaction types with witnesses
- `nockchain/public/v2/nockchain.proto` - gRPC service definitions

## Features

- ✅ Full gRPC client for Nockchain public API
  - `wallet_get_balance` - Get wallet balance (with automatic pagination)
  - `wallet_send_transaction` - Send signed transactions
  - `transaction_accepted` - Check transaction acceptance status
- ✅ Complete type conversions between rose-nockchain-types and protobuf
- ✅ Proper error handling with typed `ClientError`

## TODO

- [ ] Implement proper NoteData serialization/deserialization (currently marked with `todo!()`)
- [ ] Add comprehensive conversion tests
- [ ] Add reverse conversions (protobuf → rose-nockchain-types) where needed
- [ ] Consider WASM compatibility for client-side gRPC-web

## Building

```bash
cargo build -p rose-grpc-proto
```

The build process automatically generates Rust code from `.proto` files using `tonic-build`.
