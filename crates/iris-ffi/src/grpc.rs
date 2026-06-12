//! gRPC client, mirroring `iris-wasm` `grpc.rs`.
//!
//! Transport: **plain gRPC over HTTP/2 + TLS (tonic)**. Verified 2026-06-12:
//! both `https://rpc.nockbox.org` and `https://nockchain-api.zorp.io` accept
//! native tonic connections (the older "gRPC-web only" note in
//! iris-grpc-proto's example docs is outdated — the proxy passes plain gRPC
//! through). This replaces an earlier hand-rolled gRPC-web shim; same FFI
//! surface, same response JSON shapes as the wasm client.

use iris_grpc_proto::pb::common::v1::{Base58Hash, Base58Pubkey, PageRequest};
use iris_grpc_proto::pb::common::v2 as pb_common_v2;
use iris_grpc_proto::pb::public::v2::nockchain_service_client::NockchainServiceClient;
use iris_grpc_proto::pb::public::v2::*;

use crate::{from_json, to_json, FfiError, Result};

/// Mirror of wasm `GrpcClient` — async methods return/accept the same JSON
/// shapes as the tsify boundary (pb types, serde-serialized).
#[derive(uniffi::Object)]
pub struct FfiGrpcClient {
    endpoint: String,
}

impl FfiGrpcClient {
    /// Connect per call, like the wasm client constructs its transport per
    /// call. tonic channels are cheap to set up and this keeps the handle
    /// free of interior mutability.
    async fn client(&self) -> Result<NockchainServiceClient<tonic::transport::Channel>> {
        NockchainServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| FfiError::msg(format!("gRPC error: {e}")))
    }

    async fn get_balance(
        &self,
        selector: wallet_get_balance_request::Selector,
    ) -> Result<pb_common_v2::Balance> {
        let request = WalletGetBalanceRequest {
            selector: Some(selector),
            page: Some(PageRequest {
                client_page_items_limit: 0,
                page_token: String::new(),
                max_bytes: 0,
            }),
        };

        let response = self
            .client()
            .await?
            .wallet_get_balance(request)
            .await
            .map_err(|e| FfiError::msg(format!("gRPC error: {e}")))?
            .into_inner();

        match response.result {
            Some(wallet_get_balance_response::Result::Balance(balance)) => Ok(balance),
            Some(wallet_get_balance_response::Result::Error(e)) => {
                Err(FfiError::msg(format!("Server error: {}", e.message)))
            }
            None => Err(FfiError::msg("Empty response from server")),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiGrpcClient {
    /// wasm: `new GrpcClient(endpoint)`
    #[uniffi::constructor]
    pub fn new(endpoint: String) -> Result<Self> {
        let normalized = if endpoint.contains("://") {
            endpoint
        } else {
            format!("https://{endpoint}")
        };
        Ok(Self {
            endpoint: normalized.trim_end_matches('/').to_string(),
        })
    }

    /// wasm: `grpcClient.getBalanceByAddress(address)` -> Balance JSON
    pub async fn get_balance_by_address(&self, address: String) -> Result<String> {
        let balance = self
            .get_balance(wallet_get_balance_request::Selector::Address(
                Base58Pubkey { key: address },
            ))
            .await?;
        to_json(&balance)
    }

    /// wasm: `grpcClient.getBalanceByFirstName(firstName)` -> Balance JSON
    pub async fn get_balance_by_first_name(&self, first_name: String) -> Result<String> {
        let balance = self
            .get_balance(wallet_get_balance_request::Selector::FirstName(
                Base58Hash { hash: first_name },
            ))
            .await?;
        to_json(&balance)
    }

    /// wasm: `grpcClient.sendTransaction(rawTxProtobuf)` (pb RawTransaction JSON in)
    pub async fn send_transaction(&self, raw_tx_pb_json: String) -> Result<String> {
        let raw_tx: pb_common_v2::RawTransaction = from_json(&raw_tx_pb_json)?;
        let request = WalletSendTransactionRequest {
            tx_id: raw_tx.id,
            raw_tx: Some(raw_tx),
        };

        let response = self
            .client()
            .await?
            .wallet_send_transaction(request)
            .await
            .map_err(|e| FfiError::msg(format!("gRPC error: {e}")))?
            .into_inner();

        match response.result {
            Some(wallet_send_transaction_response::Result::Ack(_)) => {
                Ok(String::from("Transaction acknowledged"))
            }
            Some(wallet_send_transaction_response::Result::Error(e)) => {
                Err(FfiError::msg(format!("Server error: {}", e.message)))
            }
            None => Err(FfiError::msg("Empty response from server")),
        }
    }

    /// wasm: `grpcClient.transactionAccepted(txId)`
    pub async fn transaction_accepted(&self, tx_id: String) -> Result<bool> {
        let request = TransactionAcceptedRequest {
            tx_id: Some(Base58Hash { hash: tx_id }),
        };

        let response = self
            .client()
            .await?
            .transaction_accepted(request)
            .await
            .map_err(|e| FfiError::msg(format!("gRPC error: {e}")))?
            .into_inner();

        match response.result {
            Some(transaction_accepted_response::Result::Accepted(accepted)) => Ok(accepted),
            Some(transaction_accepted_response::Result::Error(e)) => {
                Err(FfiError::msg(format!("Server error: {}", e.message)))
            }
            None => Err(FfiError::msg("Empty response from server")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_normalization() {
        let client = FfiGrpcClient::new("rpc.nockbox.org".into()).unwrap();
        assert_eq!(client.endpoint, "https://rpc.nockbox.org");
        let client = FfiGrpcClient::new("http://127.0.0.1:8080/".into()).unwrap();
        assert_eq!(client.endpoint, "http://127.0.0.1:8080");
    }
}
