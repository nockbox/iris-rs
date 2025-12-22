use rose_grpc_proto::pb::common::v1::{Base58Hash, Base58Pubkey, PageRequest};
use rose_grpc_proto::pb::common::v2 as pb_common_v2;
use rose_grpc_proto::pb::public::v2::*;
use tonic_web_wasm_client::Client;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct GrpcClient {
    endpoint: String,
}

#[wasm_bindgen]
impl GrpcClient {
    #[wasm_bindgen(constructor)]
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    /// Get balance for a wallet address
    #[wasm_bindgen(js_name = getBalanceByAddress)]
    pub async fn get_balance_by_address(&self, address: String) -> Result<JsValue, JsValue> {
        let client = Client::new(self.endpoint.clone());
        let mut grpc_client = nockchain_service_client::NockchainServiceClient::new(client);

        let request = WalletGetBalanceRequest {
            selector: Some(wallet_get_balance_request::Selector::Address(
                Base58Pubkey { key: address },
            )),
            page: Some(PageRequest {
                client_page_items_limit: 0,
                page_token: String::new(),
                max_bytes: 0,
            }),
        };

        let response = grpc_client
            .wallet_get_balance(request)
            .await
            .map_err(|e| JsValue::from_str(&format!("gRPC error: {}", e)))?
            .into_inner();

        match response.result {
            Some(wallet_get_balance_response::Result::Balance(balance)) => {
                serde_wasm_bindgen::to_value(&balance)
                    .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
            }
            Some(wallet_get_balance_response::Result::Error(e)) => {
                Err(JsValue::from_str(&format!("Server error: {}", e.message)))
            }
            None => Err(JsValue::from_str("Empty response from server")),
        }
    }

    /// Get balance for a first name
    #[wasm_bindgen(js_name = getBalanceByFirstName)]
    pub async fn get_balance_by_first_name(&self, first_name: String) -> Result<JsValue, JsValue> {
        let client = Client::new(self.endpoint.clone());
        let mut grpc_client = nockchain_service_client::NockchainServiceClient::new(client);

        let request = WalletGetBalanceRequest {
            selector: Some(wallet_get_balance_request::Selector::FirstName(
                Base58Hash { hash: first_name },
            )),
            page: Some(PageRequest {
                client_page_items_limit: 0,
                page_token: String::new(),
                max_bytes: 0,
            }),
        };

        let response = grpc_client
            .wallet_get_balance(request)
            .await
            .map_err(|e| JsValue::from_str(&format!("gRPC error: {}", e)))?
            .into_inner();

        match response.result {
            Some(wallet_get_balance_response::Result::Balance(balance)) => {
                serde_wasm_bindgen::to_value(&balance)
                    .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
            }
            Some(wallet_get_balance_response::Result::Error(e)) => {
                Err(JsValue::from_str(&format!("Server error: {}", e.message)))
            }
            None => Err(JsValue::from_str("Empty response from server")),
        }
    }

    /// Send a transaction
    #[wasm_bindgen(js_name = sendTransaction)]
    pub async fn send_transaction(&self, raw_tx: JsValue) -> Result<JsValue, JsValue> {
        let client = Client::new(self.endpoint.clone());
        let mut grpc_client = nockchain_service_client::NockchainServiceClient::new(client);

        let pb_raw_tx: pb_common_v2::RawTransaction = serde_wasm_bindgen::from_value(raw_tx)
            .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;

        // Extract the tx_id from the raw transaction
        let pb_tx_id = pb_raw_tx.id;

        let request = WalletSendTransactionRequest {
            tx_id: pb_tx_id,
            raw_tx: Some(pb_raw_tx),
        };

        let response = grpc_client
            .wallet_send_transaction(request)
            .await
            .map_err(|e| JsValue::from_str(&format!("gRPC error: {}", e)))?
            .into_inner();

        match response.result {
            Some(wallet_send_transaction_response::Result::Ack(_)) => {
                Ok(JsValue::from_str("Transaction acknowledged"))
            }
            Some(wallet_send_transaction_response::Result::Error(e)) => {
                Err(JsValue::from_str(&format!("Server error: {}", e.message)))
            }
            None => Err(JsValue::from_str("Empty response from server")),
        }
    }

    /// Check if a transaction was accepted
    #[wasm_bindgen(js_name = transactionAccepted)]
    pub async fn transaction_accepted(&self, tx_id: String) -> Result<bool, JsValue> {
        let client = Client::new(self.endpoint.clone());
        let mut grpc_client = nockchain_service_client::NockchainServiceClient::new(client);

        let request = TransactionAcceptedRequest {
            tx_id: Some(Base58Hash { hash: tx_id }),
        };

        let response = grpc_client
            .transaction_accepted(request)
            .await
            .map_err(|e| JsValue::from_str(&format!("gRPC error: {}", e)))?
            .into_inner();

        match response.result {
            Some(transaction_accepted_response::Result::Accepted(accepted)) => Ok(accepted),
            Some(transaction_accepted_response::Result::Error(e)) => {
                Err(JsValue::from_str(&format!("Server error: {}", e.message)))
            }
            None => Err(JsValue::from_str("Empty response from server")),
        }
    }
}
