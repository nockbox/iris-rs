// Client module is only available for native targets (not WASM)
#![cfg(not(target_arch = "wasm32"))]

use iris_nockchain_types::{BalanceUpdate, RawTx, TxId};
use tonic::transport::Channel;

use crate::pb::common::v1::{Base58Hash, Base58Pubkey, PageRequest};
use crate::pb::common::{v1 as pb_common_v1, v2 as pb_common_v2};
use crate::pb::public::v2::nockchain_service_client::NockchainServiceClient;
use crate::pb::public::v2::*;

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC status error: {0}")]
    Status(#[from] tonic::Status),

    #[error("Server returned error: {0}")]
    ServerError(String),

    #[error("Empty response from server")]
    EmptyResponse,

    #[error("Snapshot changed during pagination; retry")]
    SnapshotChanged,

    #[error("Conversion error: {0}")]
    Conversion(#[from] crate::common::ConversionError),
}

#[derive(Clone)]
pub struct PublicNockchainGrpcClient {
    client: NockchainServiceClient<Channel>,
}

pub enum BalanceRequest {
    Address(String),
    FirstName(String),
}

impl PublicNockchainGrpcClient {
    pub async fn connect<T: AsRef<str>>(address: T) -> Result<Self> {
        let client = NockchainServiceClient::connect(address.as_ref().to_string()).await?;
        Ok(Self { client })
    }

    pub async fn wallet_get_balance(&mut self, request: &BalanceRequest) -> Result<BalanceUpdate> {
        let mut page_token = String::new();
        let mut all_notes: Vec<pb_common_v2::BalanceEntry> = Vec::new();
        let mut height: Option<pb_common_v1::BlockHeight> = None;
        let mut block_id: Option<pb_common_v1::Hash> = None;

        loop {
            let sel = match request {
                BalanceRequest::Address(addr) => {
                    wallet_get_balance_request::Selector::Address(Base58Pubkey {
                        key: addr.clone(),
                    })
                }
                BalanceRequest::FirstName(fname) => {
                    wallet_get_balance_request::Selector::FirstName(Base58Hash {
                        hash: fname.clone(),
                    })
                }
            };

            let req = WalletGetBalanceRequest {
                selector: Some(sel),
                page: Some(PageRequest {
                    client_page_items_limit: 0, // let server choose default/cap
                    page_token: page_token.clone(),
                    max_bytes: 0,
                }),
            };

            let resp = self.client.wallet_get_balance(req).await?.into_inner();
            let balance = match resp.result {
                Some(wallet_get_balance_response::Result::Balance(b)) => b,
                Some(wallet_get_balance_response::Result::Error(e)) => {
                    return Err(ClientError::ServerError(e.message))
                }
                None => return Err(ClientError::EmptyResponse),
            };

            if height.is_none() {
                height = balance.height;
                block_id = balance.block_id;
            }

            if balance.height != height || balance.block_id != block_id {
                return Err(ClientError::SnapshotChanged);
            }

            all_notes.extend(balance.notes.into_iter());
            page_token = balance
                .page
                .and_then(|p| {
                    if p.next_page_token.is_empty() {
                        None
                    } else {
                        Some(p.next_page_token)
                    }
                })
                .unwrap_or_default();

            if page_token.is_empty() {
                break;
            }
        }

        let pb_balance = pb_common_v2::Balance {
            notes: all_notes,
            height,
            block_id,
            page: Some(pb_common_v1::PageResponse {
                next_page_token: String::new(),
            }),
        };

        Ok(pb_balance.try_into()?)
    }

    pub async fn wallet_send_transaction(&mut self, raw_tx: &RawTx) -> Result<TxId> {
        let tx_id = raw_tx.id();
        let pb_tx_id = pb_common_v1::Hash::from(tx_id);
        let pb_raw_tx = pb_common_v2::RawTransaction::try_from(raw_tx.clone())?;

        let request = WalletSendTransactionRequest {
            tx_id: Some(pb_tx_id),
            raw_tx: Some(pb_raw_tx),
        };

        let response = self
            .client
            .wallet_send_transaction(request)
            .await?
            .into_inner();

        match response.result {
            Some(wallet_send_transaction_response::Result::Ack(_)) => Ok(tx_id),
            Some(wallet_send_transaction_response::Result::Error(err)) => {
                Err(ClientError::ServerError(err.message))
            }
            None => Err(ClientError::EmptyResponse),
        }
    }

    pub async fn transaction_accepted(&mut self, tx_id: Base58Hash) -> Result<bool> {
        let request = TransactionAcceptedRequest { tx_id: Some(tx_id) };
        let response = self
            .client
            .transaction_accepted(request)
            .await?
            .into_inner();

        match response.result {
            Some(transaction_accepted_response::Result::Accepted(_)) => Ok(true),
            Some(transaction_accepted_response::Result::Error(err)) => {
                Err(ClientError::ServerError(err.message))
            }
            None => Err(ClientError::EmptyResponse),
        }
    }
}
