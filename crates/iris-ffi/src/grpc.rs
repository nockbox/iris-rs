//! gRPC client, mirroring `iris-wasm` `grpc.rs`.
//!
//! Transport: **gRPC-web unary over HTTPS** (reqwest + rustls), the same
//! protocol the browser extension uses against `https://rpc.nockbox.org` —
//! iris-rs's own docs note the public RPC speaks gRPC-web only, so native
//! tonic cannot reach it (see iris-grpc-proto's `grpc_balance_fixture`
//! example). If infra later exposes plain gRPC, the tonic-based
//! `PublicNockchainGrpcClient` in iris-grpc-proto (plus a TLS feature) can
//! replace this transport without changing the FFI surface.
//!
//! All four public RPCs are unary, so the framing is simple:
//! request body = `0x00 + u32_be(len) + protobuf`, response body = data
//! frame(s) + trailers frame (flag bit 0x80) carrying `grpc-status`.

use iris_grpc_proto::pb::common::v1::{Base58Hash, Base58Pubkey, PageRequest};
use iris_grpc_proto::pb::common::v2 as pb_common_v2;
use iris_grpc_proto::pb::public::v2::*;
use prost::Message;

use crate::{from_json, to_json, FfiError, Result};

const SERVICE_PATH: &str = "/nockchain.public.v2.NockchainService";

fn frame_request<R: Message>(req: &R) -> Vec<u8> {
    let payload = req.encode_to_vec();
    let mut body = Vec::with_capacity(5 + payload.len());
    body.push(0u8);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(&payload);
    body
}

struct GrpcWebResponse {
    data: Vec<u8>,
    grpc_status: Option<i32>,
    grpc_message: Option<String>,
}

fn parse_frames(bytes: &[u8]) -> Result<GrpcWebResponse> {
    let mut data = Vec::new();
    let mut grpc_status = None;
    let mut grpc_message = None;

    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        let flag = bytes[i];
        let len = u32::from_be_bytes(
            bytes[i + 1..i + 5]
                .try_into()
                .map_err(|_| FfiError::msg("invalid gRPC-web frame header"))?,
        ) as usize;
        if i + 5 + len > bytes.len() {
            return Err(FfiError::msg("truncated gRPC-web frame"));
        }
        let frame = &bytes[i + 5..i + 5 + len];
        if flag & 0x80 != 0 {
            // Trailers frame: HTTP/1-style headers
            for line in String::from_utf8_lossy(frame).lines() {
                if let Some((name, value)) = line.split_once(':') {
                    let name = name.trim().to_ascii_lowercase();
                    let value = value.trim();
                    if name == "grpc-status" {
                        grpc_status = value.parse::<i32>().ok();
                    } else if name == "grpc-message" {
                        grpc_message = Some(value.to_string());
                    }
                }
            }
        } else {
            data.extend_from_slice(frame);
        }
        i += 5 + len;
    }

    Ok(GrpcWebResponse {
        data,
        grpc_status,
        grpc_message,
    })
}

/// Mirror of wasm `GrpcClient` — async methods return/accept the same JSON
/// shapes as the tsify boundary.
#[derive(uniffi::Object)]
pub struct FfiGrpcClient {
    endpoint: String,
    client: reqwest::Client,
}

impl FfiGrpcClient {
    async fn unary<Req: Message, Resp: Message + Default>(
        &self,
        method: &str,
        request: &Req,
    ) -> Result<Resp> {
        let url = format!("{}{}/{}", self.endpoint, SERVICE_PATH, method);
        let response = self
            .client
            .post(&url)
            .header("content-type", "application/grpc-web+proto")
            .header("x-grpc-web", "1")
            .body(frame_request(request))
            .send()
            .await
            .map_err(|e| FfiError::msg(format!("gRPC error: {e}")))?;

        // grpc-status may arrive as response headers (trailers-only replies)
        let header_status = response
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i32>().ok());
        let header_message = response
            .headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let http_status = response.status();

        let bytes = response
            .bytes()
            .await
            .map_err(|e| FfiError::msg(format!("gRPC error reading body: {e}")))?;

        if !http_status.is_success() {
            return Err(FfiError::msg(format!(
                "gRPC error: HTTP {http_status} from {url}"
            )));
        }

        let parsed = parse_frames(&bytes)?;
        let status = parsed.grpc_status.or(header_status).unwrap_or(0);
        if status != 0 {
            let message = parsed
                .grpc_message
                .or(header_message)
                .unwrap_or_else(|| "unknown".to_string());
            return Err(FfiError::msg(format!(
                "gRPC error: status {status}: {message}"
            )));
        }

        Resp::decode(parsed.data.as_slice())
            .map_err(|e| FfiError::msg(format!("gRPC error decoding response: {e}")))
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

        let response: WalletGetBalanceResponse = self.unary("WalletGetBalance", &request).await?;

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
            client: reqwest::Client::new(),
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

        let response: WalletSendTransactionResponse =
            self.unary("WalletSendTransaction", &request).await?;

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

        let response: TransactionAcceptedResponse =
            self.unary("TransactionAccepted", &request).await?;

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
    fn frames_a_unary_request() {
        let request = TransactionAcceptedRequest {
            tx_id: Some(Base58Hash { hash: "abc".into() }),
        };
        let body = frame_request(&request);
        assert_eq!(body[0], 0);
        let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
        assert_eq!(len, body.len() - 5);
        let decoded = TransactionAcceptedRequest::decode(&body[5..]).unwrap();
        assert_eq!(decoded.tx_id.unwrap().hash, "abc");
    }

    #[test]
    fn parses_data_and_trailer_frames() {
        let payload = TransactionAcceptedResponse {
            result: Some(transaction_accepted_response::Result::Accepted(true)),
        }
        .encode_to_vec();

        let mut body = Vec::new();
        body.push(0u8);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);
        let trailers = b"grpc-status: 0\r\ngrpc-message: ok";
        body.push(0x80);
        body.extend_from_slice(&(trailers.len() as u32).to_be_bytes());
        body.extend_from_slice(trailers);

        let parsed = parse_frames(&body).unwrap();
        assert_eq!(parsed.grpc_status, Some(0));
        assert_eq!(parsed.grpc_message.as_deref(), Some("ok"));
        let decoded = TransactionAcceptedResponse::decode(parsed.data.as_slice()).unwrap();
        assert!(matches!(
            decoded.result,
            Some(transaction_accepted_response::Result::Accepted(true))
        ));
    }

    #[test]
    fn reports_non_zero_grpc_status() {
        let trailers = b"grpc-status: 14\r\ngrpc-message: unavailable";
        let mut body = Vec::new();
        body.push(0x80);
        body.extend_from_slice(&(trailers.len() as u32).to_be_bytes());
        body.extend_from_slice(trailers);

        let parsed = parse_frames(&body).unwrap();
        assert_eq!(parsed.grpc_status, Some(14));
        assert_eq!(parsed.grpc_message.as_deref(), Some("unavailable"));
    }

    #[test]
    fn endpoint_normalization() {
        let client = FfiGrpcClient::new("rpc.nockbox.org".into()).unwrap();
        assert_eq!(client.endpoint, "https://rpc.nockbox.org");
        let client = FfiGrpcClient::new("http://127.0.0.1:8080/".into()).unwrap();
        assert_eq!(client.endpoint, "http://127.0.0.1:8080");
    }
}
