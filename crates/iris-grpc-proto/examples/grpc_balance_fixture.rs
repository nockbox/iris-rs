//! Fetch wallet balance over **native** gRPC and write a **jammed list of notes** as a test vector.
//!
//! Encoding matches [`iris_nockchain_types::tx_engine::builder::tests::jam_fixture_fee_adjust_spends_have_seeds_and_guard_rejects_empty_spend`]:
//! raw bytes of `jam(Vec::<Note>::to_noun())` — load with `cue` / `Vec::<Note>::from_noun`.
//!
//! The public wallet RPC (`https://rpc.nockbox.org`, etc.) speaks **gRPC-Web** like the browser
//! extension. This binary uses **native tonic** only — use it against a plain gRPC listener (e.g.
//! local `http://127.0.0.1:50051`). For production HTTPS/Web endpoints, capture notes with the
//! **`iris-wasm` Node REPL** (`scripts/repl.ts`): `GrpcClient`, `noteFromProtobuf`, build the
//! `Vec<Note>` list noun (`[...notes.map(noteToNoun), '0']`), `jam`, then write bytes to the same
//! `.jam` path.
//!
//! ## Synthetic fixture (no network)
//!
//! ```text
//! cargo run -p iris-grpc-proto --example grpc_balance_fixture -- \
//!   synthetic crates/iris-nockchain-types/test_vectors/grpc_balance_fixture_notes.jam
//! ```
//!
//! ## Live snapshot from **native** gRPC (not public gRPC-Web)
//!
//! ```text
//! cargo run -p iris-grpc-proto --example grpc_balance_fixture -- \
//!   fetch 'http://127.0.0.1:50051' '<PKH_BASE58>' \
//!   crates/iris-nockchain-types/test_vectors/grpc_balance_fixture_notes.jam
//! ```

#![cfg(not(target_arch = "wasm32"))]

use iris_grpc_proto::client::{BalanceRequest, PublicNockchainGrpcClient};
use iris_nockchain_types::v1::{NoteData, NoteV1};
use iris_nockchain_types::BalanceUpdate;
use iris_nockchain_types::{Name, Nicks, Note, Version};
use iris_ztd::{jam, NounEncode};
use std::env;
use std::fs;
use std::path::Path;
use std::process;

fn write_notes_jam(path: &Path, notes: &[Note]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create_dir_all {}: {e}", parent.display()))?;
    }
    // Encode as `Vec<Note>` (nil-terminated list). `&[Note]::to_noun()` differs from `Vec` for a
    // single element (bare note vs `[note nil]`), so `cue` + `Vec::from_noun` requires `Vec`.
    let jammed = jam(notes.to_vec().to_noun());
    fs::write(path, jammed).map_err(|e| format!("write {}: {e}", path.display()))
}

fn synthetic_notes_vec() -> Vec<Note> {
    vec![Note::V1(NoteV1 {
        version: Version::V1,
        origin_page: 13,
        name: Name::new(
            "2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH"
                .try_into()
                .expect("fixture first"),
            "7yMzrJjkb2Xu8uURP7YB3DFcotttR8dKDXF1tSp2wJmmXUvLM7SYzvM"
                .try_into()
                .expect("fixture last"),
        ),
        note_data: NoteData::empty(),
        assets: Nicks(4294967296),
    })]
}

fn notes_vec_from_balance_update(upd: BalanceUpdate) -> Vec<Note> {
    upd.notes.0.iter().map(|(_, note)| note.clone()).collect()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage:\n  {} synthetic <out.jam>\n  {} fetch <grpc-uri> <pkh-base58> <out.jam>",
            args.first()
                .map(|s| s.as_str())
                .unwrap_or("grpc_balance_fixture"),
            args.first()
                .map(|s| s.as_str())
                .unwrap_or("grpc_balance_fixture"),
        );
        process::exit(1);
    }

    let mode = args[1].as_str();
    let result = match mode {
        "synthetic" => {
            let path = Path::new(&args[2]);
            write_notes_jam(path, &synthetic_notes_vec())
        }
        "fetch" => {
            if args.len() < 5 {
                eprintln!(
                    "usage: {} fetch <grpc-uri> <pkh-base58> <out.jam>",
                    args.first()
                        .map(|s| s.as_str())
                        .unwrap_or("grpc_balance_fixture")
                );
                process::exit(1);
            }
            let uri = &args[2];
            let addr = &args[3];
            let path = Path::new(&args[4]);
            let run = async {
                let mut client = PublicNockchainGrpcClient::connect(uri.as_str()).await?;
                client
                    .wallet_get_balance(&BalanceRequest::Address(addr.clone()))
                    .await
            };
            match run.await {
                Ok(upd) => write_notes_jam(path, &notes_vec_from_balance_update(upd)),
                Err(e) => Err(format!("{e}")),
            }
        }
        other => Err(format!(
            "unknown mode `{other}`: expected synthetic | fetch"
        )),
    };

    if let Err(e) = result {
        eprintln!("{e}");
        process::exit(1);
    }
}
