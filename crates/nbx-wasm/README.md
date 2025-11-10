# Nockbox Wallet WASM

WebAssembly bindings for the Nockbox Wallet, including cryptographic operations, transaction building, and gRPC-Web client for communicating with the Nockchain server.

## Features

- **Cryptography**: Key derivation, signing, address generation
- **Transaction Building**: Create and sign transactions
- **gRPC-Web Client**: Call Nockchain gRPC endpoints from the browser
  - Get wallet balance
  - Send transactions
  - Check transaction status

## Setup

### 1. Build the WASM Package

```bash
cd crates/nbx-wasm
wasm-pack build --target web --out-dir pkg
```

This generates the WebAssembly module and JavaScript bindings in the `pkg/` directory.

### 2. Set Up Envoy Proxy

Since browsers can't directly communicate with gRPC servers, you need to run an Envoy proxy that translates gRPC-Web requests to native gRPC.

#### Install Envoy

**macOS (Homebrew):**
```bash
brew install envoy
```

**Linux (apt):**
```bash
sudo apt-get install envoy
```

**Docker:**
```bash
docker pull envoyproxy/envoy:v1.28-latest
```

#### Run Envoy

From the repository root:

```bash
# Using local installation
envoy -c envoy.yaml

# Using Docker
docker run --rm -it \
  --network host \
  -v $(pwd)/envoy.yaml:/etc/envoy/envoy.yaml \
  envoyproxy/envoy:v1.28-latest
```

Envoy will:
- Listen on `http://localhost:8080` for gRPC-Web requests
- Proxy to your gRPC server on `localhost:6666`
- Handle CORS headers for browser requests

### 3. Start Your gRPC Server

Make sure your Nockchain gRPC server is running on port 6666:

```bash
# From your server directory
./your-grpc-server
```

### 4. Run the Example

Serve the example HTML file with a local HTTP server:

```bash
# Using Python
python3 -m http.server 8000

# Using Node.js
npx http-server -p 8000

# Using Rust
cargo install simple-http-server
simple-http-server -p 8000
```

Then open your browser to:
```
http://localhost:8000/crates/nbx-wasm/examples/grpc-web-demo.html
```

## Usage Examples

### JavaScript

```javascript
import init, {
  GrpcClient,
  deriveMasterKeyFromMnemonic,
  WasmTxBuilder,
  WasmNote,
  WasmVersion,
  WasmName,
  WasmDigest,
  WasmSpendCondition,
  WasmPkh,
  WasmLockPrimitive,
  WasmLockTim
} from './pkg/nbx_wasm.js';

// Initialize the WASM module
await init();

// Create a client pointing to your Envoy proxy
const client = new GrpcClient('http://localhost:8080');

// Get balance by wallet address
const balance = await client.get_balance_by_address(
  '6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX'
);
console.log('Balance:', balance);

// Get balance by first name (note hash)
const balanceByName = await client.get_balance_by_first_name(
  '2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH'
);
console.log('Balance by name:', balanceByName);

// ============================================================================
// Building and signing transactions
// ============================================================================

// Derive keys from mnemonic
const mnemonic = "dice domain inspire horse time...";
const masterKey = deriveMasterKeyFromMnemonic(mnemonic, "");

// Create notes from balance query
const notes = balance.notes.map(entry => new WasmNote(
  WasmVersion.V1(),
  entry.note.noteVersion.v1.originPage.value,
  new WasmName(entry.name.first, entry.name.last),
  new WasmDigest(entry.note.noteVersion.v1.noteData.hash),
  entry.note.noteVersion.v1.assets.value
));

// Create spend condition
const pubkeyHash = new WasmDigest("your_pubkey_hash_here");
const spendCondition = new WasmSpendCondition([
  WasmLockPrimitive.newPkh(WasmPkh.single(pubkeyHash)),
  WasmLockPrimitive.newTim(WasmLockTim.coinbase())
]);

// Build transaction
const builder = WasmTxBuilder.newSimple(
  notes,
  spendCondition,
  new WasmDigest("recipient_address"),
  1234567, // gift
  2850816, // fee
  new WasmDigest("refund_address")
);

// Sign and submit
const signedTx = builder.sign(masterKey.private_key);
const txProtobuf = signedTx.toProtobuf();
await client.send_transaction(txProtobuf);

// Check if a transaction was accepted
const accepted = await client.transaction_accepted(signedTx.id.value);
console.log('Transaction accepted:', accepted);
```

## API Reference

### `GrpcClient`

#### Constructor
```javascript
new GrpcClient(endpoint: string)
```
Creates a new gRPC-Web client.
- `endpoint`: URL of the Envoy proxy (e.g., `http://localhost:8080`)

#### Methods

##### `get_balance_by_address(address: string): Promise<Balance>`
Get the balance for a wallet address.
- `address`: Base58-encoded wallet address
- Returns: Balance object with notes, height, and block_id

##### `get_balance_by_first_name(firstName: string): Promise<Balance>`
Get the balance for a note first name.
- `firstName`: Base58-encoded first name hash
- Returns: Balance object with notes, height, and block_id

##### `send_transaction(rawTx: RawTransaction): Promise<string>`
Send a signed transaction to the network.
- `rawTx`: RawTransaction object (must include tx_id)
- Returns: Acknowledgment message

##### `transaction_accepted(txId: string): Promise<boolean>`
Check if a transaction has been accepted.
- `txId`: Base58-encoded transaction ID
- Returns: `true` if accepted, `false` otherwise

## Architecture

```
Browser (WASM) → gRPC-Web (HTTP) → Envoy Proxy → gRPC Server (HTTP/2)
```

1. **Browser/WASM**: Your web application uses the WASM module to call gRPC methods
2. **gRPC-Web**: The `tonic-web-wasm-client` translates calls to HTTP requests with gRPC-Web protocol
3. **Envoy Proxy**: Envoy translates gRPC-Web requests to native gRPC and handles CORS
4. **gRPC Server**: Your Nockchain server receives native gRPC requests

## Troubleshooting

### CORS Errors
Make sure Envoy is running and properly configured. The `envoy.yaml` file includes CORS headers.

### Connection Refused
- Verify your gRPC server is running on port 6666
- Verify Envoy is running on port 8080
- Check that you're using the correct endpoint in the client

### WASM Module Not Loading
- Ensure you're serving files over HTTP (not `file://`)
- Check browser console for detailed error messages
- Verify the `pkg/` directory contains the built WASM files

### Build Errors
If you encounter build errors:
```bash
# Clean and rebuild
cargo clean
wasm-pack build --target web --out-dir pkg
```

## Development

### Rebuild WASM
After making changes to the Rust code:
```bash
wasm-pack build --target web --out-dir pkg
```

### Update Protobuf Definitions
If you modify `.proto` files, rebuild the project to regenerate the code:
```bash
cargo build
```

## License

See the main repository LICENSE file.
