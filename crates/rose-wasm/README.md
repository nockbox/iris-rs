# Nockchain Wallet WASM

WebAssembly bindings for the Nockchain Wallet, including cryptographic operations, transaction building, and gRPC-Web client for communicating with the Nockchain server.

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
cd crates/rose-wasm
wasm-pack build --target web --out-dir pkg --scope nockchain
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
http://localhost:8000/crates/rose-wasm/examples/grpc-web-demo.html
```

## Usage Examples

### JavaScript

```javascript
import init, {
  GrpcClient,
  deriveMasterKeyFromMnemonic,
  TxBuilder,
  Note,
  Digest,
  SpendCondition,
  Pkh,
  LockPrimitive,
  LockTim
} from './pkg/rose_wasm.js';

// Initialize the WASM module
await init();

// Create a client pointing to your Envoy proxy
const client = new GrpcClient('http://localhost:8080');

// Get balance by wallet address
const balance = await client.getBalanceByAddress(
  '6psXufjYNRxffRx72w8FF9b5MYg8TEmWq2nEFkqYm51yfqsnkJu8XqX'
);
console.log('Balance:', balance);

// Get balance by first name (note hash)
const balanceByName = await client.getBalanceByFirstName(
  '2H7WHTE9dFXiGgx4J432DsCLuMovNkokfcnCGRg7utWGM9h13PgQvsH'
);
console.log('Balance by name:', balanceByName);

// ============================================================================
// Building and signing transactions
// ============================================================================

// Derive keys from mnemonic
const mnemonic = "dice domain inspire horse time...";
const masterKey = deriveMasterKeyFromMnemonic(mnemonic, "");

// Create notes from balance query (protobuf -> wasm types)
const notes = balance.notes.map((entry) => Note.fromProtobuf(entry.note));

// Create spend condition
const pubkeyHash = "your_pubkey_hash_here"; // base58 digest string
const spendCondition = new SpendCondition([
  LockPrimitive.newPkh(Pkh.single(pubkeyHash)),
  LockPrimitive.newTim(LockTim.coinbase()),
]);
const spendConditions = notes.map(() => spendCondition);

// Build transaction (simple spend)
const feePerWord = 2850816n;
const builder = new TxBuilder(feePerWord);
builder.simpleSpend(
  notes,
  spendConditions,
  new Digest("recipient_address"),
  1234567n,       // gift
  undefined,      // fee_override (optional)
  new Digest("refund_address"),
  false           // include_lock_data
);

// Sign and submit
const signingKey = masterKey.privateKey;
if (!signingKey) throw new Error('No private key available');
builder.sign(signingKey);
builder.validate();

const nockchainTx = builder.build();
const rawTx = nockchainTx.toRawTx();
const txProtobuf = rawTx.toProtobuf();
await client.sendTransaction(txProtobuf);

// Check if a transaction was accepted
const accepted = await client.transactionAccepted(rawTx.id.value);
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

##### `getBalanceByAddress(address: string): Promise<Balance>`
Get the balance for a wallet address.
- `address`: Base58-encoded wallet address
- Returns: Balance object with notes, height, and block_id

##### `getBalanceByFirstName(firstName: string): Promise<Balance>`
Get the balance for a note first name.
- `firstName`: Base58-encoded first name hash
- Returns: Balance object with notes, height, and block_id

##### `sendTransaction(rawTx: RawTransaction): Promise<string>`
Send a signed transaction to the network.
- `rawTx`: RawTransaction object (must include tx_id)
- Returns: Acknowledgment message

##### `transactionAccepted(txId: string): Promise<boolean>`
Check if a transaction has been accepted.
- `txId`: Base58-encoded transaction ID
- Returns: `true` if accepted, `false` otherwise

### Cryptography

The WASM package also exposes key-derivation and signing helpers (backed by `rose-crypto`).

#### Key derivation (browser)

```javascript
import init, { deriveMasterKeyFromMnemonic } from './pkg/rose_wasm.js';

await init();

const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const masterKey = deriveMasterKeyFromMnemonic(mnemonic, '');

// `ExtendedKey` properties are camelCase in JS
console.log('publicKey bytes:', masterKey.publicKey.length); // 97
console.log('chainCode bytes:', masterKey.chainCode.length); // 32

const child0 = masterKey.deriveChild(0);

// Important: free wasm-bindgen objects when you're done
masterKey.free();
child0.free();
```

#### Signing

```javascript
import init, { signMessage, verifySignature } from './pkg/rose_wasm.js';

await init();

// privateKeyBytes: Uint8Array(32)
// publicKeyBytes: Uint8Array(97)
const sig = signMessage(privateKeyBytes, 'hello nockchain');
const ok = verifySignature(publicKeyBytes, sig, 'hello nockchain');
console.log('valid:', ok);
```

#### API surface (selected)

- **Functions**:
  - `deriveMasterKey(seed: Uint8Array): ExtendedKey`
  - `deriveMasterKeyFromMnemonic(mnemonic: string, passphrase?: string): ExtendedKey`
  - `hashPublicKey(publicKeyBytes: Uint8Array): string`
  - `hashU64(value: number | bigint): string`
  - `hashNoun(jamBytes: Uint8Array): string`
  - `signMessage(privateKeyBytes: Uint8Array, message: string): Signature`
  - `verifySignature(publicKeyBytes: Uint8Array, signature: Signature, message: string): boolean`
- **Classes**:
  - `ExtendedKey`
    - Properties: `privateKey?: Uint8Array`, `publicKey: Uint8Array`, `chainCode: Uint8Array`
    - Methods: `deriveChild(index: number): ExtendedKey`, `free(): void`

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
wasm-pack build --target web --out-dir pkg --scope nockchain
```

## Development

### Rebuild WASM
After making changes to the Rust code:
```bash
wasm-pack build --target web --out-dir pkg --scope nockchain
```

### Update Protobuf Definitions
If you modify `.proto` files, rebuild the project to regenerate the code:
```bash
cargo build
```

## License

See the main repository LICENSE file.
