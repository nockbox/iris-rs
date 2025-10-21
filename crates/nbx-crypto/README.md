# nbx-crypto WebAssembly Package

This package provides Nockchain cryptography primitives compiled to WebAssembly, allowing you to use `derive_master_key` and related functions from TypeScript/JavaScript.

## Building

To build the WASM package:

```bash
wasm-pack build --target web --out-dir pkg -- --features wasm
```

## Usage

### In a Web Browser

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>nbx-crypto Demo</title>
</head>
<body>
    <script type="module">
        import init, { deriveMasterKeyFromMnemonic } from './pkg/nbx_crypto.js';

        async function main() {
            // Initialize the WASM module
            await init();

            // Derive master key from mnemonic
            const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            const masterKey = deriveMasterKeyFromMnemonic(mnemonic, "");

            console.log("Private Key:", Array.from(masterKey.private_key));
            console.log("Public Key:", Array.from(masterKey.public_key));
            console.log("Chain Code:", Array.from(masterKey.chain_code));

            // Derive a child key
            const childKey = masterKey.deriveChild(0);
            console.log("Child Private Key:", Array.from(childKey.private_key));

            // Free the WASM memory
            masterKey.free();
            childKey.free();
        }

        main();
    </script>
</body>
</html>
```

### In Node.js

```javascript
import init, { deriveMasterKey, deriveMasterKeyFromMnemonic } from './pkg/nbx_crypto.js';
import { readFileSync } from 'fs';

async function main() {
    // Initialize with the WASM file
    const wasmBuffer = readFileSync('./pkg/nbx_crypto_bg.wasm');
    await init(wasmBuffer);

    // Derive from mnemonic
    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const masterKey = deriveMasterKeyFromMnemonic(mnemonic, "");

    console.log("Master Key derived successfully");
    console.log("Private Key length:", masterKey.private_key.length);
    console.log("Public Key length:", masterKey.public_key.length);
    console.log("Chain Code length:", masterKey.chain_code.length);

    // Derive children
    const child0 = masterKey.deriveChild(0);
    const child1 = masterKey.deriveChild(1);

    // Hardened derivation (index >= 2^31)
    const hardenedChild = masterKey.deriveChild(0x80000000);

    // Clean up
    masterKey.free();
    child0.free();
    child1.free();
    hardenedChild.free();
}

main();
```

### TypeScript

The package includes full TypeScript definitions:

```typescript
import init, {
    deriveMasterKey,
    deriveMasterKeyFromMnemonic,
    WasmExtendedKey
} from './pkg/nbx_crypto.js';

await init();

// Derive from mnemonic with TypeScript types
const mnemonic: string = "your mnemonic here";
const passphrase: string = "";

const masterKey: WasmExtendedKey = deriveMasterKeyFromMnemonic(mnemonic, passphrase);

// Type-safe access
const privateKey: Uint8Array | undefined = masterKey.private_key;
const publicKey: Uint8Array = masterKey.public_key;
const chainCode: Uint8Array = masterKey.chain_code;

// Derive child
const childKey: WasmExtendedKey = masterKey.deriveChild(0);
```

## API

### Functions

#### `deriveMasterKey(seed: Uint8Array): WasmExtendedKey`

Derives a master key from raw seed bytes using SLIP-10.

- **Parameters:**
  - `seed`: Raw seed bytes (typically 64 bytes from BIP39)
- **Returns:** `WasmExtendedKey` containing the master private key, public key, and chain code

#### `deriveMasterKeyFromMnemonic(mnemonic: string, passphrase?: string): WasmExtendedKey`

Derives a master key from a BIP39 mnemonic phrase.

- **Parameters:**
  - `mnemonic`: BIP39 mnemonic phrase (12-24 words)
  - `passphrase`: Optional BIP39 passphrase (defaults to empty string)
- **Returns:** `WasmExtendedKey` containing the master private key, public key, and chain code

### Classes

#### `WasmExtendedKey`

Represents an extended key with derivation capability.

**Properties:**
- `private_key: Uint8Array | undefined` - Private key (32 bytes), undefined for public-only keys
- `public_key: Uint8Array` - Public key (97 bytes: 1 byte prefix + 12 belts × 8 bytes)
- `chain_code: Uint8Array` - Chain code for derivation (32 bytes)

**Methods:**
- `deriveChild(index: number): WasmExtendedKey` - Derives a child key at the given index
  - For hardened derivation, use indices >= 2^31 (0x80000000)
  - For non-hardened derivation, use indices < 2^31
- `free(): void` - Frees the WebAssembly memory (important to prevent memory leaks)

## Implementation Details

This package uses:
- SLIP-10 for hierarchical deterministic key derivation
- Cheetah curve arithmetic from Nockchain
- Custom field arithmetic optimized for the Cheetah curve
- TIP5 hash function for internal operations

The implementation is compatible with Nockchain's wallet derivation scheme.

## License

See the main repository LICENSE file.
