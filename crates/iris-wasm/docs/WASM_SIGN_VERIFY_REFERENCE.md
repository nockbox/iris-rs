# WASM signMessage / verifySignature – Old vs New API Reference

Use this when wiring the extension or SDK to WASM so both old and new builds behave correctly.

---

## Signing: `signMessage(private_key_bytes, message)`


| Aspect           | Old WASM                                                                                       | New WASM                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| **Rust**         | Same: `Belt::from_bytes(message.as_bytes()).to_noun().hash()` then `private_key.sign(&digest)` | Same                                                                  |
| **Message**      | UTF-8 string only (JS string → Rust `&str` → bytes)                                            | Same                                                                  |
| **Return type**  | **Class instance**: `Signature.__wrap(ptr)`                                                    | **Plain object**: `takeFromExternrefTable0(ret[0])` (tsify/externref) |
| **Return value** | `Signature` class with `.free()`, getters that copy from WASM                                  | Plain `{ c, s }`; no `.free()`                                        |


---

## Signature shape: `signature.c` and `signature.s`


| Aspect             | Old WASM                                                                              | New WASM                                            |
| ------------------ | ------------------------------------------------------------------------------------- | --------------------------------------------------- |
| **Type**           | `readonly c: Uint8Array`, `readonly s: Uint8Array`                                    | `c: string`, `s: string` (little-endian hex)        |
| **Implementation** | Getters call `wasm.signature_c(ptr)` / `signature_s(ptr)`, return copied `Uint8Array` | Tsify serializes Rust `U256` as hex string          |
| **Memory**         | Owned by WASM; must call `signature.free()` when done (or use `Signature` wrapper)    | Plain JS object; no free                            |
| **Use in JSON**    | `JSON.stringify({ c: sig.c, s: sig.s })` → `{"c":[...],"s":[...]}` (arrays)           | Same call → `{"c":"hex...","s":"hex..."}` (strings) |


**Extension/SDK:** To support both, normalize before returning to dApps:

- If `signature.c` / `signature.s` are strings → use as-is (new WASM).
- If they are `Uint8Array` → convert to hex, e.g. `Array.from(v).map(b => b.toString(16).padStart(2,'0')).join('')`.

Then always return the same JSON shape: `{ c: "<hex>", s: "<hex>" }`.

---

## Verification: `verifySignature(public_key_bytes, signature, message)`


| Aspect                   | Old WASM                                                                                  | New WASM                                                                                |
| ------------------------ | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **Rust**                 | Same: same digest from `message.as_bytes()`, then `public_key.verify(&digest, signature)` | Same                                                                                    |
| `**signature` argument** | **Class**: `Signature` instance; JS passes `signature.__wbg_ptr` into WASM                | **Plain object**: signature passed as externref (tsify); WASM receives Rust `Signature` |
| **Return**               | `ret[0] !== 0` (boolean)                                                                  | Same                                                                                    |
| **Errors**               | Throws on invalid input (e.g. wrong lengths)                                              | Same                                                                                    |


Old: `_assertClass(signature, Signature)`; `wasm.verifySignature(ptr0, len0, signature.__wbg_ptr, ptr1, len1)`.  
New: `wasm.verifySignature(ptr0, len0, signature, ptr1, len1)` – raw `signature` object.

---

## Summary for extension/vault

1. **Private key:** Pass a 32-byte `Uint8Array` copy to `signMessage` (avoid views into WASM/ExtendedKey memory).
2. **Signature output:** Normalize `c`/`s` to hex so both old (Uint8Array) and new (string) WASM produce the same JSON for verifiers.
3. **Verification log:** Use the same `message` and same `signature` object (and 97-byte public key) when calling `verifySignature`; only call if `verifySignature` exists and public key length is 97.
4. **Message encoding:** Both APIs hash UTF-8 bytes of the **string** only. If the dApp sends a hex payload (e.g. `0x...`), signer and verifier must agree to decode to bytes and hash those (e.g. via a `signMessageBytes`-style API) or to hash the literal string.

---

## File references

- **Old WASM (class-based):** `.tmp-iris-wasm-0.1.2/package/iris_wasm.js` (e.g. `Signature.__wrap`, `signature_c`, `signature_s`, `signature_new`, `__wbg_signature_free`).
- **New WASM (externref/tsify):** `iris-rs/crates/iris-wasm/pkg/iris_wasm.js` (`takeFromExternrefTable0(ret[0])` for `signMessage` return).
- **Rust (unchanged):** `iris-rs/crates/iris-wasm/src/crypto.rs` (`sign_message`, `verify_signature`); `iris-rs/crates/iris-crypto/src/cheetah.rs` (`Signature` with `tsify(type = "string")` for `c`/`s`).

