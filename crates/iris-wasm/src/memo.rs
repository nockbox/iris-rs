use iris_ztd::{cue, Noun, NounEncode};
use js_sys::{Array, ArrayBuffer, Uint8Array};
use wasm_bindgen::prelude::*;

fn noun_atoms_fit_u64(noun: &Noun) -> bool {
    match noun {
        Noun::Atom(a) => {
            let r: Result<u64, _> = a.try_into();
            r.is_ok()
        }
        Noun::Cell(l, r) => noun_atoms_fit_u64(l) && noun_atoms_fit_u64(r),
    }
}

/// Encode a UTF-8 string memo using the compact atom<->belts conversion.
/// This produces a BeltSeq noun (list of field-fitting atoms) instead of a
/// null-terminated byte list, which is far more efficient for transaction size.
fn encode_utf8_string_memo(s: &str) -> Noun {
    let bytes = s.as_bytes();
    let ubig = ibig::UBig::from_le_bytes(bytes);
    iris_ztd::BeltSeq(iris_ztd::belts_from_ubig(ubig)).to_noun()
}

/// Parse optional memo from JS into an internal `Noun`.
///
/// Accepted inputs:
/// - `string`: encoded to a CLI-compatible `(list @ux)` noun (byte list).
/// - jammed noun bytes: `Uint8Array` / `ArrayBuffer` / `number[]` (validated to be belt-safe).
pub fn memo_from_js(value: Option<JsValue>) -> Result<Option<Noun>, JsValue> {
    let Some(v) = value else {
        return Ok(None);
    };
    if v.is_undefined() || v.is_null() {
        return Ok(None);
    }
    if let Some(s) = v.as_string() {
        return Ok(Some(encode_utf8_string_memo(&s)));
    }

    // Treat array values as jammed noun bytes.
    let bytes = if v.is_instance_of::<Uint8Array>() {
        Uint8Array::from(v).to_vec()
    } else if v.is_instance_of::<ArrayBuffer>() || Array::is_array(&v) {
        Uint8Array::new(&v).to_vec()
    } else {
        return Err(JsValue::from_str(
            "memo must be a string or jammed noun bytes (Uint8Array/ArrayBuffer/number[])",
        ));
    };

    let memo = cue(&bytes).ok_or_else(|| JsValue::from_str("Failed to deserialize memo bytes"))?;
    if !noun_atoms_fit_u64(&memo) {
        return Err(JsValue::from_str(
            "memo noun contains an oversized atom; all atoms must fit into u64 belts",
        ));
    }
    Ok(Some(memo))
}
