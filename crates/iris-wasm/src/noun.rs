use iris_ztd::{cue as cue_internal, jam as jam_internal, Noun};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = cue)]
pub fn cue(jam: &[u8]) -> Result<Noun, JsValue> {
    cue_internal(jam).ok_or_else(|| JsValue::from_str("unable to parse jam"))
}

#[wasm_bindgen(js_name = jam)]
pub fn jam(noun: Noun) -> Result<Vec<u8>, JsValue> {
    Ok(jam_internal(noun))
}
