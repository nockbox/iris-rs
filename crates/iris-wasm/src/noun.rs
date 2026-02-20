use iris_ztd::{cue as cue_internal, jam as jam_internal, Belt, Noun, NounDecode, NounEncode};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn cue(jam: &[u8]) -> Result<Noun, JsValue> {
    cue_internal(jam).ok_or_else(|| JsValue::from_str("unable to parse jam"))
}

#[wasm_bindgen]
pub fn jam(noun: Noun) -> Result<Vec<u8>, JsValue> {
    Ok(jam_internal(noun))
}

#[wasm_bindgen]
pub fn tas(s: &str) -> Noun {
    let bytes = s.as_bytes();
    let a = ibig::UBig::from_le_bytes(bytes);
    Noun::Atom(a)
}

#[wasm_bindgen]
pub fn untas(noun: Noun) -> Result<String, JsValue> {
    match noun {
        Noun::Atom(atom) => Ok(String::from_utf8(atom.to_le_bytes())
            .map_err(|_| JsValue::from_str("not valid utf8"))?),
        _ => Err(JsValue::from_str("not an atom")),
    }
}

#[wasm_bindgen]
pub fn tas_belts(s: &str) -> Noun {
    atom_to_belts(tas(s)).unwrap()
}

#[wasm_bindgen]
pub fn atom_to_belts(atom: Noun) -> Result<Noun, JsValue> {
    match atom {
        Noun::Atom(atom) => Ok((&iris_ztd::belts_from_atom(atom)[..]).to_noun()),
        _ => Err(JsValue::from_str("not an atom")),
    }
}

#[wasm_bindgen]
pub fn belts_to_atom(noun: Noun) -> Result<Noun, JsValue> {
    // Append tail so that this is parsed as list
    // TODO: don't do this
    let noun = Noun::Cell(Arc::new(noun), Arc::new(0u64.to_noun()));
    let belts: Vec<Belt> =
        NounDecode::from_noun(&noun).ok_or_else(|| JsValue::from_str("unable to parse belts"))?;
    Ok(Noun::Atom(iris_ztd::belts_to_atom(&belts)))
}
