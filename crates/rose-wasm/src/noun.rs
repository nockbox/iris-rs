use rose_ztd::{cue, jam, Noun};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Noun)]
pub struct WasmNoun {
    #[wasm_bindgen(skip)]
    pub noun: Noun,
}

#[wasm_bindgen(js_class = Noun)]
impl WasmNoun {
    #[wasm_bindgen(js_name = toJs)]
    pub fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok(serde_wasm_bindgen::to_value(&self.noun)?)
    }

    #[wasm_bindgen(js_name = fromJs)]
    pub fn new(value: JsValue) -> Result<Self, JsValue> {
        Ok(Self {
            noun: serde_wasm_bindgen::from_value(value)?,
        })
    }

    #[wasm_bindgen(js_name = cue)]
    pub fn cue(jam: &[u8]) -> Result<Self, JsValue> {
        Ok(Self {
            noun: cue(jam).ok_or("unable to parse jam")?,
        })
    }

    #[wasm_bindgen(js_name = jam)]
    pub fn jam(&self) -> Result<Vec<u8>, JsValue> {
        Ok(jam(self.noun.clone()))
    }
}
