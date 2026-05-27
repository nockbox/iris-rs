use iris_ztd::{cue as cue_internal, jam as jam_internal, BeltSeq, Noun, NounDecode, NounEncode};
use wasm_bindgen::prelude::*;

/// Cue a jammed Uint8Array into a Noun (see `jam`).
#[wasm_bindgen]
pub fn cue(jam: &[u8]) -> Result<Noun, JsValue> {
    cue_internal(jam).ok_or_else(|| JsValue::from_str("unable to parse jam"))
}

/// Encode a Noun as a Uint8Array of bytes.
#[wasm_bindgen]
pub fn jam(noun: Noun) -> Result<Vec<u8>, JsValue> {
    Ok(jam_internal(noun))
}

/// Convert string to an Atom.
#[wasm_bindgen]
pub fn tas(s: &str) -> Noun {
    let bytes = s.as_bytes();
    let a = ibig::UBig::from_le_bytes(bytes);
    Noun::Atom(a)
}

/// Convert an Atom into a string.
#[wasm_bindgen]
pub fn untas(noun: Noun) -> Result<String, JsValue> {
    match noun {
        Noun::Atom(atom) => Ok(String::from_utf8(atom.to_le_bytes())
            .map_err(|_| JsValue::from_str("not valid utf8"))?),
        _ => Err(JsValue::from_str("not an atom")),
    }
}

/// Convert a string to sequence of Belts.
///
/// This is equivalent to `atom_to_belts(tas(s))`.
///
/// Belts are Atoms that fit the goldilocks prime field.
///
/// If a transaction contains non-based (not-fitting) atoms, it will be rejected.
#[wasm_bindgen(js_name = "tasBelts")]
pub fn tas_belts(s: &str) -> Noun {
    atom_to_belts(tas(s)).unwrap()
}

/// Convert an Atom to belts.
#[wasm_bindgen(js_name = "atomToBelts")]
pub fn atom_to_belts(atom: Noun) -> Result<Noun, JsValue> {
    match atom {
        Noun::Atom(atom) => Ok(BeltSeq(iris_ztd::belts_from_ubig(atom)).to_noun()),
        _ => Err(JsValue::from_str("not an atom")),
    }
}

/// Convert a sequence of belts back into one atom.
#[wasm_bindgen(js_name = "beltsToAtom")]
pub fn belts_to_atom(noun: Noun) -> Result<Noun, JsValue> {
    let BeltSeq(belts) =
        NounDecode::from_noun(&noun).ok_or_else(|| JsValue::from_str("unable to parse belts"))?;
    Ok(Noun::Atom(iris_ztd::belts_to_ubig(&belts)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iris_ztd::Belt;

    #[test]
    fn atom_belts_round_trip_single_belt_atom() {
        let atom = tas("bridge");
        let belts = atom_to_belts(atom.clone()).unwrap();
        let round_trip = belts_to_atom(belts).unwrap();

        assert_eq!(round_trip, atom);
    }

    #[test]
    fn bridge_metadata_round_trips_through_belts() {
        let metadata = "base:84532:0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let belts = atom_to_belts(tas(metadata)).unwrap();
        let round_trip = belts_to_atom(belts).unwrap();

        assert_eq!(untas(round_trip).unwrap(), metadata);
    }

    #[test]
    fn base_address_round_trips_through_belts() {
        let address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let belts = atom_to_belts(tas(address)).unwrap();
        let round_trip = belts_to_atom(belts).unwrap();

        assert_eq!(untas(round_trip).unwrap(), address);
    }

    #[test]
    fn belts_to_atom_accepts_improper_belt_sequence() {
        let noun = Noun::Cell(Belt(7).to_noun().into(), Belt(9).to_noun().into());
        let atom = belts_to_atom(noun).unwrap();
        let expected = iris_ztd::belts_to_ubig(&[Belt(7), Belt(9)]);

        assert_eq!(atom, Noun::Atom(expected));
    }
}
