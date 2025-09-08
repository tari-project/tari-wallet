use wasm_bindgen::prelude::*;

#[wasm_bindgen]
/// Returns lightweight wallet version
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
