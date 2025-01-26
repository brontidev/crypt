extern  crate bcrypt;

use wasm_bindgen::prelude::*;
use bcrypt::{DEFAULT_COST, hash, verify };

#[wasm_bindgen]
pub fn _hash(password: &str) -> String {
    hash(password, DEFAULT_COST).unwrap()
}

#[wasm_bindgen]
pub fn _verify(password: &str, hash: &str) -> bool {
    verify(password, hash).unwrap()
}