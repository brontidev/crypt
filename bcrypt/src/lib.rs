extern  crate bcrypt;

use wasm_bindgen::prelude::*;
use bcrypt::{DEFAULT_COST, hash, verify };

#[wasm_bindgen]
pub fn _hash(password: &str) -> Result<String, String> {
    console_error_panic_hook::set_once();
    let password_hash = hash(password, DEFAULT_COST);
    match password_hash {
        Ok(hash) => Ok(hash),
        Err(error) => Err(error.to_string())
    }
}

#[wasm_bindgen]
pub fn _verify(password: &str, hash: &str) -> Result<bool, String> {
    console_error_panic_hook::set_once();
    let is_verified = verify(password, hash);
    match is_verified {
        Ok(value) => Ok(value),
        Err(error) => Err(error.to_string())
    }
}