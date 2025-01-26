extern crate bcrypt;

use wasm_bindgen::prelude::*;
use bcrypt::{DEFAULT_COST, hash, verify };

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub enum VerifyError {
    Unknown,
    InvalidHash
}

#[wasm_bindgen]
pub enum HashError {
    Unknown
}

#[wasm_bindgen]
pub fn _hash(password: &str) -> Result<String, HashError> {
    console_error_panic_hook::set_once();
    let password_hash = hash(password, DEFAULT_COST);
    match password_hash {
        Ok(hash) => Ok(hash),
        Err(_) => Err(HashError::Unknown)
    }
}

#[wasm_bindgen]
pub fn _verify(password: &str, hash: &str) -> Result<bool, VerifyError> {
    console_error_panic_hook::set_once();
    let is_verified = verify(password, hash);
    match is_verified {
        Ok(value) => Ok(value),
        Err(error) => {
            return match error {
                bcrypt::BcryptError::InvalidHash(_) => Err(VerifyError::InvalidHash),
                _ => Err(VerifyError::Unknown)
            }
        }
    }
}