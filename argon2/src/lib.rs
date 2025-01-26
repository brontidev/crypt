// extern  crate bcrypt;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

use wasm_bindgen::prelude::*;
// use bcrypt::{DEFAULT_COST, hash, verify };

#[wasm_bindgen]
pub fn _hash(password: &str) -> Result<String, String> {
    let password_as_bytes = password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password_as_bytes, &salt);
    match password_hash {
        Ok(pw_hash) => Ok(pw_hash.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

#[wasm_bindgen]
pub fn _verify(password: &str, hash: &str) -> Result<bool, String> {
    let password_as_bytes = password.as_bytes();
    let parsed_hash = PasswordHash::new(&hash);
    match parsed_hash {
        Ok(pw_hash) => {
            let argon2 = Argon2::default();
            let verify_result = argon2.verify_password(password_as_bytes, &pw_hash);
            match verify_result {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        Err(error) => Err(error.to_string()),
    }
}