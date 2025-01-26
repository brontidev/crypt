/**
 * # @bronti/bcrypt
 * A wasm based bcrypt implementation using https://github.com/Keats/rust-bcrypt
 *
 * @example
 * ```ts
 * import { hash. verify } from "@bronti/bcrypt"
 * function sign_up(username: string, password: string) {
 *      const hashed_password = hash(password)
 *      db.saveUser({ username, hashed_password })
 * }
 * function sign_in(username: string, password: string) {
 *      const user = db.getUser(username)
 *      if(verify(password, user.hashed_password)) return user
 *      return false;
 * }
 * ```
 * @module
 */

import { _hash, _verify } from "./wasm_bcrypt.js";
/**
 * Hashes the password and returns a string
 * @param password Password to hash
 * @returns Hashed Password
 */
export const hash = (password: string): string => _hash(password);
/**
 * Checks a password against a hash
 * @param password Password to verify
 * @param hash Hash to check against
 * @returns Is password valid?
 */
export const verify = (password: string, hash: string): boolean =>
  _verify(password, hash);
