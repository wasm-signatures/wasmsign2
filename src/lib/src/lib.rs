//! A proof of concept implementation of the WebAssembly module signature proposal.

// The `PublicKey::verify()` function is what most runtimes should use or reimplement if they don't need partial verification.
// The `SecretKey::sign()` function is what most 3rd-party signing tools can use or reimplement if they don't need support for multiple signatures.

#![allow(clippy::vec_init_then_push)]
#![forbid(unsafe_code)]

mod error;
mod signature;
mod split;
mod wasm_module;

#[allow(unused_imports)]
pub use error::*;
#[allow(unused_imports)]
pub use signature::*;
#[allow(unused_imports)]
pub use split::*;
#[allow(unused_imports)]
pub use wasm_module::*;

pub mod reexports {
    pub use {ct_codecs, getrandom, hmac_sha256, log, thiserror};
}

const SIGNATURE_WASM_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_WASM_MODULE_CONTENT_TYPE: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;
