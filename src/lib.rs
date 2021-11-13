//! A proof of concept implementation of the WebAssembly module signature proposal.

// The `PublicKey::verify()` function is what most runtimes should use or reimplement if they don't need partial verification.
// The `SecretKey::sign()` function is what most 3rd-party signing tools can use or reimplement if they don't need support for multiple signatures.

#![allow(clippy::vec_init_then_push)]
#![forbid(unsafe_code)]

mod error;
mod signature;
mod split;
mod wasm_module;

pub use error::*;
pub use signature::*;
pub use split::*;
pub use wasm_module::*;

pub mod reexports {
    pub use {anyhow, ct_codecs, getrandom, hmac_sha256, log, regex, thiserror};
}

const SIGNATURE_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;
