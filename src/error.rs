#[derive(Debug, thiserror::Error)]
pub enum WSError {
    #[error("Internal error: [{0}]")]
    InternalError(String),

    #[error("Parse error")]
    ParseError,

    #[error("I/O error")]
    IOError(#[from] std::io::Error),

    #[error("EOF")]
    Eof,

    #[error("UTF-8 error")]
    UTF8Error(#[from] std::str::Utf8Error),

    #[error("Ed25519 signature function error")]
    CryptoError(#[from] ed25519_compact::Error),

    #[error("No valid signatures")]
    VerificationFailed,

    #[error("No signatures found")]
    NoSignatures,

    #[error("Unsupported key type")]
    UnsupportedKeyType,
}
