/// The WasmSign2 error type.
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

    #[error("Unsupported module type")]
    UnsupportedModuleType,

    #[error("No valid signatures")]
    VerificationFailed,

    #[error("No valid signatures for the given predicates")]
    VerificationFailedForPredicates,

    #[error("No signatures found")]
    NoSignatures,

    #[error("Unsupported key type")]
    UnsupportedKeyType,

    #[error("Invalid argument")]
    InvalidArgument,

    #[error("Incompatible signature version")]
    IncompatibleSignatureVersion,

    #[error("Duplicate signature")]
    DuplicateSignature,

    #[error("Sections can only be verified between pre-defined boundaries")]
    InvalidVerificationPredicate,

    #[error("Signature already attached")]
    SignatureAlreadyAttached,

    #[error("Duplicate public key")]
    DuplicatePublicKey,

    #[error("Unknown public key")]
    UnknownPublicKey,

    #[error("Too many hashes (max: {0})")]
    TooManyHashes(usize),

    #[error("Too many signatures (max: {0})")]
    TooManySignatures(usize),

    #[error("Usage error: {0}")]
    UsageError(&'static str),
}
