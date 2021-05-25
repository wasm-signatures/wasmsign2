use serde::{Deserialize, Serialize};

pub const SIGNATURE_SECTION_HEADER_NAME: &str = "signature";
pub const SIGNATURE_SECTION_DELIMITER_NAME: &str = "signature_delimiter";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignatureForHashes {
    pub key_id: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignedParts {
    pub hashes: Vec<Vec<u8>>,
    pub signatures: Vec<SignatureForHashes>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct HeaderPayload {
    pub specification_version: u8,
    pub hash_function: u8,
    pub signed_parts_set: Vec<SignedParts>,
}
