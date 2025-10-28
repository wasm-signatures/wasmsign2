use log::*;
use std::io::{prelude::*, BufReader, BufWriter};

use crate::error::*;
use crate::wasm_module::*;
use crate::ED25519_PK_ID;
use crate::SIGNATURE_VERSION;
use crate::SIGNATURE_WASM_MODULE_CONTENT_TYPE;

pub const SIGNATURE_SECTION_HEADER_NAME: &str = "signature";
pub const SIGNATURE_SECTION_DELIMITER_NAME: &str = "signature_delimiter";

pub const MAX_HASHES: usize = 64;
pub const MAX_SIGNATURES: usize = 256;

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct SignatureForHashes {
    pub key_id: Option<Vec<u8>>,
    pub alg_id: u8,
    pub signature: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct SignedHashes {
    pub hashes: Vec<Vec<u8>>,
    pub signatures: Vec<SignatureForHashes>,
}

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct SignatureData {
    pub specification_version: u8,
    pub content_type: u8,
    pub hash_function: u8,
    pub signed_hashes_set: Vec<SignedHashes>,
}

impl SignatureForHashes {
    pub fn serialize(&self) -> Result<Vec<u8>, WSError> {
        let mut writer = BufWriter::new(Vec::new());
        if let Some(key_id) = &self.key_id {
            varint::put_slice(&mut writer, key_id)?;
        } else {
            varint::put(&mut writer, 0)?;
        }
        writer.write_all(&[self.alg_id])?;
        varint::put_slice(&mut writer, &self.signature)?;
        Ok(writer.into_inner().unwrap())
    }

    pub fn deserialize(bin: impl AsRef<[u8]>) -> Result<Self, WSError> {
        let mut reader = BufReader::new(bin.as_ref());
        let key_id = varint::get_slice(&mut reader)?;
        let key_id = if key_id.is_empty() {
            None
        } else {
            Some(key_id)
        };
        let mut alg_id = [0u8; 1];
        reader.read_exact(&mut alg_id)?;
        let alg_id = alg_id[0];
        if alg_id != ED25519_PK_ID {
            debug!("Unsupported algorithm: {:02x}", alg_id);
            return Err(WSError::ParseError);
        }
        let signature = varint::get_slice(&mut reader)?;
        Ok(Self {
            key_id,
            alg_id,
            signature,
        })
    }
}

impl SignedHashes {
    pub fn serialize(&self) -> Result<Vec<u8>, WSError> {
        let mut writer = BufWriter::new(Vec::new());
        varint::put(&mut writer, self.hashes.len() as _)?;
        for hash in &self.hashes {
            writer.write_all(hash)?;
        }
        varint::put(&mut writer, self.signatures.len() as _)?;
        for signature in &self.signatures {
            varint::put_slice(&mut writer, &signature.serialize()?)?;
        }
        Ok(writer.into_inner().unwrap())
    }

    pub fn deserialize(bin: impl AsRef<[u8]>) -> Result<Self, WSError> {
        let mut reader = BufReader::new(bin.as_ref());
        let hashes_count = varint::get32(&mut reader)? as _;
        if hashes_count > MAX_HASHES {
            debug!("Too many hashes: {} (max: {})", hashes_count, MAX_HASHES);
            return Err(WSError::TooManyHashes(MAX_HASHES));
        }
        let mut hashes = Vec::with_capacity(hashes_count);
        for _ in 0..hashes_count {
            let mut hash = vec![0; 32];
            reader.read_exact(&mut hash)?;
            hashes.push(hash);
        }
        let signatures_count = varint::get32(&mut reader)? as _;
        if signatures_count > MAX_SIGNATURES {
            debug!(
                "Too many signatures: {} (max: {})",
                signatures_count, MAX_SIGNATURES
            );
            return Err(WSError::TooManySignatures(MAX_SIGNATURES));
        }
        let mut signatures = Vec::with_capacity(signatures_count);
        for _ in 0..signatures_count {
            let bin = varint::get_slice(&mut reader)?;
            if let Ok(signature) = SignatureForHashes::deserialize(bin) {
                signatures.push(signature);
            }
        }
        Ok(Self { hashes, signatures })
    }
}

impl SignatureData {
    pub fn serialize(&self) -> Result<Vec<u8>, WSError> {
        let mut writer = BufWriter::new(Vec::new());
        varint::put(&mut writer, self.specification_version as _)?;
        varint::put(&mut writer, self.content_type as _)?;
        varint::put(&mut writer, self.hash_function as _)?;
        varint::put(&mut writer, self.signed_hashes_set.len() as _)?;
        for signed_hashes in &self.signed_hashes_set {
            varint::put_slice(&mut writer, &signed_hashes.serialize()?)?;
        }
        Ok(writer.into_inner().unwrap())
    }

    pub fn deserialize(bin: impl AsRef<[u8]>) -> Result<Self, WSError> {
        let mut reader = BufReader::new(bin.as_ref());
        let specification_version = varint::get7(&mut reader)?;
        if specification_version != SIGNATURE_VERSION {
            debug!(
                "Unsupported specification version: {:02x}",
                specification_version
            );
            return Err(WSError::ParseError);
        }
        let content_type = varint::get7(&mut reader)?;
        if content_type != SIGNATURE_WASM_MODULE_CONTENT_TYPE {
            debug!("Unsupported content type: {:02x}", content_type);
            return Err(WSError::ParseError);
        }
        let hash_function = varint::get7(&mut reader)?;
        let signed_hashes_count = varint::get32(&mut reader)? as _;
        if signed_hashes_count > MAX_HASHES {
            debug!(
                "Too many hashes: {} (max: {})",
                signed_hashes_count, MAX_HASHES
            );
            return Err(WSError::TooManyHashes(MAX_HASHES));
        }
        let mut signed_hashes_set = Vec::with_capacity(signed_hashes_count);
        for _ in 0..signed_hashes_count {
            let bin = varint::get_slice(&mut reader)?;
            let signed_hashes = SignedHashes::deserialize(bin)?;
            signed_hashes_set.push(signed_hashes);
        }
        Ok(Self {
            specification_version,
            content_type,
            hash_function,
            signed_hashes_set,
        })
    }
}

pub fn new_delimiter_section() -> Result<Section, WSError> {
    let mut custom_payload = vec![0u8; 16];
    getrandom::fill(&mut custom_payload)
        .map_err(|_| WSError::InternalError("RNG error".to_string()))?;
    Ok(Section::Custom(CustomSection::new(
        SIGNATURE_SECTION_DELIMITER_NAME.to_string(),
        custom_payload,
    )))
}
