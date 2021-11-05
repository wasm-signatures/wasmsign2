#![allow(clippy::vec_init_then_push)]
#![forbid(unsafe_code)]

mod error;
mod sig_sections;
mod varint;
mod wasm_module;

pub use error::*;
use sig_sections::*;
use wasm_module::*;

use ct_codecs::{Encoder, Hex};
use hmac_sha256::Hash;
use log::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, prelude::*};
use std::ops::RangeInclusive;
use std::str;

const SIGNATURE_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;

const ED25519_PK_ID: u8 = 0x01;
const ED25519_SK_ID: u8 = 0x81;

pub struct PublicKey {
    pk: ed25519_compact::PublicKey,
}

impl PublicKey {
    pub fn from_bytes(pk: &[u8]) -> Result<Self, WSError> {
        let mut reader = io::Cursor::new(pk);
        let mut id = [0u8];
        reader.read_exact(&mut id)?;
        if id[0] != ED25519_PK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_pem(pem)?;
        Ok(Self { pk })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_der(der)?;
        Ok(Self { pk })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_PK_ID];
        bytes.extend_from_slice(self.pk.as_ref());
        bytes
    }

    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    pub fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }
}

pub struct SecretKey {
    sk: ed25519_compact::SecretKey,
}

impl SecretKey {
    pub fn from_bytes(pk: &[u8]) -> Result<Self, WSError> {
        let mut reader = io::Cursor::new(pk);
        let mut id = [0u8];
        reader.read_exact(&mut id)?;
        if id[0] != ED25519_SK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_pem(pem)?;
        Ok(Self { sk })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_der(der)?;
        Ok(Self { sk })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_SK_ID];
        bytes.extend_from_slice(self.sk.as_ref());
        bytes
    }

    pub fn to_pem(&self) -> String {
        self.sk.to_pem()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.sk.to_der()
    }

    pub fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }
}

pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::generate());
        KeyPair {
            pk: PublicKey { pk: kp.pk },
            sk: SecretKey { sk: kp.sk },
        }
    }
}

pub fn show(file: &str, verbose: bool) -> Result<(), WSError> {
    let module = Module::deserialize_from_file(file)?;
    for (idx, section) in module.sections.iter().enumerate() {
        println!("{}:\t{}", idx, section.display(verbose));
    }
    Ok(())
}

fn build_header_section(sk: &SecretKey, hashes: Vec<Vec<u8>>) -> Result<Section, WSError> {
    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    msg.extend_from_slice(&[SIGNATURE_VERSION, SIGNATURE_HASH_FUNCTION]);
    for hash in &hashes {
        msg.extend_from_slice(hash);
    }

    debug!("* Adding signature:\n");

    debug!(
        "sig = Ed25519(sk, \"{}\" ‖ {:02x} ‖ {:02x} ‖ {})\n",
        SIGNATURE_DOMAIN,
        SIGNATURE_VERSION,
        SIGNATURE_HASH_FUNCTION,
        Hex::encode_to_string(&msg[SIGNATURE_DOMAIN.len() + 2..]).unwrap()
    );

    let signature = sk.sk.sign(msg, None).to_vec();

    debug!("    = {}\n\n", Hex::encode_to_string(&signature).unwrap());

    let signature_for_hashes = SignatureForHashes {
        key_id: None,
        signature,
    };
    let mut signatures = vec![];
    signatures.push(signature_for_hashes);
    let signed_parts = SignedHashes { hashes, signatures };
    let mut signed_hashes_set = vec![];
    signed_hashes_set.push(signed_parts);
    let signature_data = SignatureData {
        specification_version: SIGNATURE_VERSION,
        hash_function: SIGNATURE_HASH_FUNCTION,
        signed_hashes_set,
    };
    let signature_data_bin = signature_data.serialize()?;
    let header_section = Section::Custom(CustomSection::new(
        SIGNATURE_SECTION_HEADER_NAME.to_string(),
        signature_data_bin,
    ));
    Ok(header_section)
}

pub fn sign(
    sk: &SecretKey,
    in_file: &str,
    out_file: &str,
    signature_file: Option<&str>,
    splits: Option<Vec<usize>>,
) -> Result<(), WSError> {
    let splits = splits.unwrap_or_default();

    let mut module = Module::deserialize_from_file(in_file)?;
    let mut hasher = Hash::new();
    let mut hashes = vec![];

    let mut out_sections = vec![];
    let header_section = Section::Custom(CustomSection::default());
    if signature_file.is_none() {
        out_sections.push(header_section);
    }

    let mut splits_cursor = splits.iter();
    let mut next_split = splits_cursor.next();
    for (idx, section) in module.sections.iter().enumerate() {
        if let Section::Custom(custom_section) = section {
            if custom_section.is_signature_header() {
                debug!("A signature section was already present.");
                if idx != 0 {
                    debug!("WARNING: the signature section was not the first module section.")
                }
                continue;
            }
        }
        if Some(&idx) == next_split {
            let delimiter = new_delimiter_section()?;
            hasher.update(delimiter.payload());
            out_sections.push(delimiter);
            hashes.push(hasher.finalize().to_vec());
            hasher = Hash::new();
            next_split = splits_cursor.next();
        }
        hasher.update(section.payload());
        out_sections.push(section.clone());
    }
    let delimiter = new_delimiter_section()?;
    hasher.update(delimiter.payload());
    if signature_file.is_none() {
        out_sections.push(delimiter);
    }
    hashes.push(hasher.finalize().to_vec());

    let header_section = build_header_section(sk, hashes)?;

    if let Some(signature_file) = signature_file {
        File::create(signature_file)?.write_all(header_section.payload())?;
    } else {
        out_sections[0] = header_section;
    }
    module.sections = out_sections;
    module.serialize_to_file(out_file)?;
    Ok(())
}

pub fn verify(
    pk: &PublicKey,
    in_file: &str,
    signature_file: Option<&str>,
) -> Result<Vec<RangeInclusive<usize>>, WSError> {
    let module = Module::deserialize_from_file(in_file)?;
    let sections_len = module.sections.len();
    let mut sections = module.sections.iter().enumerate();
    let signature_header: &Section;
    let signature_header_from_file;
    if let Some(signature_file) = signature_file {
        let mut custom_payload = vec![];
        File::open(signature_file)?.read_to_end(&mut custom_payload)?;
        signature_header_from_file = Section::new(SectionId::CustomSection, custom_payload)?;
        signature_header = &signature_header_from_file;
    } else {
        signature_header = sections.next().ok_or(WSError::ParseError)?.1;
    }
    let signature_header = match signature_header {
        Section::Custom(custom_section) if custom_section.is_signature_header() => custom_section,
        _ => {
            debug!("This module is not signed");
            return Err(WSError::NoSignatures);
        }
    };
    let signature_data = signature_header.signature_data()?;
    if signature_data.specification_version != SIGNATURE_VERSION {
        debug!(
            "Unsupported specification version: {:02x}",
            signature_data.specification_version
        );
        return Err(WSError::ParseError);
    }
    if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
        debug!(
            "Unsupported hash function: {:02x}",
            signature_data.specification_version
        );
        return Err(WSError::ParseError);
    }

    let mut valid_hashes = HashSet::new();
    let signed_hashes_set = signature_data.signed_hashes_set;
    for signed_part in &signed_hashes_set {
        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
        msg.extend_from_slice(&[SIGNATURE_VERSION, SIGNATURE_HASH_FUNCTION]);
        let hashes = &signed_part.hashes;
        for hash in hashes {
            msg.extend_from_slice(hash);
        }
        for signature in &signed_part.signatures {
            if pk
                .pk
                .verify(
                    &msg,
                    &ed25519_compact::Signature::from_slice(&signature.signature)?,
                )
                .is_err()
            {
                continue;
            }
            debug!(
                "Hash signature is valid for key [{}]",
                Hex::encode_to_string(&*pk.pk).unwrap()
            );
            for hash in hashes {
                valid_hashes.insert(hash);
            }
        }
    }
    if valid_hashes.is_empty() {
        debug!("No valid signatures");
        return Err(WSError::VerificationFailed);
    }
    debug!("Hashes matching the signature:");
    for valid_hash in &valid_hashes {
        debug!("  - [{}]", Hex::encode_to_string(&valid_hash).unwrap());
    }
    let mut hasher = Hash::new();
    let mut matching_section_ranges = vec![];
    debug!("Computed hashes:");
    for (idx, section) in sections {
        hasher.update(section.payload());
        match section {
            Section::Custom(custom_section) if custom_section.is_signature_delimiter() => {
                let h = hasher.finalize().to_vec();
                debug!("  - [{}]", Hex::encode_to_string(&h).unwrap());
                if !valid_hashes.contains(&h) {
                    return Err(WSError::VerificationFailed);
                }
                matching_section_ranges.push(0..=idx);
                hasher = Hash::new();
            }
            _ => {
                if idx + 1 == sections_len && signature_file.is_none() {
                    return Err(WSError::VerificationFailed);
                }
            }
        }
    }
    debug!("Valid, signed ranges:");
    for range in &matching_section_ranges {
        debug!("  - {}...{}", range.start(), range.end());
    }
    Ok(matching_section_ranges)
}
