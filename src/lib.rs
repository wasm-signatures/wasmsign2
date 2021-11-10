#![allow(clippy::vec_init_then_push)]
#![forbid(unsafe_code)]

mod error;
mod keys;
mod sig_sections;
mod varint;
mod wasm_module;

pub use error::*;
pub use keys::*;
use sig_sections::*;
pub use wasm_module::*;

use ct_codecs::{Encoder, Hex};
use hmac_sha256::Hash;
use log::*;
use std::collections::HashSet;
use std::str;

const SIGNATURE_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;

pub fn show(file: &str, verbose: bool) -> Result<(), WSError> {
    let module = Module::deserialize_from_file(file)?;
    for (idx, section) in module.sections.iter().enumerate() {
        println!("{}:\t{}", idx, section.display(verbose));
    }
    Ok(())
}

fn build_header_section(
    previous_signature_data: Option<SignatureData>,
    sk: &SecretKey,
    key_id: &Option<Vec<u8>>,
    hashes: Vec<Vec<u8>>,
) -> Result<Section, WSError> {
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
        key_id: key_id.clone(),
        signature,
    };
    let mut signed_hashes_set = match &previous_signature_data {
        None => vec![],
        Some(previous_signature_data)
            if previous_signature_data.specification_version == SIGNATURE_VERSION
                && previous_signature_data.hash_function == SIGNATURE_HASH_FUNCTION =>
        {
            previous_signature_data.signed_hashes_set.clone()
        }
        _ => return Err(WSError::IncompatibleSignatureVersion),
    };

    let mut new_hashes = true;
    for previous_signed_hashes_set in &mut signed_hashes_set {
        if previous_signed_hashes_set.hashes == hashes {
            if previous_signed_hashes_set.signatures.iter().any(|sig| {
                sig.key_id == signature_for_hashes.key_id
                    && sig.signature == signature_for_hashes.signature
            }) {
                debug!("A matching hash set was already signed with that key.");
                return Err(WSError::DuplicateSignature);
            }
            debug!("A matching hash set was already signed.");
            previous_signed_hashes_set
                .signatures
                .push(signature_for_hashes.clone());
            new_hashes = false;
            break;
        }
    }
    if new_hashes {
        debug!("No matching hash was previously signed.");
        let signatures = vec![signature_for_hashes];
        let new_signed_parts = SignedHashes { hashes, signatures };
        signed_hashes_set.push(new_signed_parts);
    }
    let signature_data = SignatureData {
        specification_version: SIGNATURE_VERSION,
        hash_function: SIGNATURE_HASH_FUNCTION,
        signed_hashes_set,
    };
    let header_section = Section::Custom(CustomSection::new(
        SIGNATURE_SECTION_HEADER_NAME.to_string(),
        signature_data.serialize()?,
    ));
    Ok(header_section)
}

pub fn split<P>(module: Module, mut predicate: P) -> Result<Module, WSError>
where
    P: FnMut(&Section) -> bool,
{
    let mut out_sections = vec![];
    let mut flip = false;
    let mut last_was_delimiter = false;
    for (idx, section) in module.sections.into_iter().enumerate() {
        if section.is_signature_delimiter() {
            out_sections.push(section);
            last_was_delimiter = true;
            continue;
        }
        let section_can_be_signed = predicate(&section);
        if idx == 0 {
            flip = !section_can_be_signed;
        } else if section_can_be_signed == flip {
            if !last_was_delimiter {
                let delimiter = new_delimiter_section()?;
                out_sections.push(delimiter);
            }
            flip = !flip;
        }
        out_sections.push(section);
        last_was_delimiter = false;
    }
    if let Some(last_section) = out_sections.last() {
        if !last_section.is_signature_delimiter() {
            let delimiter = new_delimiter_section()?;
            out_sections.push(delimiter);
        }
    }
    Ok(Module {
        sections: out_sections,
    })
}

pub fn sign_all(sk: &SecretKey, mut module: Module) -> Result<Module, WSError> {
    let mut out_sections = vec![Section::Custom(CustomSection::default())];
    module = split(module, |_| true)?;
    let mut hasher = Hash::new();
    for section in module.sections.into_iter() {
        if section.is_signature_header() {
            continue;
        }
        hasher.update(section.payload());
        out_sections.push(section);
    }
    let h = hasher.finalize().to_vec();

    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    msg.extend_from_slice(&[SIGNATURE_VERSION, SIGNATURE_HASH_FUNCTION]);

    let signature = sk.sk.sign(msg, None).to_vec();

    let signature_for_hashes = SignatureForHashes {
        key_id: None,
        signature,
    };
    let signed_hashes_set = vec![SignedHashes {
        hashes: vec![h],
        signatures: vec![signature_for_hashes],
    }];
    let signature_data = SignatureData {
        specification_version: SIGNATURE_VERSION,
        hash_function: SIGNATURE_HASH_FUNCTION,
        signed_hashes_set,
    };
    out_sections[0] = Section::Custom(CustomSection::new(
        SIGNATURE_SECTION_HEADER_NAME.to_string(),
        signature_data.serialize()?,
    ));

    module.sections = out_sections;
    Ok(module)
}

pub fn sign(
    sk: &SecretKey,
    pk: Option<&PublicKey>,
    mut module: Module,
    detached: bool,
) -> Result<(Module, Vec<u8>), WSError> {
    let mut hasher = Hash::new();
    let mut hashes = vec![];

    let mut out_sections = vec![];
    let header_section = Section::Custom(CustomSection::default());
    if !detached {
        module = split(module, |_| true)?;
        out_sections.push(header_section);
    }
    let mut previous_signature_data = None;
    let mut last_section_was_a_signature = false;
    for (idx, section) in module.sections.iter().enumerate() {
        if let Section::Custom(custom_section) = section {
            if custom_section.is_signature_header() {
                debug!("A signature section was already present.");
                if idx != 0 {
                    error!("The signature section was not the first module section");
                    continue;
                }
                assert_eq!(previous_signature_data, None);
                previous_signature_data = Some(custom_section.signature_data()?);
                continue;
            }
            if custom_section.is_signature_delimiter() {
                hasher.update(section.payload());
                out_sections.push(section.clone());
                hashes.push(hasher.finalize().to_vec());
                hasher = Hash::new();
                last_section_was_a_signature = true;
                continue;
            }
            last_section_was_a_signature = false;
        }
        hasher.update(section.payload());
        out_sections.push(section.clone());
    }
    if !last_section_was_a_signature {
        hashes.push(hasher.finalize().to_vec());
    }
    let key_id = match pk {
        None => &None,
        Some(pk) => pk.key_id(),
    };
    let header_section = build_header_section(previous_signature_data, sk, key_id, hashes)?;
    if detached {
        Ok((module, header_section.payload().to_vec()))
    } else {
        out_sections[0] = header_section;
        module.sections = out_sections;
        let signature = module.sections[0].payload().to_vec();
        Ok((module, signature))
    }
}

fn valid_hashes_for_pk<'t>(
    signed_hashes_set: &'t [SignedHashes],
    pk: &PublicKey,
) -> Result<HashSet<&'t Vec<u8>>, WSError> {
    let mut valid_hashes = HashSet::new();
    for signed_part in signed_hashes_set {
        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
        msg.extend_from_slice(&[SIGNATURE_VERSION, SIGNATURE_HASH_FUNCTION]);
        let hashes = &signed_part.hashes;
        for hash in hashes {
            msg.extend_from_slice(hash);
        }
        for signature in &signed_part.signatures {
            match (&signature.key_id, &pk.key_id) {
                (Some(signature_key_id), Some(pk_key_id)) if signature_key_id != pk_key_id => {
                    continue;
                }
                _ => {}
            }
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
    Ok(valid_hashes)
}

pub fn verify_all(pk: &PublicKey, module: &Module) -> Result<(), WSError> {
    let mut sections = module.sections.iter();

    let signature_header = match sections.next().ok_or(WSError::ParseError)? {
        Section::Custom(custom_section) if custom_section.is_signature_header() => custom_section,
        _ => {
            debug!("This module is not signed");
            return Err(WSError::NoSignatures);
        }
    };
    let signature_data = signature_header.signature_data()?;
    if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
        debug!(
            "Unsupported hash function: {:02x}",
            signature_data.specification_version
        );
        return Err(WSError::ParseError);
    }
    let signed_hashes_set = signature_data.signed_hashes_set;
    let valid_hashes = valid_hashes_for_pk(&signed_hashes_set, pk)?;
    if valid_hashes.is_empty() {
        debug!("No valid signatures");
        return Err(WSError::VerificationFailed);
    }

    let mut hasher = Hash::new();
    let mut last_section_is_a_delimiter = false;
    for section in sections {
        hasher.update(section.payload());
        last_section_is_a_delimiter = section.is_signature_delimiter();
    }
    if !last_section_is_a_delimiter {
        debug!("The last section is not a delimiter");
        return Err(WSError::VerificationFailed);
    }

    let h = hasher.finalize().to_vec();
    if valid_hashes.contains(&h) {
        debug!("Signature is valid");
        Ok(())
    } else {
        debug!("Signature is invalid");
        Err(WSError::VerificationFailed)
    }
}

pub fn verify<P>(
    pk: &PublicKey,
    module: &Module,
    detached_signature: Option<&[u8]>,
    mut predicate: P,
) -> Result<(), WSError>
where
    P: FnMut(&Section) -> bool,
{
    let mut sections = module.sections.iter().enumerate();
    let signature_header: &Section;
    let signature_header_from_detached_signature;
    if let Some(detached_signature) = &detached_signature {
        signature_header_from_detached_signature = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            detached_signature.to_vec(),
        ));
        signature_header = &signature_header_from_detached_signature;
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
    if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
        debug!(
            "Unsupported hash function: {:02x}",
            signature_data.specification_version
        );
        return Err(WSError::ParseError);
    }
    let signed_hashes_set = signature_data.signed_hashes_set;
    let valid_hashes = valid_hashes_for_pk(&signed_hashes_set, pk)?;
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
    let mut part_must_be_signed: Option<bool> = None;
    let mut last_section_is_a_delimiter = false;
    for (idx, section) in sections {
        let section_must_be_signed = predicate(section);
        hasher.update(section.payload());
        if section.is_signature_delimiter() {
            last_section_is_a_delimiter = true;
            let h = hasher.finalize().to_vec();
            debug!("  - [{}]", Hex::encode_to_string(&h).unwrap());
            if part_must_be_signed == Some(false) {
                continue;
            }
            if !valid_hashes.contains(&h) {
                return Err(WSError::VerificationFailed);
            }
            matching_section_ranges.push(0..=idx);
            hasher = Hash::new();
            part_must_be_signed = None;
        } else {
            last_section_is_a_delimiter = false;
            match part_must_be_signed {
                None => part_must_be_signed = Some(section_must_be_signed),
                Some(false) if section_must_be_signed => {
                    return Err(WSError::VerificationFailed);
                }
                Some(true) if !section_must_be_signed => {
                    return Err(WSError::VerificationFailed);
                }
                _ => {}
            }
        }
    }
    if !last_section_is_a_delimiter {
        debug!("The last section is not a delimiter");
        return Err(WSError::VerificationFailed);
    }
    debug!("Valid, signed ranges:");
    for range in &matching_section_ranges {
        debug!("  - {}...{}", range.start(), range.end());
    }
    Ok(())
}
