use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use log::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;

impl SecretKey {
    /// Sign a module with the secret key.
    ///
    /// If the module was already signed, the signature is replaced.
    ///
    /// `key_id` is the key identifier of the public key, to be stored with the signature.
    /// This parameter is optional.
    pub fn sign(&self, mut module: Module, key_id: Option<&Vec<u8>>) -> Result<Module, WSError> {
        let mut out_sections = vec![Section::Custom(CustomSection::default())];
        let mut hasher = Hash::new();
        for section in module.sections.into_iter() {
            if section.is_signature_header() {
                continue;
            }
            section.serialize(&mut hasher)?;
            out_sections.push(section);
        }
        let h = hasher.finalize().to_vec();

        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
        msg.extend_from_slice(&[SIGNATURE_VERSION, SIGNATURE_HASH_FUNCTION]);
        msg.extend_from_slice(&h);

        let signature = self.sk.sign(msg, None).to_vec();

        let signature_for_hashes = SignatureForHashes {
            key_id: key_id.cloned(),
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
}

impl PublicKey {
    /// Verify a module's signature.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// This simplified interface verifies the entire module, with a single public key.
    pub fn verify(&self, reader: &mut impl Read) -> Result<(), WSError> {
        let signature_header = match Module::stream(reader)?
            .next()
            .ok_or(WSError::ParseError)??
        {
            Section::Custom(custom_section) if custom_section.is_signature_header() => {
                custom_section
            }
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
        let valid_hashes = self.valid_hashes_for_pk(&signed_hashes_set)?;
        if valid_hashes.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }

        let mut hasher = Hash::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.read(&mut buf)? {
                0 => break,
                n => {
                    hasher.update(&buf[..n]);
                }
            }
        }
        let h = hasher.finalize().to_vec();

        if valid_hashes.contains(&h) {
            Ok(())
        } else {
            Err(WSError::VerificationFailed)
        }
    }
}

impl PublicKeySet {
    /// Verify a module's signature with multiple public keys.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// This simplified interface verifies the entire module, with all public keys from the set.
    /// It returns the set of public keys for which a valid signature was found.
    pub fn verify(&self, reader: &mut impl Read) -> Result<HashSet<&PublicKey>, WSError> {
        let signature_header = match Module::stream(reader)?
            .next()
            .ok_or(WSError::ParseError)??
        {
            Section::Custom(custom_section) if custom_section.is_signature_header() => {
                custom_section
            }
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
        let valid_hashes_for_pks: HashMap<&PublicKey, HashSet<&Vec<u8>>> = self
            .pks
            .iter()
            .filter_map(|pk| match pk.valid_hashes_for_pk(&signed_hashes_set) {
                Ok(valid_hashes) if !valid_hashes.is_empty() => Some((pk, valid_hashes)),
                _ => None,
            })
            .collect();
        if valid_hashes_for_pks.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }

        let mut hasher = Hash::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.read(&mut buf)? {
                0 => break,
                n => {
                    hasher.update(&buf[..n]);
                }
            }
        }
        let h = hasher.finalize().to_vec();
        let mut valid_pks = HashSet::new();
        for (pk, valid_hashes) in valid_hashes_for_pks {
            if valid_hashes.contains(&h) {
                valid_pks.insert(pk);
            }
        }
        if valid_pks.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }
        Ok(valid_pks)
    }
}
