use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use ct_codecs::{Encoder, Hex};
use log::*;
use std::collections::HashSet;
use std::io::Read;

impl SecretKey {
    /// Sign a module with the secret key.
    ///
    /// If the module was already signed, the new signature is added to the existing ones.
    /// `key_id` is the key identifier of the public key, to be stored with the signature.
    /// This parameter is optional.
    ///
    /// `detached` prevents the signature from being embedded.
    ///
    /// `allow_extensions` allows new sections to be added to the module later, while retaining the ability for the original module to be verified.
    pub fn sign_multi(
        &self,
        mut module: Module,
        key_id: Option<&Vec<u8>>,
        detached: bool,
        allow_extensions: bool,
    ) -> Result<(Module, Vec<u8>), WSError> {
        let mut hasher = Hash::new();
        let mut hashes = vec![];

        let mut out_sections = vec![];
        let header_section = Section::Custom(CustomSection::default());
        if !detached {
            if allow_extensions {
                module = module.split(|_| true)?;
            }
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
                    section.serialize(&mut hasher)?;
                    out_sections.push(section.clone());
                    hashes.push(hasher.finalize().to_vec());
                    last_section_was_a_signature = true;
                    continue;
                }
                last_section_was_a_signature = false;
            }
            section.serialize(&mut hasher)?;
            out_sections.push(section.clone());
        }
        if !last_section_was_a_signature {
            hashes.push(hasher.finalize().to_vec());
        }
        let header_section =
            Self::build_header_section(previous_signature_data, self, key_id, hashes)?;
        if detached {
            Ok((module, header_section.payload().to_vec()))
        } else {
            out_sections[0] = header_section;
            module.sections = out_sections;
            let signature = module.sections[0].payload().to_vec();
            Ok((module, signature))
        }
    }

    fn build_header_section(
        previous_signature_data: Option<SignatureData>,
        sk: &SecretKey,
        key_id: Option<&Vec<u8>>,
        hashes: Vec<Vec<u8>>,
    ) -> Result<Section, WSError> {
        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
        msg.extend_from_slice(&[
            SIGNATURE_VERSION,
            SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            SIGNATURE_HASH_FUNCTION,
        ]);
        for hash in &hashes {
            msg.extend_from_slice(hash);
        }

        debug!("* Adding signature:\n");

        debug!(
            "sig = Ed25519(sk, \"{}\" ‖ {:02x} ‖ {:02x} ‖ {:02x} ‖ {})\n",
            SIGNATURE_WASM_DOMAIN,
            SIGNATURE_VERSION,
            SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            SIGNATURE_HASH_FUNCTION,
            Hex::encode_to_string(&msg[SIGNATURE_WASM_DOMAIN.len() + 2..]).unwrap()
        );

        let signature = sk.sk.sign(msg, None).to_vec();

        debug!("    = {}\n\n", Hex::encode_to_string(&signature).unwrap());

        let signature_for_hashes = SignatureForHashes {
            key_id: key_id.cloned(),
            alg_id: ED25519_PK_ID,
            signature,
        };
        let mut signed_hashes_set = match &previous_signature_data {
            None => vec![],
            Some(previous_signature_data)
                if previous_signature_data.specification_version == SIGNATURE_VERSION
                    && previous_signature_data.content_type
                        == SIGNATURE_WASM_MODULE_CONTENT_TYPE
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
            let new_signed_section_sequences = SignedHashes { hashes, signatures };
            signed_hashes_set.push(new_signed_section_sequences);
        }
        let signature_data = SignatureData {
            specification_version: SIGNATURE_VERSION,
            content_type: SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            hash_function: SIGNATURE_HASH_FUNCTION,
            signed_hashes_set,
        };
        let header_section = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            signature_data.serialize()?,
        ));
        Ok(header_section)
    }
}

impl PublicKey {
    /// Verify the signature of a module, or module subset.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` allows the caller to verify a module without an embedded signature.
    ///
    /// `predicate` should return `true` for each section that needs to be included in the signature verification.
    pub fn verify_multi<P>(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
        mut predicate: P,
    ) -> Result<(), WSError>
    where
        P: FnMut(&Section) -> bool,
    {
        let mut sections = Module::stream(reader)?.enumerate();
        let signature_header_section = if let Some(detached_signature) = &detached_signature {
            Section::Custom(CustomSection::new(
                SIGNATURE_SECTION_HEADER_NAME.to_string(),
                detached_signature.to_vec(),
            ))
        } else {
            sections.next().ok_or(WSError::ParseError)?.1?
        };
        let signature_header = match signature_header_section {
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
                signature_data.hash_function
            );
            return Err(WSError::ParseError);
        }

        let signed_hashes_set = signature_data.signed_hashes_set;
        let valid_hashes = self.valid_hashes_for_pk(&signed_hashes_set)?;
        if valid_hashes.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }
        debug!("Hashes matching the signature:");
        for valid_hash in &valid_hashes {
            debug!("  - [{}]", Hex::encode_to_string(valid_hash).unwrap());
        }
        let mut hasher = Hash::new();
        let mut matching_section_ranges = vec![];
        debug!("Computed hashes:");
        let mut section_sequence_must_be_signed: Option<bool> = None;
        for (idx, section) in sections {
            let section = section?;
            section.serialize(&mut hasher)?;
            if section.is_signature_delimiter() {
                if section_sequence_must_be_signed == Some(false) {
                    section_sequence_must_be_signed = None;
                    continue;
                }
                let h = hasher.finalize().to_vec();
                debug!("  - [{}]", Hex::encode_to_string(&h).unwrap());
                if !valid_hashes.contains(&h) {
                    return Err(WSError::VerificationFailedForPredicates);
                }
                matching_section_ranges.push(0..=idx);
                section_sequence_must_be_signed = None;
            } else {
                let section_must_be_signed = predicate(&section);
                match section_sequence_must_be_signed {
                    None => section_sequence_must_be_signed = Some(section_must_be_signed),
                    Some(false) if section_must_be_signed => {
                        return Err(WSError::VerificationFailedForPredicates);
                    }
                    Some(true) if !section_must_be_signed => {
                        return Err(WSError::VerificationFailedForPredicates);
                    }
                    _ => {}
                }
            }
        }
        debug!("Valid, signed ranges:");
        for range in &matching_section_ranges {
            debug!("  - {}...{}", range.start(), range.end());
        }
        Ok(())
    }

    pub(crate) fn valid_hashes_for_pk<'t>(
        &self,
        signed_hashes_set: &'t [SignedHashes],
    ) -> Result<HashSet<&'t Vec<u8>>, WSError> {
        let mut valid_hashes = HashSet::new();
        for signed_section_sequence in signed_hashes_set {
            let mut msg: Vec<u8> = vec![];
            msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
            msg.extend_from_slice(&[
                SIGNATURE_VERSION,
                SIGNATURE_WASM_MODULE_CONTENT_TYPE,
                SIGNATURE_HASH_FUNCTION,
            ]);
            let hashes = &signed_section_sequence.hashes;
            for hash in hashes {
                msg.extend_from_slice(hash);
            }
            for signature in &signed_section_sequence.signatures {
                match (&signature.key_id, &self.key_id) {
                    (Some(signature_key_id), Some(pk_key_id)) if signature_key_id != pk_key_id => {
                        continue;
                    }
                    _ => {}
                }
                if self
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
                    Hex::encode_to_string(*self.pk).unwrap()
                );
                for hash in hashes {
                    valid_hashes.insert(hash);
                }
            }
        }
        Ok(valid_hashes)
    }
}
