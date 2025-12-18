use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use log::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;

/// A sized predicate, used to verify a predicate*public_key matrix.
pub type BoxedPredicate = Box<dyn Fn(&Section) -> bool>;

impl PublicKeySet {
    /// Given a set of predicates and a set of public keys, check which public keys verify a signature over sections matching each predicate.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` is the detached signature of the module, if any.
    ///
    /// `predicates` is a set of predicates.
    ///
    /// The function returns a vector which maps every predicate to a set of public keys verifying a signature over sections matching the predicate.
    /// The vector is sorted by predicate index.
    pub fn verify_matrix(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
        predicates: &[impl Fn(&Section) -> bool],
    ) -> Result<Vec<HashSet<&PublicKey>>, WSError> {
        let mut sections = Module::iterate(Module::init_from_reader(reader)?)?;
        let signature_header_section = if let Some(detached_signature) = &detached_signature {
            Section::Custom(CustomSection::new(
                SIGNATURE_SECTION_HEADER_NAME.to_string(),
                detached_signature.to_vec(),
            ))
        } else {
            sections.next().ok_or(WSError::ParseError)??
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
                signature_data.hash_function,
            );
            return Err(WSError::ParseError);
        }
        if signature_data.content_type != SIGNATURE_WASM_MODULE_CONTENT_TYPE {
            debug!(
                "Unsupported content type: {:02x}",
                signature_data.content_type,
            );
            return Err(WSError::ParseError);
        }

        let signed_hashes_set = signature_data.signed_hashes_set;
        let mut valid_hashes_for_pks = HashMap::new();
        for pk in &self.pks {
            let valid_hashes = pk.valid_hashes_for_pk(&signed_hashes_set)?;
            if !valid_hashes.is_empty() {
                valid_hashes_for_pks.insert(pk.clone(), valid_hashes);
            }
        }
        if valid_hashes_for_pks.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }

        let mut section_state_for_pks: HashMap<PublicKey, Option<bool>> = HashMap::new();
        for pk in valid_hashes_for_pks.keys() {
            section_state_for_pks.insert(pk.clone(), None);
        }

        let mut verify_failures: Vec<HashSet<PublicKey>> = vec![HashSet::new(); predicates.len()];

        let mut hasher = Hash::new();
        for section in sections {
            let section = section?;
            section.serialize(&mut hasher)?;
            if section.is_signature_delimiter() {
                let h = hasher.finalize().to_vec();
                for (pk, state) in section_state_for_pks.iter_mut() {
                    if *state == Some(false) {
                        *state = None;
                        continue;
                    }
                    if let Some(valid_hashes) = valid_hashes_for_pks.get(pk) {
                        if !valid_hashes.contains(&h) {
                            valid_hashes_for_pks.remove(pk);
                        }
                    }
                    *state = None;
                }
            } else {
                for (idx, predicate) in predicates.iter().enumerate() {
                    let section_must_be_signed = predicate(&section);
                    for (pk, state) in section_state_for_pks.iter_mut() {
                        if let Some(expected) = *state {
                            if section_must_be_signed != expected {
                                verify_failures[idx].insert(pk.clone());
                            }
                        } else {
                            *state = Some(section_must_be_signed);
                        }
                    }
                }
            }
        }

        let mut results: Vec<HashSet<&PublicKey>> = Vec::new();
        for (idx, _predicate) in predicates.iter().enumerate() {
            let mut valid_for_predicate: HashSet<&PublicKey> = HashSet::new();
            for pk in &self.pks {
                if !valid_hashes_for_pks.contains_key(pk) {
                    continue;
                }
                if !verify_failures[idx].contains(pk) {
                    valid_for_predicate.insert(pk);
                }
            }
            results.push(valid_for_predicate);
        }

        if results.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailedForPredicates);
        }
        Ok(results)
    }
}
