use crate::signature::*;
use crate::wasm_module::*;

use log::*;

impl Module {
    /// Print the structure of a module to the standard output, mainly for debugging purposes.
    ///
    /// Set `verbose` to `true` in order to also print details about signature data.
    pub fn show(&self, verbose: bool) -> Result<(), WSError> {
        for (idx, section) in self.sections.iter().enumerate() {
            println!("{}:\t{}", idx, section.display(verbose));
        }
        Ok(())
    }

    /// Prepare a module for partial verification.
    ///
    /// The predicate should return `true` if a section is part of a set that can be verified,
    /// and `false` if the section can be ignored during verification.
    ///
    /// It is highly recommended to always include the standard sections in the signed set.
    pub fn split<P>(self, mut predicate: P) -> Result<Module, WSError>
    where
        P: FnMut(&Section) -> bool,
    {
        let mut out_sections = vec![];
        let mut flip = false;
        let mut last_was_delimiter = false;
        for (idx, section) in self.sections.into_iter().enumerate() {
            if section.is_signature_header() {
                info!("Module is already signed");
                out_sections.push(section);
                continue;
            }
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
            header: self.header,
            sections: out_sections,
        })
    }

    /// Detach the signature from a signed module.
    ///
    /// This function returns the module without the embedded signature,
    /// as well as the detached signature as a byte string.
    pub fn detach_signature(mut self) -> Result<(Module, Vec<u8>), WSError> {
        let mut out_sections = vec![];
        let mut sections = self.sections.into_iter();
        let detached_signature = match sections.next() {
            None => return Err(WSError::NoSignatures),
            Some(section) => {
                if !section.is_signature_header() {
                    return Err(WSError::NoSignatures);
                }
                section.payload().to_vec()
            }
        };
        for section in sections {
            out_sections.push(section);
        }
        self.sections = out_sections;
        debug!("Signature detached");
        Ok((self, detached_signature))
    }

    /// Embed a detached signature into a module.
    /// This function returns the module with embedded signature.
    pub fn attach_signature(mut self, detached_signature: &[u8]) -> Result<Module, WSError> {
        let mut out_sections = vec![];
        let sections = self.sections.into_iter();
        let signature_header = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            detached_signature.to_vec(),
        ));
        out_sections.push(signature_header);
        for section in sections {
            if section.is_signature_header() {
                return Err(WSError::SignatureAlreadyAttached);
            }
            out_sections.push(section);
        }
        self.sections = out_sections;
        debug!("Signature attached");
        Ok(self)
    }
}
