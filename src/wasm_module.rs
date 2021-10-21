use crate::error::*;
use crate::sig_sections::*;
use crate::varint;

use ct_codecs::{Encoder, Hex};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, prelude::*, BufReader, BufWriter};
use std::str;

pub const WASM_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Clone)]
pub struct Section {
    pub id: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CustomSection {
    pub name: String,
    pub custom_payload: Vec<u8>,
}

impl CustomSection {
    pub fn to_section(&self) -> Result<Section, WSError> {
        let mut writer = BufWriter::new(io::Cursor::new(Vec::new()));
        varint::put(&mut writer, self.name.len() as _)?;
        writer.write_all(self.name.as_bytes())?;
        writer.write_all(&self.custom_payload)?;
        let payload = writer.into_inner().unwrap().into_inner();
        Ok(Section { id: 0, payload })
    }
}

impl Section {
    pub fn serialize<W: Write>(&self, writer: &mut BufWriter<W>) -> Result<(), WSError> {
        varint::put(writer, self.id as _)?;
        varint::put(writer, self.payload.len() as _)?;
        writer.write_all(&self.payload)?;
        Ok(())
    }

    pub fn new(id: u8, payload: Vec<u8>) -> Section {
        Section { id, payload }
    }

    pub fn custom_section_get(&self) -> Result<CustomSection, WSError> {
        if self.id != 0 {
            return Err(WSError::ParseError);
        }
        let mut reader = BufReader::new(io::Cursor::new(&self.payload));
        let name_len = varint::get32(&mut reader)? as usize;
        let mut name_slice = vec![0u8; name_len];
        reader.read_exact(&mut name_slice)?;
        let name = str::from_utf8(&name_slice)?.to_string();
        let mut payload = Vec::new();
        let len = reader.read_to_end(&mut payload)?;
        payload.truncate(len);
        Ok(CustomSection {
            name,
            custom_payload: payload,
        })
    }

    pub fn get_signature_header_payload(&self) -> Result<SignatureData, WSError> {
        let custom_section = self.custom_section_get()?;
        let header_payload: SignatureData = bincode::deserialize(&custom_section.custom_payload)
            .map_err(|_| WSError::ParseError)?;
        Ok(header_payload)
    }

    pub fn is_signature_header(&self) -> Result<bool, WSError> {
        if self.id != 0 {
            return Ok(false);
        }
        Ok(self.custom_section_get()?.name == SIGNATURE_SECTION_HEADER_NAME)
    }

    pub fn is_signature_delimiter(&self) -> Result<bool, WSError> {
        if self.id != 0 {
            return Ok(false);
        }
        Ok(self.custom_section_get()?.name == SIGNATURE_SECTION_DELIMITER_NAME)
    }

    pub fn type_to_string(&self, verbose: bool) -> Result<String, WSError> {
        match self.id {
            0 => {
                let custom_section = self.custom_section_get()?;
                if verbose {
                    match custom_section.name.as_str() {
                        SIGNATURE_SECTION_DELIMITER_NAME => Ok(format!(
                            "custom section: [{}]\n- delimiter: [{}]\n",
                            custom_section.name,
                            Hex::encode_to_string(custom_section.custom_payload).unwrap()
                        )),
                        SIGNATURE_SECTION_HEADER_NAME => {
                            let header_payload: SignatureData =
                                bincode::deserialize(&custom_section.custom_payload)
                                    .map_err(|_| WSError::ParseError)?;
                            let mut s = String::new();
                            writeln!(
                                s,
                                "- specification version: 0x{:02x}",
                                header_payload.specification_version,
                            )
                            .unwrap();
                            writeln!(
                                s,
                                "- hash function: 0x{:02x} (SHA-256)",
                                header_payload.hash_function
                            )
                            .unwrap();
                            writeln!(s, "- (hashes,signatures) set:").unwrap();
                            for signed_parts in &header_payload.signed_hashes_set {
                                writeln!(s, "  - hashes:").unwrap();
                                for hash in &signed_parts.hashes {
                                    writeln!(s, "    - [{}]", Hex::encode_to_string(hash).unwrap())
                                        .unwrap();
                                }
                                writeln!(s, "  - signatures:").unwrap();
                                for signature in &signed_parts.signatures {
                                    write!(
                                        s,
                                        "    - [{}]",
                                        Hex::encode_to_string(&signature.signature).unwrap()
                                    )
                                    .unwrap();
                                    match &signature.key_id {
                                        None => writeln!(s, " (no key id)").unwrap(),
                                        Some(key_id) => writeln!(
                                            s,
                                            " (key id: [{}])",
                                            Hex::encode_to_string(key_id).unwrap()
                                        )
                                        .unwrap(),
                                    }
                                }
                            }
                            Ok(format!("custom section: [{}]\n{}", custom_section.name, s))
                        }
                        _ => Ok(format!("custom section: [{}]", custom_section.name)),
                    }
                } else {
                    Ok(format!("custom section: [{}]", custom_section.name))
                }
            }
            1 => Ok("type section".to_string()),
            2 => Ok("import section".to_string()),
            3 => Ok("function section".to_string()),
            4 => Ok("table section".to_string()),
            5 => Ok("memory section".to_string()),
            6 => Ok("global section".to_string()),
            7 => Ok("export section".to_string()),
            8 => Ok("start section".to_string()),
            9 => Ok("element section".to_string()),
            10 => Ok("code section".to_string()),
            11 => Ok("data section".to_string()),
            _ => {
                dbg!(self.id);
                Err(WSError::ParseError)
            }
        }
    }
}

pub struct Module {
    pub sections: Vec<Section>,
}

impl Module {
    pub fn parse(file: &str) -> Result<Self, WSError> {
        let fp = File::open(file)?;
        let mut reader = BufReader::new(fp);
        let mut header = [0u8; 8];
        reader.read_exact(&mut header)?;
        if header != WASM_HEADER {
            return Err(WSError::ParseError);
        }

        let mut sections = Vec::new();
        loop {
            let id = match varint::get7(&mut reader) {
                Ok(id) => id,
                Err(WSError::Eof) => break,
                Err(e) => return Err(e),
            };
            let len = varint::get32(&mut reader)? as usize;
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload)?;
            let section = Section { id, payload };
            sections.push(section);
        }
        Ok(Module { sections })
    }

    pub fn serialize(&self, file: &str) -> Result<(), WSError> {
        let fp = File::create(file)?;
        let mut writer = BufWriter::new(fp);
        writer.write_all(&WASM_HEADER)?;
        for section in &self.sections {
            section.serialize(&mut writer)?;
        }
        Ok(())
    }
}
