use crate::error::*;
use crate::sig_sections::*;
use crate::varint;

use ct_codecs::{Encoder, Hex};
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, prelude::*, BufReader, BufWriter};
use std::str;

pub const WASM_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SectionId {
    CustomSection,
    Type,
    Import,
    Function,
    Table,
    Memory,
    Global,
    Export,
    Start,
    Element,
    Code,
    Data,
    Extension(u8),
}

impl From<u8> for SectionId {
    fn from(v: u8) -> Self {
        match v {
            0 => (SectionId::CustomSection),
            1 => (SectionId::Type),
            2 => (SectionId::Import),
            3 => (SectionId::Function),
            4 => (SectionId::Table),
            5 => (SectionId::Memory),
            6 => (SectionId::Global),
            7 => (SectionId::Export),
            8 => (SectionId::Start),
            9 => (SectionId::Element),
            10 => (SectionId::Code),
            11 => (SectionId::Data),
            x => (SectionId::Extension(x)),
        }
    }
}

impl From<SectionId> for u8 {
    fn from(v: SectionId) -> Self {
        match v {
            SectionId::CustomSection => 0,
            SectionId::Type => 1,
            SectionId::Import => 2,
            SectionId::Function => 3,
            SectionId::Table => 4,
            SectionId::Memory => 5,
            SectionId::Global => 6,
            SectionId::Export => 7,
            SectionId::Start => 8,
            SectionId::Element => 9,
            SectionId::Code => 10,
            SectionId::Data => 11,
            SectionId::Extension(x) => x,
        }
    }
}

impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SectionId::CustomSection => write!(f, "custom section"),
            SectionId::Type => write!(f, "types section"),
            SectionId::Import => write!(f, "imports section"),
            SectionId::Function => write!(f, "functions section"),
            SectionId::Table => write!(f, "table section"),
            SectionId::Memory => write!(f, "memory section"),
            SectionId::Global => write!(f, "global section"),
            SectionId::Export => write!(f, "exports section"),
            SectionId::Start => write!(f, "start section"),
            SectionId::Element => write!(f, "elements section"),
            SectionId::Code => write!(f, "code section"),
            SectionId::Data => write!(f, "data section"),
            SectionId::Extension(x) => write!(f, "section id#{}", x),
        }
    }
}

#[derive(Clone)]
pub struct Section {
    pub id: SectionId,
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
        Ok(Section {
            id: SectionId::CustomSection,
            payload,
        })
    }
}

impl Section {
    pub fn serialize<W: Write>(&self, writer: &mut BufWriter<W>) -> Result<(), WSError> {
        varint::put(writer, u8::from(self.id) as _)?;
        varint::put(writer, self.payload.len() as _)?;
        writer.write_all(&self.payload)?;
        Ok(())
    }

    pub fn new(id: SectionId, payload: Vec<u8>) -> Section {
        Section { id, payload }
    }

    pub fn custom_section_get(&self) -> Result<CustomSection, WSError> {
        if !matches!(self.id, SectionId::CustomSection) {
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

    pub fn get_signature_data(&self) -> Result<SignatureData, WSError> {
        let custom_section = self.custom_section_get()?;
        let header_payload = SignatureData::deserialize(&custom_section.custom_payload)
            .map_err(|_| WSError::ParseError)?;
        Ok(header_payload)
    }

    pub fn is_signature_header(&self) -> Result<bool, WSError> {
        if self.id != SectionId::CustomSection {
            return Ok(false);
        }
        Ok(self.custom_section_get()?.name == SIGNATURE_SECTION_HEADER_NAME)
    }

    pub fn is_signature_delimiter(&self) -> Result<bool, WSError> {
        if self.id != SectionId::CustomSection {
            return Ok(false);
        }
        Ok(self.custom_section_get()?.name == SIGNATURE_SECTION_DELIMITER_NAME)
    }

    pub fn type_to_string(&self, verbose: bool) -> Result<String, WSError> {
        match self.id {
            SectionId::CustomSection => {
                let custom_section = self.custom_section_get()?;
                if !verbose {
                    Ok(format!("custom section: [{}]", custom_section.name))
                } else {
                    match custom_section.name.as_str() {
                        SIGNATURE_SECTION_DELIMITER_NAME => Ok(format!(
                            "custom section: [{}]\n- delimiter: [{}]\n",
                            custom_section.name,
                            Hex::encode_to_string(custom_section.custom_payload).unwrap()
                        )),
                        SIGNATURE_SECTION_HEADER_NAME => {
                            let signature_data =
                                SignatureData::deserialize(&custom_section.custom_payload)
                                    .map_err(|_| WSError::ParseError)?;
                            let mut s = String::new();
                            writeln!(
                                s,
                                "- specification version: 0x{:02x}",
                                signature_data.specification_version,
                            )
                            .unwrap();
                            writeln!(
                                s,
                                "- hash function: 0x{:02x} (SHA-256)",
                                signature_data.hash_function
                            )
                            .unwrap();
                            writeln!(s, "- (hashes,signatures) set:").unwrap();
                            for signed_parts in &signature_data.signed_hashes_set {
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
                }
            }
            x => Ok(x.to_string()),
        }
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            self.type_to_string(false)
                .unwrap_or_else(|_| self.id.to_string())
        )
    }
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            self.type_to_string(true)
                .unwrap_or_else(|_| self.id.to_string())
        )
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
                Ok(id) => SectionId::from(id),
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
