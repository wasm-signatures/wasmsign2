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
            0 => SectionId::CustomSection,
            1 => SectionId::Type,
            2 => SectionId::Import,
            3 => SectionId::Function,
            4 => SectionId::Table,
            5 => SectionId::Memory,
            6 => SectionId::Global,
            7 => SectionId::Export,
            8 => SectionId::Start,
            9 => SectionId::Element,
            10 => SectionId::Code,
            11 => SectionId::Data,
            x => SectionId::Extension(x),
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

pub trait SectionLike {
    fn id(&self) -> SectionId;
    fn payload(&self) -> &[u8];
    fn display(&self, verbose: bool) -> String;
}

#[derive(Debug, Clone)]
pub struct StandardSection {
    id: SectionId,
    payload: Vec<u8>,
}

impl StandardSection {
    pub fn new(id: SectionId, payload: Vec<u8>) -> Self {
        Self { id, payload }
    }
}

impl SectionLike for StandardSection {
    fn id(&self) -> SectionId {
        self.id
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn display(&self, _verbose: bool) -> String {
        self.id().to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CustomSection {
    name: String,
    payload: Vec<u8>,
}

impl CustomSection {
    pub fn new(name: String, payload: Vec<u8>) -> Self {
        Self { name, payload }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn serialize_outer_payload<W: Write>(
        &self,
        writer: &mut BufWriter<W>,
    ) -> Result<(), WSError> {
        varint::put(writer, self.name.len() as _)?;
        writer.write_all(self.name.as_bytes())?;
        writer.write_all(&self.payload)?;
        Ok(())
    }
}

impl SectionLike for CustomSection {
    fn id(&self) -> SectionId {
        SectionId::CustomSection
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn display(&self, verbose: bool) -> String {
        if !verbose {
            return format!("custom section: [{}]", self.name());
        }

        match self.name() {
            SIGNATURE_SECTION_DELIMITER_NAME => format!(
                "custom section: [{}]\n- delimiter: [{}]\n",
                self.name,
                Hex::encode_to_string(self.payload()).unwrap()
            ),
            SIGNATURE_SECTION_HEADER_NAME => {
                let signature_data = match SignatureData::deserialize(self.payload()) {
                    Ok(signature_data) => signature_data,
                    _ => return "undecodable signature header".to_string(),
                };
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
                        writeln!(s, "    - [{}]", Hex::encode_to_string(hash).unwrap()).unwrap();
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
                format!("custom section: [{}]\n{}", self.name(), s)
            }
            _ => format!("custom section: [{}]", self.name()),
        }
    }
}

#[derive(Clone)]
pub enum Section {
    Standard(StandardSection),
    Custom(CustomSection),
}

impl SectionLike for Section {
    fn id(&self) -> SectionId {
        match self {
            Section::Standard(s) => s.id(),
            Section::Custom(s) => s.id(),
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Section::Standard(s) => s.payload(),
            Section::Custom(s) => s.payload(),
        }
    }

    fn display(&self, verbose: bool) -> String {
        match self {
            Section::Standard(s) => s.display(verbose),
            Section::Custom(s) => s.display(verbose),
        }
    }
}

impl Section {
    pub fn new(id: SectionId, payload: Vec<u8>) -> Result<Self, WSError> {
        match id {
            SectionId::CustomSection => {
                let mut reader = BufReader::new(io::Cursor::new(payload));
                let name_len = varint::get32(&mut reader)? as usize;
                let mut name_slice = vec![0u8; name_len];
                reader.read_exact(&mut name_slice)?;
                let name = str::from_utf8(&name_slice)?.to_string();
                let mut payload = Vec::new();
                let len = reader.read_to_end(&mut payload)?;
                payload.truncate(len);
                Ok(Section::Custom(CustomSection::new(name, payload)))
            }
            _ => Ok(Section::Standard(StandardSection::new(id, payload))),
        }
    }

    pub fn deserialize<R: Read>(reader: &mut BufReader<R>) -> Result<Option<Self>, WSError> {
        let id = match varint::get7(reader) {
            Ok(id) => SectionId::from(id),
            Err(WSError::Eof) => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = varint::get32(reader)? as usize;
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload)?;
        let section = Section::new(id, payload)?;
        Ok(Some(section))
    }

    pub fn serialize<W: Write>(&self, writer: &mut BufWriter<W>) -> Result<(), WSError> {
        varint::put(writer, u8::from(self.id()) as _)?;
        match self {
            Section::Standard(s) => {
                varint::put(writer, s.payload().len() as _)?;
                writer.write_all(s.payload())?;
            }
            Section::Custom(s) => {
                s.serialize_outer_payload(writer)?;
            }
        }
        Ok(())
    }
}

impl CustomSection {
    pub fn is_signature_header(&self) -> bool {
        self.name() == SIGNATURE_SECTION_HEADER_NAME
    }

    pub fn is_signature_delimiter(&self) -> bool {
        self.name() == SIGNATURE_SECTION_DELIMITER_NAME
    }

    pub fn signature_data(&self) -> Result<SignatureData, WSError> {
        let header_payload =
            SignatureData::deserialize(self.payload()).map_err(|_| WSError::ParseError)?;
        Ok(header_payload)
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.display(false))
    }
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.display(true))
    }
}

#[derive(Debug, Clone, Default)]
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
            match Section::deserialize(&mut reader)? {
                None => break,
                Some(section) => sections.push(section),
            }
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
