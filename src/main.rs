use anyhow::{anyhow, bail, ensure, Error};
use io::BufWriter;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::str;

#[derive(Debug, thiserror::Error)]
pub enum WSError {
    #[error("Internal error: [{0}]")]
    InternalError(String),
    #[error("Parse error")]
    ParseError,
    #[error("I/O error")]
    IOError(#[from] io::Error),
    #[error("EOF")]
    UTF8Error(#[from] std::str::Utf8Error),
    #[error("UTF-8 error")]
    Eof,
}

fn varint_get7<R: Read>(reader: &mut BufReader<R>) -> Result<u8, WSError> {
    let mut v: u8 = 0;
    for i in 0..1 {
        let mut byte = [0u8; 1];
        if let Err(e) = reader.read_exact(&mut byte) {
            return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                WSError::Eof
            } else {
                e.into()
            });
        };
        v |= ((byte[0] & 0x7f) as u8) << (i * 7);
        if (byte[0] & 0x80) == 0 {
            return Ok(v);
        }
    }
    Err(WSError::ParseError)
}

fn varint_get32<R: Read>(reader: &mut BufReader<R>) -> Result<u32, WSError> {
    let mut v: u32 = 0;
    for i in 0..5 {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        v |= ((byte[0] & 0x7f) as u32) << (i * 7);
        if (byte[0] & 0x80) == 0 {
            return Ok(v);
        }
    }
    Err(WSError::ParseError)
}

#[derive(Debug, Clone)]
struct Section {
    pub id: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CustomSection {
    pub name: String,
    pub payload: Vec<u8>,
}

impl Section {
    pub fn custom_section_get(&self) -> Result<CustomSection, WSError> {
        if self.id != 0 {
            return Err(WSError::ParseError);
        }
        let mut reader = BufReader::new(io::Cursor::new(&self.payload));
        let name_len = varint_get32(&mut reader)? as usize;
        let mut name_slice = vec![0u8; name_len];
        reader.read_exact(&mut name_slice)?;
        let name = str::from_utf8(&name_slice)?.to_string();
        let mut payload = Vec::new();
        let len = reader.read_to_end(&mut payload)?;
        payload.truncate(len);
        Ok(CustomSection { name, payload })
    }

    pub fn type_to_string(&self) -> Result<String, WSError> {
        match self.id {
            0 => {
                let custom_section = self.custom_section_get()?;
                Ok(format!("custom section: [{}]", custom_section.name))
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

fn doit() -> Result<(), WSError> {
    let file = "/tmp/z.wasm";
    let fp = File::open(file)?;
    let mut reader = BufReader::new(fp);
    let mut header = [0u8; 8];
    reader.read_exact(&mut header)?;

    let file_out = "/tmp/z2.wasm";
    let fp2 = File::create(file_out)?;
    let mut writer = BufWriter::new(fp2);

    let mut sections = Vec::new();
    loop {
        let id = match varint_get7(&mut reader) {
            Ok(id) => id,
            Err(WSError::Eof) => break,
            Err(e) => return Err(e.into()),
        };
        let len = varint_get32(&mut reader)? as usize;
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload)?;
        let section = Section { id, payload };
        dbg!(section.type_to_string());
        sections.push(section);
    }

    Ok(())
}

fn main() {
    doit().unwrap();
}
