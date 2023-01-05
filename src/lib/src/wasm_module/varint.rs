use std::io::{self, prelude::*};

use crate::error::*;

pub fn get7(reader: &mut impl Read) -> Result<u8, WSError> {
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
        v |= (byte[0] & 0x7f) << (i * 7);
        if (byte[0] & 0x80) == 0 {
            return Ok(v);
        }
    }
    Err(WSError::ParseError)
}

pub fn get32(reader: &mut impl Read) -> Result<u32, WSError> {
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

pub fn put(writer: &mut impl Write, mut v: u64) -> Result<(), WSError> {
    let mut byte = [0u8; 1];
    loop {
        byte[0] = (v & 0x7f) as u8;
        if v > 0x7f {
            byte[0] |= 0x80;
        }
        writer.write_all(&byte)?;
        v >>= 7;
        if v == 0 {
            return Ok(());
        }
    }
}

pub fn put_slice(writer: &mut impl Write, bytes: impl AsRef<[u8]>) -> Result<(), WSError> {
    let bytes = bytes.as_ref();
    put(writer, bytes.len() as _)?;
    writer.write_all(bytes)?;
    Ok(())
}

pub fn get_slice(reader: &mut impl Read) -> Result<Vec<u8>, WSError> {
    let len = get32(reader)? as _;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
