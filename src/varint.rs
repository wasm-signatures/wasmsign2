use std::io::{self, prelude::*, BufReader, BufWriter};

use crate::error::*;

pub fn get7<R: Read>(reader: &mut BufReader<R>) -> Result<u8, WSError> {
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

pub fn get32<R: Read>(reader: &mut BufReader<R>) -> Result<u32, WSError> {
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

pub fn put<W: Write>(writer: &mut BufWriter<W>, mut v: u64) -> Result<(), WSError> {
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
