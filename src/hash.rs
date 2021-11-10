use std::io::{self, Write};

#[derive(Clone, Copy)]
pub(crate) struct Hash {
    hash: hmac_sha256::Hash,
}

impl Hash {
    pub fn new() -> Self {
        Hash {
            hash: hmac_sha256::Hash::new(),
        }
    }

    pub fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.hash.update(data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        self.hash.finalize()
    }
}

impl Write for Hash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hash.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
