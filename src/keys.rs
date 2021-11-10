pub use crate::error::*;

use std::fs::File;
use std::io::{self, prelude::*};

const ED25519_PK_ID: u8 = 0x01;
const ED25519_SK_ID: u8 = 0x81;

pub struct PublicKey {
    pub pk: ed25519_compact::PublicKey,
    pub key_id: Option<Vec<u8>>,
}

impl PublicKey {
    pub fn from_bytes(pk: &[u8]) -> Result<Self, WSError> {
        let mut reader = io::Cursor::new(pk);
        let mut id = [0u8];
        reader.read_exact(&mut id)?;
        if id[0] != ED25519_PK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes)?;
        Ok(Self {
            pk: ed25519_compact::PublicKey::from_slice(&bytes)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_pem(pem)?;
        Ok(Self { pk, key_id: None })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_der(der)?;
        Ok(Self { pk, key_id: None })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_PK_ID];
        bytes.extend_from_slice(self.pk.as_ref());
        bytes
    }

    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    pub fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }

    pub fn key_id(&self) -> Option<&Vec<u8>> {
        self.key_id.as_ref()
    }

    pub fn attach_default_key_id(mut self) -> Self {
        self.key_id = Some(hmac_sha256::HMAC::mac(b"key_id", self.pk.as_ref())[0..12].to_vec());
        self
    }
}

pub struct SecretKey {
    pub sk: ed25519_compact::SecretKey,
}

impl SecretKey {
    pub fn from_bytes(sk: &[u8]) -> Result<Self, WSError> {
        let mut reader = io::Cursor::new(sk);
        let mut id = [0u8];
        reader.read_exact(&mut id)?;
        if id[0] != ED25519_SK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes)?;
        Ok(Self {
            sk: ed25519_compact::SecretKey::from_slice(&bytes)?,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_pem(pem)?;
        Ok(Self { sk })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_der(der)?;
        Ok(Self { sk })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_SK_ID];
        bytes.extend_from_slice(self.sk.as_ref());
        bytes
    }

    pub fn to_pem(&self) -> String {
        self.sk.to_pem()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.sk.to_der()
    }

    pub fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }
}

pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::generate());
        KeyPair {
            pk: PublicKey {
                pk: kp.pk,
                key_id: None,
            },
            sk: SecretKey { sk: kp.sk },
        }
    }
}
