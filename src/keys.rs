pub use crate::error::*;

use ct_codecs::{Encoder, Hex};
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{self, prelude::*};

const ED25519_PK_ID: u8 = 0x01;
const ED25519_SK_ID: u8 = 0x81;

/// A public key.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PublicKey {
    pub pk: ed25519_compact::PublicKey,
    pub key_id: Option<Vec<u8>>,
}

impl PublicKey {
    /// Create a public key from raw bytes.
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

    /// Deserialize a PEM-encoded public key.
    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_pem(pem)?;
        Ok(Self { pk, key_id: None })
    }

    /// Deserialize a DER-encoded public key.
    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_der(der)?;
        Ok(Self { pk, key_id: None })
    }

    /// Return the public key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_PK_ID];
        bytes.extend_from_slice(self.pk.as_ref());
        bytes
    }

    /// Serialize the public key using PEM encoding.
    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    /// Serialize the public key using DER encoding.
    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    /// Read public key from a file.
    pub fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    /// Save the public key to a file.
    pub fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Return the key identifier associated with this public key, if there is one.
    pub fn key_id(&self) -> Option<&Vec<u8>> {
        self.key_id.as_ref()
    }

    /// Compute a deterministic key identifier for this public key, if it doesn't already have one.
    pub fn attach_default_key_id(mut self) -> Self {
        if self.key_id.is_none() {
            self.key_id = Some(hmac_sha256::HMAC::mac(b"key_id", self.pk.as_ref())[0..12].to_vec());
        }
        self
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PublicKey {{ [{}] - key_id: {:?} }}",
            Hex::encode_to_string(self.pk.as_ref()).unwrap(),
            self.key_id()
                .map(|key_id| format!("[{}]", Hex::encode_to_string(key_id).unwrap()))
        )
    }
}

/// A secret key.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SecretKey {
    pub sk: ed25519_compact::SecretKey,
}

impl SecretKey {
    /// Create a secret key from raw bytes.
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

    /// Deserialize a PEM-encoded secret key.
    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_pem(pem)?;
        Ok(Self { sk })
    }

    /// Deserialize a DER-encoded secret key.
    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_der(der)?;
        Ok(Self { sk })
    }

    /// Return the secret key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_SK_ID];
        bytes.extend_from_slice(self.sk.as_ref());
        bytes
    }

    /// Serialize the secret key using PEM encoding.
    pub fn to_pem(&self) -> String {
        self.sk.to_pem()
    }

    /// Serialize the secret key using DER encoding.
    pub fn to_der(&self) -> Vec<u8> {
        self.sk.to_der()
    }

    /// Read a secret key from a file.
    pub fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    /// Save a secret key to a file.
    pub fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SecretKey {{ [{}] }}",
            Hex::encode_to_string(self.sk.as_ref()).unwrap(),
        )
    }
}

/// A key pair.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct KeyPair {
    /// The public key.
    pub pk: PublicKey,
    /// The secret key.
    pub sk: SecretKey,
}

impl KeyPair {
    /// Generate a new key pair.
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

/// A set of multiple public keys.
#[derive(Debug, Clone)]
pub struct PublicKeySet {
    pub pks: HashSet<PublicKey>,
}

impl PublicKeySet {
    /// Create a new public key set.
    pub fn new(pks: HashSet<PublicKey>) -> Self {
        PublicKeySet { pks }
    }

    /// Add a new key to the set.
    pub fn insert(&mut self, pk: PublicKey) -> Result<(), WSError> {
        if !self.pks.insert(pk) {
            return Err(WSError::DuplicatePublicKey);
        }
        Ok(())
    }

    /// Remove a key from the set.
    pub fn remove(&mut self, pk: &PublicKey) -> Result<(), WSError> {
        if !self.pks.remove(pk) {
            return Err(WSError::UnknownPublicKey);
        }
        Ok(())
    }

    /// Return the hash set storing the keys.
    pub fn items(&self) -> &HashSet<PublicKey> {
        &self.pks
    }

    /// Return the mutable hash set storing the keys.
    pub fn items_mut(&mut self) -> &mut HashSet<PublicKey> {
        &mut self.pks
    }

    /// Add a deterministic key identifier to all the keys that don't have one already.
    pub fn attach_default_key_id(mut self) -> Self {
        self.pks = self
            .pks
            .into_iter()
            .map(|pk| pk.attach_default_key_id())
            .collect();
        self
    }
}
