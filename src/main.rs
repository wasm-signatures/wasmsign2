#[macro_use]
extern crate clap;

mod error;
mod sig_sections;
mod varint;
mod wasm_module;

use error::*;
use sig_sections::*;
use wasm_module::*;

use clap::Arg;
use ct_codecs::{Encoder, Hex};
use hmac_sha256::Hash;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::str;

const SIGNATURE_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;

const ED25519_PK_ID: u8 = 0x01;
const ED25519_SK_ID: u8 = 0x81;

struct PublicKey {
    pk: ed25519_compact::PublicKey,
}

impl PublicKey {
    fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut id = [0u8];
        fp.read_exact(&mut id)?;
        if id[0] != ED25519_PK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        let pk = ed25519_compact::PublicKey::from_slice(&bytes)?;
        Ok(PublicKey { pk })
    }

    fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&[ED25519_PK_ID])?;
        fp.write_all(&*self.pk)?;
        Ok(())
    }
}

struct SecretKey {
    sk: ed25519_compact::SecretKey,
}

impl SecretKey {
    fn from_file(file: &str) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut id = [0u8];
        fp.read_exact(&mut id)?;
        if id[0] != ED25519_SK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        let sk = ed25519_compact::SecretKey::from_slice(&bytes)?;
        Ok(SecretKey { sk })
    }

    fn to_file(&self, file: &str) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&[ED25519_SK_ID])?;
        fp.write_all(&*self.sk)?;
        Ok(())
    }
}

struct KeyPair {
    pk: PublicKey,
    sk: SecretKey,
}

impl KeyPair {
    fn generate() -> Self {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::generate());
        KeyPair {
            pk: PublicKey { pk: kp.pk },
            sk: SecretKey { sk: kp.sk },
        }
    }
}

fn show(file: &str, verbose: bool) -> Result<(), WSError> {
    let module = Module::parse(file)?;
    for (idx, section) in module.sections.iter().enumerate() {
        println!("{}:\t{}", idx, section.type_to_string(verbose)?);
    }
    Ok(())
}

fn delimiter_section() -> Result<Section, WSError> {
    let mut custom_payload = vec![0u8; 16];
    getrandom::getrandom(&mut custom_payload)
        .map_err(|_| WSError::InternalError("RNG error".to_string()))?;
    CustomSection {
        name: SIGNATURE_SECTION_DELIMITER_NAME.to_string(),
        custom_payload,
    }
    .to_section()
}

fn build_header_section(sk: &SecretKey, hashes: Vec<Vec<u8>>) -> Result<Section, WSError> {
    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    msg.extend_from_slice(&[SIGNATURE_VERSION, SIGNATURE_HASH_FUNCTION]);
    for hash in &hashes {
        msg.extend_from_slice(hash);
    }

    println!("* Adding signature:\n");

    println!(
        "sig = Ed25519(sk, \"{}\" ‖ {:02x} ‖ {:02x} ‖ {})\n",
        SIGNATURE_DOMAIN,
        SIGNATURE_VERSION,
        SIGNATURE_HASH_FUNCTION,
        Hex::encode_to_string(&msg[SIGNATURE_DOMAIN.len() + 2..]).unwrap()
    );

    let signature = sk.sk.sign(msg, None).to_vec();

    println!("    = {}\n\n", Hex::encode_to_string(&signature).unwrap());

    let signature_for_hashes = SignatureForHashes {
        key_id: None,
        signature,
    };
    let mut signatures = vec![];
    signatures.push(signature_for_hashes);
    let signed_parts = SignedHashes { hashes, signatures };
    let mut signed_hashes_set = vec![];
    signed_hashes_set.push(signed_parts);
    let signature_data = SignatureData {
        specification_version: SIGNATURE_VERSION,
        hash_function: SIGNATURE_HASH_FUNCTION,
        signed_hashes_set,
    };
    let signature_data_bin = signature_data.serialize()?;
    let header_section = CustomSection {
        name: SIGNATURE_SECTION_HEADER_NAME.to_string(),
        custom_payload: signature_data_bin,
    }
    .to_section()?;

    Ok(header_section)
}

fn sign(
    sk: &SecretKey,
    in_file: &str,
    out_file: &str,
    signature_file: Option<&str>,
    splits: Option<Vec<usize>>,
) -> Result<(), WSError> {
    let splits = splits.unwrap_or_default();

    let mut module = Module::parse(in_file)?;
    let mut hasher = Hash::new();
    let mut hashes = vec![];

    let mut out_sections = vec![];
    let header_section = CustomSection {
        name: "".to_string(),
        custom_payload: vec![],
    }
    .to_section()?;
    if signature_file.is_none() {
        out_sections.push(header_section);
    }

    let mut splits_cursor = splits.iter();
    let mut next_split = splits_cursor.next();
    for (idx, section) in module.sections.iter().enumerate() {
        if section.is_signature_header()? {
            println!("A signature section was already present.");
            if idx != 0 {
                println!("WARNING: the signature section was not the first module section.")
            }
            continue;
        }
        if Some(&idx) == next_split {
            let delimiter = delimiter_section()?;
            hasher.update(&delimiter.payload);
            out_sections.push(delimiter);
            hashes.push(hasher.finalize().to_vec());
            hasher = Hash::new();
            next_split = splits_cursor.next();
        }
        hasher.update(&section.payload);
        out_sections.push(section.clone());
    }
    let delimiter = delimiter_section()?;
    hasher.update(&delimiter.payload);
    if signature_file.is_none() {
        out_sections.push(delimiter);
    }
    hashes.push(hasher.finalize().to_vec());

    let header_section = build_header_section(sk, hashes)?;

    if let Some(signature_file) = signature_file {
        File::create(signature_file)?.write_all(&header_section.payload)?;
    } else {
        out_sections[0] = header_section;
    }
    module.sections = out_sections;
    module.serialize(out_file)?;
    Ok(())
}

fn verify(pk: &PublicKey, in_file: &str, signature_file: Option<&str>) -> Result<(), WSError> {
    let module = Module::parse(in_file)?;
    let mut sections = module.sections.iter().enumerate();
    let signature_header: &Section;
    let signature_header_from_file;
    if let Some(signature_file) = signature_file {
        let mut custom_payload = vec![];
        File::open(signature_file)?.read_to_end(&mut custom_payload)?;
        signature_header_from_file = Section::new(0, custom_payload);
        signature_header = &signature_header_from_file;
    } else {
        signature_header = sections.next().ok_or(WSError::ParseError)?.1;
    }
    if !signature_header.is_signature_header()? {
        println!("This module is not signed");
        return Ok(());
    }
    let signature_data = signature_header.get_signature_data()?;
    if signature_data.specification_version != SIGNATURE_VERSION {
        println!(
            "Unsupported specification version: {:02x}",
            signature_data.specification_version
        );
        return Err(WSError::ParseError);
    }
    if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
        println!(
            "Unsupported hash function: {:02x}",
            signature_data.specification_version
        );
        return Err(WSError::ParseError);
    }

    let mut valid_hashes = HashSet::new();
    let signed_hashes_set = signature_data.signed_hashes_set;
    for signed_part in &signed_hashes_set {
        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
        msg.extend_from_slice(&[SIGNATURE_VERSION, SIGNATURE_HASH_FUNCTION]);
        let hashes = &signed_part.hashes;
        for hash in hashes {
            msg.extend_from_slice(hash);
        }
        for signature in &signed_part.signatures {
            if pk
                .pk
                .verify(
                    &msg,
                    &ed25519_compact::Signature::from_slice(&signature.signature)?,
                )
                .is_err()
            {
                continue;
            }
            println!(
                "Hash signature is valid for key [{}]",
                Hex::encode_to_string(&*pk.pk).unwrap()
            );
            for hash in hashes {
                valid_hashes.insert(hash);
            }
        }
    }
    println!();
    if valid_hashes.is_empty() {
        println!("No valid signatures");
        return Err(WSError::VerificationFailed);
    }
    println!("Hashes matching the signature:");
    for valid_hash in valid_hashes {
        println!("  - [{}]", Hex::encode_to_string(&valid_hash).unwrap());
    }
    println!();
    println!("Computed hashes:");
    let mut hasher = Hash::new();
    let sections_len = sections.len();
    for (idx, section) in sections {
        hasher.update(&section.payload);
        if section.is_signature_delimiter()? {
            let h = hasher.finalize();
            hasher = Hash::new();
            println!("  - [{}]", Hex::encode_to_string(h).unwrap());
        } else if idx + 1 == sections_len && signature_file.is_none() {
            println!("No final delimiter");
            return Err(WSError::VerificationFailed);
        }
    }

    Ok(())
}

fn main() -> Result<(), WSError> {
    println!();
    let matches = app_from_crate!()
        .arg(
            Arg::with_name("in")
                .value_name("input_file")
                .long("--input-file")
                .short("-i")
                .multiple(false)
                .help("Input file"),
        )
        .arg(
            Arg::with_name("out")
                .value_name("output_file")
                .long("--output-file")
                .short("-o")
                .multiple(false)
                .help("Output file"),
        )
        .arg(
            Arg::with_name("signature_file")
                .value_name("signature_file")
                .long("--signature-file")
                .short("-S")
                .multiple(false)
                .help("Signature file"),
        )
        .arg(
            Arg::with_name("secret_key")
                .value_name("secret_key_file")
                .long("--secret-key")
                .short("-k")
                .multiple(false)
                .help("Secret key file"),
        )
        .arg(
            Arg::with_name("public_key")
                .value_name("public_key_file")
                .long("--public-key")
                .short("-K")
                .multiple(false)
                .help("Public key file"),
        )
        .arg(
            Arg::with_name("action")
                .long("--action")
                .short("-a")
                .value_name("action (show, sign, verify, keygen)")
                .multiple(false)
                .required(true)
                .help("Action"),
        )
        .arg(
            Arg::with_name("splits")
                .long("--split")
                .short("-s")
                .value_name("position")
                .multiple(true)
                .help("Split"),
        )
        .arg(Arg::with_name("verbose").short("-v").help("Verbose output"))
        .get_matches();

    let input_file = matches.value_of("in");
    let output_file = matches.value_of("out");
    let signature_file = matches.value_of("signature_file");
    let action = matches.value_of("action").unwrap();
    let splits = matches.values_of("splits");
    let verbose = matches.is_present("verbose");

    if action == "show" {
        show(input_file.unwrap(), verbose)?;
    } else if action == "keygen" {
        let kp = KeyPair::generate();
        let sk_file = matches.value_of("secret_key");
        let pk_file = matches.value_of("public_key");
        if let Some(sk_file) = sk_file {
            kp.sk.to_file(sk_file)?;
        }
        if let Some(pk_file) = pk_file {
            kp.pk.to_file(pk_file)?;
        }
    } else if action == "sign" {
        let kp;
        let sk_file = matches.value_of("secret_key");
        let sk = if let Some(sk_file) = sk_file {
            SecretKey::from_file(sk_file)?
        } else {
            kp = KeyPair::generate();
            kp.sk
        };
        let mut splits: Vec<usize> = splits
            .unwrap_or_default()
            .map(|x| x.parse::<usize>().unwrap())
            .collect();
        splits.sort_unstable();
        let output_file = output_file.expect("Missing output file");
        let input_file = input_file.expect("Missing input file");
        sign(&sk, input_file, output_file, signature_file, Some(splits))?;
        println!("* Signed module structure:\n");
        show(output_file, verbose)?;
    } else if action == "verify" {
        let pk_file = matches.value_of("public_key").expect("Missing public key");
        let pk = PublicKey::from_file(pk_file)?;
        let input_file = input_file.expect("Missing input file");
        verify(&pk, input_file, signature_file)?;
    }
    Ok(())
}
