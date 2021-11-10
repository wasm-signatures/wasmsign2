use wasmsign2::*;

#[macro_use]
extern crate clap;

use clap::Arg;
use regex_automata::RegexBuilder;
use std::fs::File;
use std::io::prelude::*;

fn main() -> Result<(), WSError> {
    env_logger::builder()
        .format_timestamp(None)
        .format_level(false)
        .format_module_path(false)
        .format_target(false)
        .filter_level(log::LevelFilter::Debug)
        .init();

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
                .value_name("regex")
                .multiple(false)
                .help("custom section names to be signed"),
        )
        .arg(Arg::with_name("verbose").short("-v").help("Verbose output"))
        .get_matches();

    let input_file = matches.value_of("in");
    let output_file = matches.value_of("out");
    let signature_file = matches.value_of("signature_file");
    let action = matches.value_of("action").unwrap();
    let splits = matches.value_of("splits");
    let verbose = matches.is_present("verbose");

    let signed_sections_rx = match splits {
        None => None,
        Some(splits) => Some(
            RegexBuilder::new()
                .unicode(true)
                .anchored(true)
                .dot_matches_new_line(false)
                .build(splits)
                .map_err(|_| WSError::InvalidArgument)?,
        ),
    };
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
        let sk_file = matches.value_of("secret_key");
        let sk = if let Some(sk_file) = sk_file {
            SecretKey::from_file(sk_file)?
        } else {
            panic!("Secret key file is required");
        };
        let output_file = output_file.expect("Missing output file");
        let input_file = input_file.expect("Missing input file");
        let mut module = Module::deserialize_from_file(input_file)?;
        if signature_file.is_none() || (signature_file.is_some() && signed_sections_rx.is_some()) {
            module = split(module, |section| match section {
                Section::Standard(_) => true,
                Section::Custom(custom_section) => {
                    if let Some(signed_sections_rx) = &signed_sections_rx {
                        signed_sections_rx.is_match(custom_section.name().as_bytes())
                    } else {
                        true
                    }
                }
            })?;
        }
        let (module, signature) = sign(&sk, module, signature_file.is_some())?;
        if let Some(signature_file) = signature_file {
            module.serialize_to_file(output_file)?;
            File::create(signature_file)?.write_all(&signature)?;
        } else {
            module.serialize_to_file(output_file)?;
        }
        println!("* Signed module structure:\n");
        show(output_file, verbose)?;
    } else if action == "verify" {
        let pk_file = matches.value_of("public_key").expect("Missing public key");
        let pk = PublicKey::from_file(pk_file)?;
        let input_file = input_file.expect("Missing input file");
        let module = Module::deserialize_from_file(input_file)?;
        let mut detached_signatures_ = vec![];
        let detached_signatures = match signature_file {
            None => None,
            Some(signature_file) => {
                File::open(signature_file)?.read_to_end(&mut detached_signatures_)?;
                Some(detached_signatures_.as_slice())
            }
        };
        verify(&pk, &module, detached_signatures, |section| match section {
            Section::Standard(_) => true,
            Section::Custom(custom_section) => {
                if let Some(signed_sections_rx) = &signed_sections_rx {
                    signed_sections_rx.is_match(custom_section.name().as_bytes())
                } else {
                    true
                }
            }
        })?;
    }
    Ok(())
}
