use wasmsign2::{
    BoxedPredicate, KeyPair, Module, PublicKey, PublicKeySet, SecretKey, Section, WSError,
};

#[macro_use]
extern crate clap;

use clap::{App, Arg};
use regex::RegexBuilder;
use std::fs::File;
use std::io::{prelude::*, BufReader};

fn start() -> Result<(), WSError> {
    let matches = app_from_crate!()
        .arg(Arg::with_name("verbose").short("-v").help("Verbose output"))
        .arg(
            Arg::with_name("debug")
                .short("-d")
                .help("Debug information"),
        )
        .subcommand(
            App::new("keygen")
                .arg(
                    Arg::with_name("secret_key")
                        .value_name("secret_key_file")
                        .long("--secret-key")
                        .short("-k")
                        .multiple(false)
                        .required(true)
                        .help("Secret key file"),
                )
                .arg(
                    Arg::with_name("public_key")
                        .value_name("public_key_file")
                        .long("--public-key")
                        .short("-K")
                        .multiple(false)
                        .required(true)
                        .help("Public key file"),
                ),
        )
        .subcommand(
            App::new("show").arg(
                Arg::with_name("in")
                    .value_name("input_file")
                    .long("--input-file")
                    .short("-i")
                    .multiple(false)
                    .required(true)
                    .help("Input file"),
            ),
        )
        .subcommand(
            App::new("split")
                .arg(
                    Arg::with_name("in")
                        .value_name("input_file")
                        .long("--input-file")
                        .short("-i")
                        .multiple(false)
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::with_name("out")
                        .value_name("output_file")
                        .long("--output-file")
                        .short("-o")
                        .multiple(false)
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::with_name("splits")
                        .long("--split")
                        .short("-s")
                        .value_name("regex")
                        .multiple(false)
                        .help("custom section names to be signed"),
                ),
        )
        .subcommand(
            App::new("sign")
                .arg(
                    Arg::with_name("in")
                        .value_name("input_file")
                        .long("--input-file")
                        .short("-i")
                        .multiple(false)
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::with_name("out")
                        .value_name("output_file")
                        .long("--output-file")
                        .short("-o")
                        .multiple(false)
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::with_name("secret_key")
                        .value_name("secret_key_file")
                        .long("--secret-key")
                        .short("-k")
                        .multiple(false)
                        .required(true)
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
                    Arg::with_name("signature_file")
                        .value_name("signature_file")
                        .long("--signature-file")
                        .short("-S")
                        .multiple(false)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            App::new("verify")
                .arg(
                    Arg::with_name("in")
                        .value_name("input_file")
                        .long("--input-file")
                        .short("-i")
                        .multiple(false)
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::with_name("public_key")
                        .value_name("public_key_file")
                        .long("--public-key")
                        .short("-K")
                        .multiple(false)
                        .required(true)
                        .help("Public key file"),
                )
                .arg(
                    Arg::with_name("signature_file")
                        .value_name("signature_file")
                        .long("--signature-file")
                        .short("-S")
                        .multiple(false)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            App::new("detach")
                .arg(
                    Arg::with_name("in")
                        .value_name("input_file")
                        .long("--input-file")
                        .short("-i")
                        .multiple(false)
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::with_name("out")
                        .value_name("output_file")
                        .long("--output-file")
                        .short("-o")
                        .multiple(false)
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::with_name("signature_file")
                        .value_name("signature_file")
                        .long("--signature-file")
                        .short("-S")
                        .multiple(false)
                        .required(true)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            App::new("attach")
                .arg(
                    Arg::with_name("in")
                        .value_name("input_file")
                        .long("--input-file")
                        .short("-i")
                        .multiple(false)
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::with_name("out")
                        .value_name("output_file")
                        .long("--output-file")
                        .short("-o")
                        .multiple(false)
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::with_name("signature_file")
                        .value_name("signature_file")
                        .long("--signature-file")
                        .short("-S")
                        .multiple(false)
                        .required(true)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            App::new("verify_matrix")
                .arg(
                    Arg::with_name("in")
                        .value_name("input_file")
                        .long("--input-file")
                        .short("-i")
                        .multiple(false)
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::with_name("public_key")
                        .value_name("public_key_file")
                        .long("--public-key")
                        .short("-K")
                        .multiple(false)
                        .required(true)
                        .help("Public key file"),
                ),
        )
        .get_matches();

    let verbose = matches.is_present("verbose");
    let debug = matches.is_present("debug");

    env_logger::builder()
        .format_timestamp(None)
        .format_level(false)
        .format_module_path(false)
        .format_target(false)
        .filter_level(if debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    if let Some(matches) = matches.subcommand_matches("show") {
        let input_file = matches.value_of("in");
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let module = Module::deserialize_from_file(input_file)?;
        module.show(verbose)?;
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        let kp = KeyPair::generate();
        let sk_file = matches
            .value_of("secret_key")
            .ok_or(WSError::UsageError("Missing secret key file"))?;
        let pk_file = matches
            .value_of("public_key")
            .ok_or(WSError::UsageError("Missing public key file"))?;
        kp.sk.to_file(sk_file)?;
        println!("Secret key saved to [{}]", sk_file);
        kp.pk.to_file(pk_file)?;
        println!("Public key saved to [{}]", pk_file);
    } else if let Some(matches) = matches.subcommand_matches("split") {
        let input_file = matches.value_of("in");
        let output_file = matches.value_of("out");
        let splits = matches.value_of("splits");
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;
        let signed_sections_rx = match splits {
            None => None,
            Some(splits) => Some(
                RegexBuilder::new(splits)
                    .case_insensitive(false)
                    .multi_line(false)
                    .dot_matches_new_line(false)
                    .size_limit(1_000_000)
                    .dfa_size_limit(1_000_000)
                    .nest_limit(1000)
                    .build()
                    .map_err(|_| WSError::InvalidArgument)?,
            ),
        };
        let mut module = Module::deserialize_from_file(input_file)?;
        module = module.split(|section| match section {
            Section::Standard(_) => true,
            Section::Custom(custom_section) => {
                if let Some(signed_sections_rx) = &signed_sections_rx {
                    signed_sections_rx.is_match(custom_section.name())
                } else {
                    true
                }
            }
        })?;
        module.serialize_to_file(output_file)?;
        println!("* Split module structure:\n");
        module.show(verbose)?;
    } else if let Some(matches) = matches.subcommand_matches("sign") {
        let input_file = matches.value_of("in");
        let output_file = matches.value_of("out");
        let signature_file = matches.value_of("signature_file");
        let sk_file = matches
            .value_of("secret_key")
            .ok_or(WSError::UsageError("Missing secret key file"))?;
        let sk = SecretKey::from_file(sk_file)?;
        let pk_file = matches.value_of("public_key");
        let key_id = if let Some(pk_file) = pk_file {
            let pk = PublicKey::from_file(pk_file)?.attach_default_key_id();
            pk.key_id().cloned()
        } else {
            None
        };
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;
        let module = Module::deserialize_from_file(input_file)?;
        let (module, signature) =
            sk.sign_multi(module, key_id.as_ref(), signature_file.is_some(), false)?;
        if let Some(signature_file) = signature_file {
            module.serialize_to_file(output_file)?;
            File::create(signature_file)?.write_all(&signature)?;
        } else {
            module.serialize_to_file(output_file)?;
        }
        println!("* Signed module structure:\n");
        module.show(verbose)?;
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        let input_file = matches.value_of("in");
        let signature_file = matches.value_of("signature_file");
        let splits = matches.value_of("splits");
        let signed_sections_rx = match splits {
            None => None,
            Some(splits) => Some(
                RegexBuilder::new(splits)
                    .case_insensitive(false)
                    .multi_line(false)
                    .dot_matches_new_line(false)
                    .size_limit(1_000_000)
                    .dfa_size_limit(1_000_000)
                    .nest_limit(1000)
                    .build()
                    .map_err(|_| WSError::InvalidArgument)?,
            ),
        };
        let pk_file = matches
            .value_of("public_key")
            .ok_or(WSError::UsageError("Missing public key file"))?;
        let pk = PublicKey::from_file(pk_file)?.attach_default_key_id();
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let mut detached_signatures_ = vec![];
        let detached_signatures = match signature_file {
            None => None,
            Some(signature_file) => {
                File::open(signature_file)?.read_to_end(&mut detached_signatures_)?;
                Some(detached_signatures_.as_slice())
            }
        };
        let mut reader = BufReader::new(File::open(input_file)?);
        if let Some(signed_sections_rx) = &signed_sections_rx {
            pk.verify_multi(&mut reader, detached_signatures, |section| match section {
                Section::Standard(_) => true,
                Section::Custom(custom_section) => {
                    signed_sections_rx.is_match(custom_section.name())
                }
            })?;
        } else {
            pk.verify(&mut reader)?;
        }
        println!("Signature is valid.");
    } else if let Some(matches) = matches.subcommand_matches("detach") {
        let input_file = matches.value_of("in");
        let output_file = matches.value_of("out");
        let signature_file = matches.value_of("signature_file");
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;
        let signature_file =
            signature_file.ok_or(WSError::UsageError("Missing detached signature file"))?;
        let module = Module::deserialize_from_file(input_file)?;
        let (module, detached_signature) = module.detach_signature()?;
        File::create(signature_file)?.write_all(&detached_signature)?;
        module.serialize_to_file(output_file)?;
        println!("Signature is now detached.");
    } else if let Some(matches) = matches.subcommand_matches("attach") {
        let input_file = matches.value_of("in");
        let output_file = matches.value_of("out");
        let signature_file = matches.value_of("signature_file");
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;
        let signature_file =
            signature_file.ok_or(WSError::UsageError("Missing detached signature file"))?;
        let mut detached_signature = vec![];
        File::open(signature_file)?.read_to_end(&mut detached_signature)?;
        let mut module = Module::deserialize_from_file(input_file)?;
        module = module.attach_signature(&detached_signature)?;
        module.serialize_to_file(output_file)?;
        println!("Signature is now embedded as a custom section.");
    } else if let Some(matches) = matches.subcommand_matches("verify_matrix") {
        let input_file = matches.value_of("in");
        let signature_file = matches.value_of("signature_file");
        let splits = matches.value_of("splits");
        let signed_sections_rx = match splits {
            None => None,
            Some(splits) => Some(
                RegexBuilder::new(splits)
                    .case_insensitive(false)
                    .multi_line(false)
                    .dot_matches_new_line(false)
                    .size_limit(1_000_000)
                    .dfa_size_limit(1_000_000)
                    .nest_limit(1000)
                    .build()
                    .map_err(|_| WSError::InvalidArgument)?,
            ),
        };
        let mut pks = std::collections::HashSet::new();
        for pk_file in matches
            .value_of("public_key")
            .ok_or(WSError::UsageError("Missing public key files"))?
            .split(',')
        {
            let pk = PublicKey::from_file(pk_file)?;
            pks.insert(pk);
        }
        let pks = PublicKeySet::new(pks);
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let mut detached_signatures_ = vec![];
        let detached_signatures = match signature_file {
            None => None,
            Some(signature_file) => {
                File::open(signature_file)?.read_to_end(&mut detached_signatures_)?;
                Some(detached_signatures_.as_slice())
            }
        };
        let mut reader = BufReader::new(File::open(input_file)?);
        let predicates: Vec<BoxedPredicate> = if let Some(signed_sections_rx) = signed_sections_rx {
            vec![Box::new(move |section| match section {
                Section::Standard(_) => true,
                Section::Custom(custom_section) => {
                    signed_sections_rx.is_match(custom_section.name())
                }
            })]
        } else {
            vec![Box::new(|_| true)]
        };
        let matrix = pks.verify_matrix(&mut reader, detached_signatures, &predicates)?;
        let valid_pks = matrix.get(0).ok_or(WSError::UsageError("No predicates"))?;
        if valid_pks.is_empty() {
            println!("No valid public keys found");
        } else {
            println!("Valid public keys:");
            for pk in valid_pks {
                println!("  - {:x?}", pk);
            }
        }
    } else {
        return Err(WSError::UsageError("No subcommand specified"));
    }
    Ok(())
}

fn main() -> Result<(), WSError> {
    let res = start();
    match res {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}
