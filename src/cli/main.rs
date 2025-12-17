use wasmsign2::{
    BoxedPredicate, KeyPair, Module, PublicKey, PublicKeySet, SecretKey, Section, WSError,
};

use wasmsign2::reexports::log;

use clap::{command, Arg, Command};
use regex::RegexBuilder;
use std::fs::File;
use std::io::{prelude::*, BufReader};

fn start() -> Result<(), WSError> {
    let matches = command!()
        .arg(Arg::new("verbose").short('v').action(clap::ArgAction::SetTrue).help("Verbose output"))
        .arg(
            Arg::new("debug")
                .short('d')
                .action(clap::ArgAction::SetTrue)
                .help("Prints debugging information"),
        )
        .subcommand(
            Command::new("keygen")
                .about("Generate a new key pair")
                .arg(
                    Arg::new("secret_key")
                        .value_name("secret_key_file")
                        .long("secret-key")
                        .short('k')
                        .required(true)
                        .help("Secret key file"),
                )
                .arg(
                    Arg::new("public_key")
                        .value_name("public_key_file")
                        .long("public-key")
                        .short('K')
                        .required(true)
                        .help("Public key file"),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Print the structure of a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                ),
        )
        .subcommand(
            Command::new("split")
                .about("Add cutting points to a module to enable partial verification")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("splits")
                        .long("split")
                        .short('s')
                        .value_name("regex")
                        .help("Custom section names to be signed"),
                ),
        )
        .subcommand(
            Command::new("sign")
                .about("Sign a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("secret_key")
                        .value_name("secret_key_file")
                        .long("secret-key")
                        .short('k')
                        .required(true)
                        .help("Secret key file"),
                )
                .arg(
                    Arg::new("public_key")
                        .value_name("public_key_file")
                        .long("public-key")
                        .short('K')
                        .help("Public key file"),
                )
                .arg(
                    Arg::new("ssh")
                        .long("ssh")
                        .short('Z')
                        .action(clap::ArgAction::SetTrue)
                        .help("Parse OpenSSH keys"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .help("Signature file"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a module's signature")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("public_key")
                        .value_name("public_key_file")
                        .long("public-key")
                        .short('K')
                        .required(false)
                        .help("Public key file"),
                )
                .arg(
                    Arg::new("from_github")
                        .value_name("from_github")
                        .long("from-github")
                        .short('G')
                        .required(false)
                        .help("GitHub account to retrieve public keys from"),
                )
                .arg(
                    Arg::new("ssh")
                        .long("ssh")
                        .short('Z')
                        .action(clap::ArgAction::SetTrue)
                        .help("Parse OpenSSH keys"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .help("Signature file"),
                )
                .arg(
                    Arg::new("splits")
                        .long("split")
                        .short('s')
                        .value_name("regex")
                        .help("Custom section names to be verified"),
                ),
        )
        .subcommand(
            Command::new("detach")
                .about("Detach the signature from a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .required(true)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            Command::new("attach")
                .about("Embed a detach signature into a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .required(true)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            Command::new("verify_matrix")
                .about("Batch verification against multiple public keys")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("public_keys")
                        .value_name("public_key_files")
                        .long("public-keys")
                        .short('K')
                        .num_args(1..)
                        .required(false)
                        .help("Public key files"),
                )
                .arg(
                    Arg::new("from_github")
                        .value_name("from_github")
                        .long("from-github")
                        .short('G')
                        .required(false)
                        .help("GitHub account to retrieve public keys from"),
                )
                .arg(
                    Arg::new("ssh")
                        .long("ssh")
                        .short('Z')
                        .action(clap::ArgAction::SetTrue)
                        .help("Parse OpenSSH keys"),
                )
                .arg(
                    Arg::new("splits")
                        .long("split")
                        .short('s')
                        .value_name("regex")
                        .help("Custom section names to be verified"),
                ),
        )
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let debug = matches.get_flag("debug");

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
        let input_file = matches.get_one::<String>("in");
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?.as_str();
        let module = Module::deserialize_from_file(input_file)?;
        module.show(verbose)?;
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        let kp = KeyPair::generate();
        let sk_file = matches
            .get_one::<String>("secret_key")
            .ok_or(WSError::UsageError("Missing secret key file"))?.as_str();
        let pk_file = matches
            .get_one::<String>("public_key")
            .ok_or(WSError::UsageError("Missing public key file"))?.as_str();
        kp.sk.to_file(sk_file)?;
        println!("Secret key saved to [{sk_file}]");
        kp.pk.to_file(pk_file)?;
        println!("Public key saved to [{pk_file}]");
    } else if let Some(matches) = matches.subcommand_matches("split") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let splits = matches.get_one::<String>("splits").map(|s| s.as_str());
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
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let signature_file = matches.get_one::<String>("signature_file").map(|s| s.as_str());
        let sk_file = matches
            .get_one::<String>("secret_key")
            .ok_or(WSError::UsageError("Missing secret key file"))?.as_str();
        let sk = match matches.get_flag("ssh") {
            false => SecretKey::from_file(sk_file)?,
            true => SecretKey::from_openssh_file(sk_file)?,
        };
        let pk_file = matches.get_one::<String>("public_key").map(|s| s.as_str());
        let key_id = if let Some(pk_file) = pk_file {
            let pk = match matches.get_flag("ssh") {
                false => PublicKey::from_file(pk_file)?,
                true => PublicKey::from_openssh_file(pk_file)?,
            }
            .attach_default_key_id();
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
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let signature_file = matches.get_one::<String>("signature_file").map(|s| s.as_str());
        let splits = matches.get_one::<String>("splits").map(|s| s.as_str());
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
        let pk = if let Some(github_account) = matches.get_one::<String>("from_github").map(|s| s.as_str()) {
            PublicKey::from_openssh(&get_pks_from_github(github_account)?)?
        } else {
            let pk_file = matches
                .get_one::<String>("public_key")
                .ok_or(WSError::UsageError("Missing public key file"))?.as_str();
            match matches.get_flag("ssh") {
                false => PublicKey::from_file(pk_file)?,
                true => PublicKey::from_openssh_file(pk_file)?,
            }
        }
        .attach_default_key_id();
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
            pk.verify(&mut reader, detached_signatures)?;
        }
        println!("Signature is valid.");
    } else if let Some(matches) = matches.subcommand_matches("detach") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let signature_file = matches.get_one::<String>("signature_file").map(|s| s.as_str());
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
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let signature_file = matches.get_one::<String>("signature_file").map(|s| s.as_str());
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
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let signature_file = matches.get_one::<String>("signature_file").map(|s| s.as_str());
        let splits = matches.get_one::<String>("splits").map(|s| s.as_str());
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
        let pks = if let Some(github_account) = matches.get_one::<String>("from_github").map(|s| s.as_str()) {
            PublicKeySet::from_openssh(&get_pks_from_github(github_account)?)?
        } else {
            let pk_files = matches
                .get_many::<String>("public_keys")
                .ok_or(WSError::UsageError("Missing public key files"))?;
            match matches.get_flag("ssh") {
                false => {
                    let mut pks = std::collections::HashSet::new();
                    for pk_file in pk_files {
                        let pk = PublicKey::from_file(pk_file.as_str())?;
                        pks.insert(pk);
                    }
                    PublicKeySet::new(pks)
                }
                true => PublicKeySet::from_openssh_file(
                    pk_files
                        .map(|s| s.as_str())
                        .next()
                        .ok_or(WSError::UsageError("Missing public keys file"))?,
                )?,
            }
        }
        .attach_default_key_id();
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
        let valid_pks = matrix.first().ok_or(WSError::UsageError("No predicates"))?;
        if valid_pks.is_empty() {
            println!("No valid public keys found");
        } else {
            println!("Valid public keys:");
            for pk in valid_pks {
                println!("  - {pk:x?}");
            }
        }
    } else {
        return Err(WSError::UsageError("No subcommand specified"));
    }
    Ok(())
}

fn get_pks_from_github(account: impl AsRef<str>) -> Result<String, WSError> {
    let account_rawurlencoded = uri_encode::encode_uri_component(account.as_ref());
    let url = format!("https://github.com/{account_rawurlencoded}.keys");
    let response = ureq::get(&url)
        .call()
        .map_err(|_| WSError::UsageError("Keys couldn't be retrieved from GitHub"))?;
    let s = response
        .into_body()
        .read_to_vec()
        .map_err(|_| WSError::UsageError("Keys couldn't be retrieved from GitHub"))?;
    String::from_utf8(s).map_err(|_| {
        WSError::UsageError("Unexpected characters in the public keys retrieved from GitHub")
    })
}

fn main() -> Result<(), WSError> {
    let res = start();
    match res {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
