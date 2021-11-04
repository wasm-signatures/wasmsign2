use wasmsign2::*;

#[macro_use]
extern crate clap;

use clap::Arg;

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
        let sk_file = matches.value_of("secret_key");
        let sk = if let Some(sk_file) = sk_file {
            SecretKey::from_file(sk_file)?
        } else {
            panic!("Secret key file is required");
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
