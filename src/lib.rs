use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::str;

use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::bn::MsbOption;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509Name;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509Req;
use openssl::x509::X509;
use serde::Deserialize;
use serde::Serialize;

pub struct Args {
    pub file_path: Option<Vec<PathBuf>>,
    pub bundle_path: Option<Vec<PathBuf>>,
}

pub struct Config {
    certificates: Vec<Certificate>,
    bundles: Vec<Bundle>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Certificate {
    common_name: String,
    organization: String,
    locality: String,
    state: String,
    country: String,
    key_size_bits: u32,
    self_signed: bool,
}

struct Bundle {
    private_key_file: PathBuf,
}

impl Config {
    pub fn build(args: Args) -> Result<Config, Box<dyn Error>> {
        let mut certificates: Vec<Certificate> = Vec::new();
        let mut bundles: Vec<Bundle> = Vec::new();

        if let Some(file_path) = args.file_path {
            for file in file_path {
                let contents = fs::read_to_string(file)?;
                extend_certificates_from_contents(&mut certificates, contents)?;
            }
        }

        if let Some(bundle_path) = args.bundle_path {
            for private_key_file in bundle_path {
                if private_key_file.extension().ok_or("Not a private key file")? == "key" {
                    bundles.push(Bundle {private_key_file});
                } else {
                    println!("Not a private key file: {}", private_key_file.display());
                }
            }
        }

        Ok(Config { certificates, bundles })
    }
}

struct Passphrase {
    value: String,
}

impl Passphrase {
    fn new_from_tty() -> Result<Passphrase, Box<dyn Error>> {
        let value = rpassword::prompt_password("Enter new passphrase: ").unwrap();
        let confirmation =
            rpassword::prompt_password("Verifying - Enter new passphrase: ").unwrap();
        assert_eq!(value, confirmation, "Verify failure");
        assert!(!value.is_empty());

        Ok(Passphrase { value })
    }

    fn from_tty() -> Result<Passphrase, Box<dyn Error>> {
        let value = rpassword::prompt_password("Enter passphrase: ").unwrap();
        assert!(!value.is_empty());

        Ok(Passphrase { value })
    }
}

/// Parses the content of a template file and extends the certificates vector.
fn extend_certificates_from_contents(
    certificates: &mut Vec<Certificate>,
    contents: String,
) -> Result<(), serde_yaml::Error> {
    let c: Vec<Certificate> = serde_yaml::from_str(&contents)?;
    certificates.extend(c);

    Ok(())
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    for bundle in config.bundles {
        println!("Bundle: {}", bundle.private_key_file.display());
        let passphrase = Passphrase::from_tty()?;

        let der = fs::read_to_string(bundle.private_key_file)?.into_bytes();
        let private_key = PKey::private_key_from_pkcs8_passphrase(&der, &passphrase.value.into_bytes())?;

        dbg!(&der);
        dbg!(&private_key);
    }


    for request in config.certificates {
        println!("New certificate: {}", request.common_name);
        let passphrase = Passphrase::new_from_tty()?;

        let key_pair = new_key_pair(&request)?;

        let mut key_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(request.common_name.clone() + ".key")?;
        key_file.write_all(&key_pair.private_key_to_pem_pkcs8_passphrase(
            Cipher::aes_256_cbc(),
            &passphrase.value.into_bytes(),
        )?)?;

        if request.self_signed {
            let cert = new_self_signed_certificate(&request, &key_pair)?;

            let mut cert_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(request.common_name.clone() + ".crt")?;
            cert_file.write_all(&cert.to_pem()?)?;

            // TODO: Make this --verbose
            // print(&cert.to_text()?)?;
        } else {
            let csr = new_csr(&request, &key_pair)?;

            let mut csr_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(request.common_name.clone() + ".csr")?;
            csr_file.write_all(&csr.to_pem()?)?;

            // TODO: Make this --verbose
            // print(&csr.to_text()?)?;
        }

        println!() // visually separate multiple requests
    }

    Ok(())
}

/// Generates a new RSA public/private key pair with the specified size.
fn new_key_pair(cert: &Certificate) -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(cert.key_size_bits)?;
    let key_pair = PKey::from_rsa(rsa)?;
    Ok(key_pair)
}

fn build_x509_name(cert: &Certificate) -> Result<X509Name, ErrorStack> {
    let mut x509_name = X509NameBuilder::new()?;

    // The order of the calls matter.
    // This is reversed when opening the certificate on Windows.
    x509_name.append_entry_by_text("C", &cert.country)?;
    x509_name.append_entry_by_text("ST", &cert.state)?;
    x509_name.append_entry_by_text("L", &cert.locality)?;
    x509_name.append_entry_by_text("O", &cert.organization)?;
    x509_name.append_entry_by_text("CN", &cert.common_name)?;

    Ok(x509_name.build())
}

/// Creates a new self-signed certificate which expires after 1 year.
fn new_self_signed_certificate(
    cert: &Certificate,
    key_pair: &PKey<Private>,
) -> Result<X509, ErrorStack> {
    let x509_name = build_x509_name(cert)?;

    let mut builder = X509::builder()?;

    builder.set_version(2)?;
    let serial_number = new_serial_number()?;

    builder.set_serial_number(&serial_number)?;
    builder.set_issuer_name(&x509_name)?;
    let not_before = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(366)?;
    builder.set_not_after(&not_after)?;
    builder.set_subject_name(&x509_name)?;
    builder.set_pubkey(key_pair)?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_key_identifier)?;

    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(authority_key_identifier)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;

    builder.sign(key_pair, MessageDigest::sha256())?;

    Ok(builder.build())
}

/// Generates a new certificate serial number.
fn new_serial_number() -> Result<Asn1Integer, ErrorStack> {
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    serial.to_asn1_integer()
}

/// Makes a new certificate signing request with the given private key
fn new_csr(cert: &Certificate, key_pair: &PKey<Private>) -> Result<X509Req, ErrorStack> {
    let mut builder = X509Req::builder()?;

    builder.set_pubkey(key_pair)?;
    builder.set_version(1)?;

    let x509_name = build_x509_name(cert)?;
    builder.set_subject_name(&x509_name)?;

    builder.sign(key_pair, MessageDigest::sha256())?;
    let req = builder.build();

    Ok(req)
}

// TODO: Useful for --verbose or a 'show' command to read existing certificate files
// print(&csr.to_text()?)?;
// /// Prints the raw certificate data.
// use std::str::Utf8Error;
// fn print(c: &[u8]) -> Result<(), Utf8Error> {
//     print!("{}", str::from_utf8(c)?);
//     Ok(())
// }
