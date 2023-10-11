use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::str;
use std::str::Utf8Error;

use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::bn::MsbOption;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

pub struct Args {
    pub file_path: Option<Vec<PathBuf>>,
}

pub struct Config {
    certificates: Vec<Certificate>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Certificate {
    self_signed: bool,
    key_size_bits: u32,
    days_until_expiration: u32,
    common_name: String,
    organization: String,
    state: String,
    country: String,
    locality: String,
}

impl Config {
    pub fn build(args: Args) -> Result<Config, Box<dyn Error>> {
        let mut certificates: Vec<Certificate> = Vec::new();

        if let Some(file_path) = args.file_path {
            for file in file_path {
                let contents = fs::read_to_string(file)?;
                extend_certificates_from_contents(&mut certificates, contents)?;
            }
        }

        Ok(Config { certificates })
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

/// Creates a new self-signed certificate and prints the details.
pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    for request in config.certificates {
        let key_pair = new_key_pair(&request)?;

        if request.self_signed {
            let cert = new_self_signed_certificate(&request, &key_pair)?;

            let mut cert_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(request.common_name.clone() + ".pem")?;
            cert_file.write_all(&cert.to_pem()?)?;

            let mut key_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(request.common_name + ".key")?;
            key_file.write_all(&key_pair.private_key_to_pem_pkcs8()?)?;

            // print(&cert.to_text()?)?;
        }
    }

    Ok(())
}

/// Generates a new RSA public/private key pair with the specified size.
fn new_key_pair(cert: &Certificate) -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(cert.key_size_bits)?;
    let key_pair = PKey::from_rsa(rsa)?;
    Ok(key_pair)
}

/// Creates a new self-signed certificate which expires after 1 year.
fn new_self_signed_certificate(
    cert: &Certificate,
    key_pair: &PKey<Private>,
) -> Result<X509, ErrorStack> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("CN", &cert.common_name)?;
    x509_name.append_entry_by_text("O", &cert.organization)?;
    x509_name.append_entry_by_text("L", &cert.locality)?;
    x509_name.append_entry_by_text("ST", &cert.state)?;
    x509_name.append_entry_by_text("C", &cert.country)?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;

    cert_builder.set_version(2)?;
    let serial_number = new_serial_number()?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_issuer_name(&x509_name)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(cert.days_until_expiration)?;
    cert_builder.set_not_after(&not_after)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_pubkey(key_pair)?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(authority_key_identifier)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;

    cert_builder.sign(key_pair, MessageDigest::sha256())?;
    Ok(cert_builder.build())
}

/// Generates a new certificate serial number.
fn new_serial_number() -> Result<Asn1Integer, ErrorStack> {
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    serial.to_asn1_integer()
}

/// Prints the raw certificate data.
fn print(c: &[u8]) -> Result<(), Utf8Error> {
    print!("{}", str::from_utf8(c)?);
    Ok(())
}
