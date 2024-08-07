//! # A library crate

// Lints:
#![warn(clippy::pedantic)]
#![warn(deprecated_in_future)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use anyhow::{anyhow, bail, Context};
use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::bn::MsbOption;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509Name;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509Req;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

/// An opaque error type for all kinds of application errors
// pub type AppError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type AppError = anyhow::Error;

/// Fields are documented in main.rs > CLI Args
#[allow(missing_docs)]
#[derive(Debug)]
pub struct Args {
    pub file_path: Option<Vec<PathBuf>>,
    pub bundle_path: Option<Vec<PathBuf>>,
}

/// The configuration for the program
#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
struct Bundle {
    private_key_file: PathBuf,
}

impl Config {
    /// Builds a `Config` from CLI `Args`.
    /// # Errors
    ///
    /// Can fail.
    pub fn build(args: Args) -> Result<Config, AppError> {
        let mut certificates: Vec<Certificate> = Vec::new();
        let mut bundles: Vec<Bundle> = Vec::new();

        if let Some(file_path) = args.file_path {
            for file in file_path {
                let contents = fs::read_to_string(file)?;
                extend_certificates_from_contents(&mut certificates, &contents)?;
            }
        }

        if let Some(bundle_path) = args.bundle_path {
            for private_key_file in bundle_path {
                match private_key_file.extension() {
                    Some(extension) if extension == "key" => {
                        bundles.push(Bundle { private_key_file });
                    }
                    _ => bail!("Expected a .key file: '{}'", private_key_file.display()),
                }
            }
        }

        Ok(Config {
            certificates,
            bundles,
        })
    }
}

struct Passphrase {
    value: String,
}

impl Passphrase {
    fn new_from_tty() -> Result<Passphrase, AppError> {
        let value = rpassword::prompt_password("Enter new passphrase: ")?;
        let confirmation = rpassword::prompt_password("Verifying - Enter new passphrase: ")?;

        if value != confirmation {
            bail!("Passphrases do not match");
        };
        if value.is_empty() {
            bail!("Passphrase is empty");
        };
        assert_eq!(value, confirmation, "Verify failure");

        Ok(Passphrase { value })
    }

    fn from_tty() -> Result<Passphrase, AppError> {
        let value = rpassword::prompt_password("Enter passphrase: ")?;
        Ok(Passphrase { value })
    }
}

/// Parses the content of a template file and extends the certificates vector.
fn extend_certificates_from_contents(
    certificates: &mut Vec<Certificate>,
    contents: &str,
) -> Result<(), AppError> {
    let c: Vec<Certificate> = serde_yaml::from_str(contents).context("Invalid YAML file")?;
    certificates.extend(c);

    Ok(())
}

/// Performs the main actions
///
/// # Errors
///
/// Can fail.
pub fn run(config: Config) -> Result<(), AppError> {
    for bundle in config.bundles {
        let name = bundle
            .private_key_file
            .file_stem()
            .ok_or(anyhow!("Invalid file name"))?
            .to_str()
            .ok_or(anyhow!("Invalid file name"))?;
        println!("Bundle: {}", &name);

        let pkey = &bundle.private_key_file;
        let pkey = fs::read_to_string(pkey)
            .context("Failed to read .key file")?
            .into_bytes();

        let passphrase = Passphrase::from_tty()?;

        // TODO: Test if pkey is a valid PEM
        let pkey =
            PKey::private_key_from_pem_passphrase(&pkey, &passphrase.value.clone().into_bytes())
                .context("Maybe wrong password or bad .key file")?;

        let cert = bundle.private_key_file.with_extension("crt");
        let cert = fs::read_to_string(cert.clone())
            .context(format!("Missing crt file: '{}'", &cert.display()))?
            .into_bytes();

        let cert = X509::from_pem(&cert)?;

        let mut builder = Pkcs12::builder();

        builder.name(name);
        builder.pkey(&pkey);
        builder.cert(&cert);

        let p12 = builder.build2(&passphrase.value)?;

        let p12_path = bundle.private_key_file.with_extension("p12");
        let mut p12_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p12_path)
            .context(format!("Failed to open file: '{}'", p12_path.display()))?;

        p12_file
            .write_all(&p12.to_der()?)
            .context(format!("Failed to write file: '{}'", p12_path.display()))?;
    }

    for request in config.certificates {
        println!("New certificate: '{}'", request.common_name);
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

        println!(); // visually separate multiple requests
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

    builder.append_extension(
        SubjectAlternativeName::new()
            .dns(&cert.common_name)
            .build(&builder.x509v3_context(None, None))?,
    )?;

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

    let mut extensions = Stack::new()?;
    extensions.push(
        SubjectAlternativeName::new()
            .dns(&cert.common_name)
            .build(&builder.x509v3_context(None))?,
    )?;
    builder.add_extensions(&extensions)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config() {
        // let args = Args {
        //     file_path: Some(vec![PathBuf::new()]),
        //     bundle_path: Some(vec![PathBuf::new()]),
        // };
        // let config = Config::build(args)?;
        let _expected = Config {
            certificates: Vec::new(),
            bundles: Vec::new(),
        };
        // assert_eq!(config, expected);
    }
}
