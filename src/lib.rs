use std::error::Error;
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

struct Config<'a> {
    self_signed: bool,
    key_size_bits: u32,
    days_until_expiration: u32,
    common_name: &'a str,
    organization: &'a str,
    state: &'a str,
    country: &'a str,
    locality: &'a str,
}

/// Creates a new self-signed certificate and prints the details.
pub fn run() -> Result<(), Box<dyn Error>> {
    let default_config = Config {
        self_signed: true,
        key_size_bits: 2048,
        days_until_expiration: 365,
        common_name: "generated",
        organization: "generated",
        state: "XX",
        country: "XX",
        locality: "XX",
    };

    let key_pair = new_key_pair(&default_config)?;
    if default_config.self_signed {
        let cert = new_self_signed_certificate(&default_config, &key_pair)?;

        print(&cert.to_text()?)?;
        print(&key_pair.public_key_to_pem()?)?;
        print(&cert.to_pem()?)?;
    }

    Ok(())
}

/// Generates a new RSA public/private key pair with the specified size.
fn new_key_pair(config: &Config) -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(config.key_size_bits)?;
    let key_pair = PKey::from_rsa(rsa)?;
    Ok(key_pair)
}

/// Creates a new self-signed certificate which expires after 1 year.
fn new_self_signed_certificate(
    config: &Config,
    key_pair: &PKey<Private>,
) -> Result<X509, ErrorStack> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", config.country)?;
    x509_name.append_entry_by_text("ST", config.state)?;
    x509_name.append_entry_by_text("L", config.locality)?;
    x509_name.append_entry_by_text("O", config.organization)?;
    x509_name.append_entry_by_text("CN", config.common_name)?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;

    cert_builder.set_version(2)?;
    let serial_number = new_serial_number()?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_issuer_name(&x509_name)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(config.days_until_expiration)?;
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

/// Prints raw certificate data.
fn print(c: &[u8]) -> Result<(), Utf8Error> {
    print!("{}", str::from_utf8(c)?);
    Ok(())
}
