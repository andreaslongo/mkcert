use std::error::Error;
use std::str;

use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::bn::MsbOption;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509;

/// Creates a new self-signed certificate and prints the details.
pub fn run() -> Result<(), Box<dyn Error>> {
    let key_pair = new_key_pair()?;
    let cert = new_self_signed_certificate(&key_pair)?;

    let _ = print(&cert.to_text()?);
    let _ = print(&key_pair.public_key_to_pem()?);
    let _ = print(&cert.to_pem()?);

    Ok(())
}

/// Generates a new RSA 2048-bit public/private key pair.
fn new_key_pair() -> Result<PKey<Private>, Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    Ok(PKey::from_rsa(rsa)?)
}

/// Creates a new self-signed certificate which expires after 1 year.
fn new_self_signed_certificate(key_pair: &PKey<Private>) -> Result<X509, Box<dyn Error>> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "XX")?;
    x509_name.append_entry_by_text("ST", "XX")?;
    x509_name.append_entry_by_text("L", "XX")?;
    x509_name.append_entry_by_text("O", "generated")?;
    x509_name.append_entry_by_text("CN", "generated")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;

    cert_builder.set_version(2)?;
    let serial_number = new_serial_number()?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_issuer_name(&x509_name)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
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
fn new_serial_number() -> Result<Asn1Integer, Box<dyn Error>> {
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    Ok(serial.to_asn1_integer()?)
}

/// Prints raw certificate data.
fn print(c: &[u8]) -> Result<(), Box<dyn Error>> {
    print!("{}", str::from_utf8(c)?);
    Ok(())
}
