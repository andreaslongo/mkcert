//! # An integration test crate

// Lints:
#![warn(clippy::pedantic)]
#![warn(deprecated_in_future)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use assert_cmd::prelude::*;
use mkcert::AppError;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn help() -> Result<(), AppError> {
    let mut cmd = Command::cargo_bin("mkcert")?;
    cmd.arg("--help");
    cmd.assert()
        .success()
        .code(0)
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains(
            "A simple program to create X.509 certificates",
        ));
    Ok(())
}

#[test]
fn version() -> Result<(), AppError> {
    let mut cmd = Command::cargo_bin("mkcert")?;
    cmd.arg("--version");
    cmd.assert()
        .success()
        .code(0)
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::is_match(r"^mkcert \d+\.\d+\.\d+\n$")?);
    Ok(())
}

//#[test]
//fn new_cert_syntax() -> Result<(), AppError> {
//    let mut cmd = Command::cargo_bin("mkcert")?;
//    cmd.arg("ticket").arg("new").arg("--help");
//    cmd.assert()
//        .success()
//        .code(0)
//        .stderr(predicate::str::is_empty())
//        .stdout(predicate::str::contains("Usage: visoma-cli ticket new [OPTIONS] --server <SERVER> --user <USER> --password <PASSWORD> --title <TITLE> --description <DESCRIPTION> --customer-id <CUSTOMER_ID> --address-id <ADDRESS_ID>"));
//    Ok(())
//}
