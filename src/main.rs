//! # A binary crate

// Lints:
#![warn(clippy::pedantic)]
#![warn(deprecated_in_future)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use clap::Parser;
use human_panic::setup_panic;
use mkcert::{AppError, Args, Config};
use std::path::PathBuf;

fn main() -> Result<(), AppError> {
    setup_panic!();

    let cli = Cli::parse();

    let args = Args {
        file_path: cli.file,
        bundle_path: cli.bundle,
    };

    let config = Config::build(args)?;
    mkcert::run(config)?;
    Ok(())
}

// const HELP: &str = "Error: {e}\nTry 'mkcert --help' for more information.";
const TEMPLATE: &str = "
{about}
https://github.com/andreaslongo/mkcert

{usage-heading} {usage}

{all-args}";

#[derive(Debug, Parser)]
#[command(about, version, arg_required_else_help(true), help_template = TEMPLATE)]
struct Cli {
    /// Template file
    #[arg(short, long)]
    file: Option<Vec<PathBuf>>,

    /// Bundle a private key with a certificate into a PKCS #12 file.
    #[arg(short, long)]
    bundle: Option<Vec<PathBuf>>,
}
