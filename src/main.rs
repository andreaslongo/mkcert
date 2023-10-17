use std::path::PathBuf;
use std::process;

use clap::Parser;

use mkcert::Args;
use mkcert::Config;

fn main() {
    let cli = Cli::parse();

    let args = Args {
        file_path: cli.file,
        bundle_path: cli.bundle,
    };

    let config = Config::build(args).unwrap_or_else(|e| {
        eprintln!("Configuration error: {e}\nTry 'mkcert --help' for more information.");
        process::exit(1);
    });

    if let Err(e) = mkcert::run(config) {
        eprintln!("Application error: {e}\nTry 'mkcert --help' for more information.");
        process::exit(1);
    }
}

/// A simple program to create X.509 certificates
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(arg_required_else_help(true))]
#[command(
    help_template = "{about-section}\n{usage-heading} {usage}\n\n{all-args}\n\nWritten by {author}\nhttps://github.com/andreaslongo/mkcert"
)]
pub struct Cli {
    /// Template file
    #[arg(short, long)]
    file: Option<Vec<PathBuf>>,

    /// Bundle a private key with a certificate into a PKCS #12 file.
    #[arg(short, long)]
    bundle: Option<Vec<PathBuf>>,
}
