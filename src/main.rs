use std::process;

use clap::Parser;

fn main() {
    let _cli = Cli::parse();

    if let Err(e) = mkcert::run() {
        eprintln!("Application error: {e}\nTry 'mkcert --help' for more information.");
        process::exit(1);
    }
}

/// A simple program to create X.509 certificates
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(
    help_template = "{about-section}\n{usage-heading} {usage}\n\n{all-args}\n\nWritten by {author}\nhttps://github.com/andreaslongo/mkcert"
)]
pub struct Cli {}
