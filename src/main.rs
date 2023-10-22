use std::path::PathBuf;
use std::process;

use clap::Parser;
use human_panic::setup_panic;

use mkcert::Args;
use mkcert::Config;

fn main() {
    setup_panic!();

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

const TEMPLATE: &str = "
{about}
https://github.com/andreaslongo/mkcert

{usage-heading} {usage}

{all-args}";

#[derive(Parser)]
#[command(about, version, arg_required_else_help(true), help_template = TEMPLATE)]
pub struct Cli {
    /// Template file
    #[arg(short, long)]
    file: Option<Vec<PathBuf>>,

    /// Bundle a private key with a certificate into a PKCS #12 file.
    #[arg(short, long)]
    bundle: Option<Vec<PathBuf>>,
}
