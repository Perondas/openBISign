use clap::Parser;
use std::path::PathBuf;

/// Pbo signing utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to the private key
    pub private_key_path: PathBuf,

    /// Path to the pbo files to be signed. Supports wildcards
    pub pbo_path: String,
}
