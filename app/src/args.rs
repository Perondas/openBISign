use crate::commands::gen_key::GenKeyCommandArgs;
use crate::commands::sign::SignCommandArgs;
use clap::{Parser, Subcommand};
use crate::commands::verify::VerifyCommandArgs;

/// Pbo signing utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: AppSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AppSubcommand {
    Sign(SignCommandArgs),
    Verify(VerifyCommandArgs),
    GenKey(GenKeyCommandArgs),
}
