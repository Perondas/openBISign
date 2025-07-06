use crate::args::{AppSubcommand, Args};
use crate::commands::gen_key::gen_key_command;
use crate::commands::sign::sign_command;
use crate::commands::verify::verify_command;
use anyhow::Result;
use clap::Parser;

mod args;
mod commands;

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        AppSubcommand::Sign(args) => sign_command(args),
        AppSubcommand::Verify(args) => verify_command(args),
        AppSubcommand::GenKey(args) => gen_key_command(args),
    }
}
