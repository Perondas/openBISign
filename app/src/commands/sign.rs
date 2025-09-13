use crate::commands::macros::check_is_file;
use anyhow::Context;
use bi_fs_rs::keys::private_key::BIPrivateKey;
use bi_fs_rs::pbo::handle::PBOHandle;
use bi_fs_rs::sign::version::BISignVersion::V3;
use clap::Args;
use std::fs::File;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct SignCommandArgs {
    pub pbo_path: PathBuf,
    pub private_key_path: PathBuf,
}

pub fn sign_command(args: SignCommandArgs) -> anyhow::Result<()> {
    let SignCommandArgs {
        pbo_path,
        private_key_path,
    } = args;
    check_is_file!(pbo_path, private_key_path);

    let mut key_file = File::open(&private_key_path).context("Failed to open private key")?;

    let private_key =
        BIPrivateKey::from_reader(&mut key_file).context("Failed to read private key")?;

    let authority = &private_key.authority;

    let mut pbo = PBOHandle::open_file(&pbo_path)?;

    let signature = private_key.sign_pbo(&mut pbo, V3)?;

    let signature_path = pbo_path.with_extension(format!("pbo.{authority}.bisign"));

    let mut signature_file = File::create(&signature_path)?;
    signature.to_writer(&mut signature_file)?;

    Ok(())
}
