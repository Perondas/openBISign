#![ warn(clippy::pedantic)]

use crate::args::Args;
use anyhow::{Context, Result};
use bi_sign_core::keys::private_key::BIPrivateKey;
use bi_sign_core::pbo::pbo_handle::PBOHandle;
use bi_sign_core::sign::version::BISignVersion::V3;
use clap::Parser;
use indicatif::ProgressBar;
use std::fs::File;
use std::path::{Path, PathBuf};

mod args;

fn main() -> Result<()> {
    let Args {
        pbo_path,
        private_key_path,
    } = Args::parse();

    if !private_key_path.exists() {
        return Err(anyhow::anyhow!("Private key path does not exist"));
    }

    if !private_key_path.is_file() {
        return Err(anyhow::anyhow!("Private key path is not a file"));
    }

    let mut key_file = File::open(&private_key_path).context("Failed to open private key")?;

    let private_key =
        BIPrivateKey::from_reader(&mut key_file).context("Failed to read private key")?;
    let authority = &private_key.authority;

    println!("Signing with authority: {}", authority);

    let pbo_paths = glob::glob(&pbo_path)
        .context("Failed to resolve pbo path")?
        .filter_map(|p| match p {
            Ok(p) if p.extension().map(|p| p == "pbo").unwrap_or_default() => Some(p),
            Ok(_) => None,
            Err(e) => {
                eprintln!("Failed to resolve pbo path: {:?}", e);
                None
            }
        })
        .collect::<Vec<PathBuf>>();

    if pbo_paths.is_empty() {
        eprintln!("No PBOs found to sign");
        return Ok(());
    }

    println!("Found {} PBOs to sign", pbo_paths.len());

    let pb = ProgressBar::new(pbo_paths.len() as u64);

    let k2 = private_key.clone();
    let a2 = authority.clone();
    let pb2 = pb.clone();
    rayon::scope(move |s| {
        for pbo_path in pbo_paths {
            let key = k2.clone();
            let authority = a2.clone();
            let pb = pb2.clone();
            s.spawn(move |_| {
                if let Err(e) = sign_pbo(&pbo_path, &key, &authority) {
                    pb.println(format!("Failed to sign {:?}: {:?}", pbo_path, e));
                }
                pb.inc(1);
            });
        }
    });

    pb.println("Done");
    pb.finish();

    Ok(())
}

fn sign_pbo(pbo_path: &Path, key: &BIPrivateKey, authority: &str) -> Result<()> {
    let mut pbo = PBOHandle::open_file(pbo_path)?;

    let signature = key.sign_pbo(&mut pbo, V3)?;

    let signature_path = pbo_path.with_extension(format!("pbo.{}.bisign", authority));

    let mut signature_file = File::create(&signature_path)?;
    signature.to_writer(&mut signature_file)?;
    Ok(())
}
