use crate::commands::macros::check_is_dir;
use anyhow::{anyhow, Result};
use bi_sign_core::keys::authority::Authority;
use bi_sign_core::keys::public_key::BIPublicKey;
use bi_sign_core::pbo::handle::PBOHandle;
use bi_sign_core::sign::signature::BiSignature;
use clap::Args;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::LazyLock;

static KEY_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+)\.bikey$").unwrap());

static PBO_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+)\.pbo$").unwrap());

static PBO_SIG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(.+)\.pbo\.(.+)\.bisign$").unwrap());

#[derive(Debug, Args)]
pub struct VerifyCommandArgs {
    pub checked_dir: PathBuf,
    pub keys_dir: PathBuf,
}

pub fn verify_command(args: VerifyCommandArgs) -> Result<()> {
    let VerifyCommandArgs {
        checked_dir,
        keys_dir,
    } = args;
    check_is_dir!(checked_dir, keys_dir);

    let keys = get_all_keys(&keys_dir)?;

    let pbo_files = get_all_pbos(&checked_dir)?;

    for (path, signatures) in pbo_files {
        let mut pbo = PBOHandle::open_file(&path)?;

        for (authority, sig_path) in signatures {
            let key = match keys.get(&authority) {
                Some(key) => key,
                None => {
                    eprintln!(
                        "No key found for authority: {}, skipping verification.",
                        authority
                    );
                    continue;
                }
            };

            let mut sig_file = File::open(&sig_path)?;
            let sig = BiSignature::from_reader(&mut sig_file)?;

            if !key.verify_signature(&mut pbo, &sig)? {
                eprintln!(
                    "Signature verification failed for PBO: {}, authority: {}",
                    path.display(),
                    authority
                );
            }
        }
    }

    Ok(())
}

fn get_all_keys(keys_dir: &PathBuf) -> Result<HashMap<Authority, BIPublicKey>> {
    let mut keys = HashMap::new();

    for entry in std::fs::read_dir(keys_dir)?.filter_map(Result::ok) {
        let path = entry.path();
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        let matches = match KEY_NAME_REGEX.captures(file_name) {
            Some(captures) => captures,
            None => continue,
        };

        if matches.get(0).is_none() {
            continue;
        }

        let authority = Authority::try_new(matches.get(1).unwrap().as_str())?;
        let mut file = File::open(path)?;

        let key = BIPublicKey::from_reader(&mut file)?;

        if key.authority != authority {
            return Err(anyhow!(
                "Authority mismatch: expected {}, found {}",
                key.authority,
                authority,
            ));
        }

        keys.insert(authority, key);
    }

    Ok(keys)
}

fn get_all_pbos(checked_dir: &PathBuf) -> Result<Vec<(PathBuf, Vec<(Authority, PathBuf)>)>> {
    let mut pbo_files = Vec::new();

    let entries = std::fs::read_dir(checked_dir)?.filter_map(Result::ok);

    let mut signature_map: HashMap<String, Vec<(Authority, PathBuf)>> = HashMap::new();
    let mut pbo_map: HashMap<String, PathBuf> = HashMap::new();

    for entry in entries {
        if !entry.path().is_file() {
            continue;
        }

        let file_name = entry.file_name().clone();

        if let Some(matches) = PBO_NAME_REGEX.captures(&file_name.to_string_lossy()) {
            let pbo_name = matches.get(1).unwrap().as_str().to_string();
            let pbo_path = entry.path();

            pbo_map.insert(pbo_name, pbo_path);
        } else if let Some(matches) = PBO_SIG_REGEX.captures(&file_name.to_string_lossy()) {
            let authority = Authority::try_new(matches.get(2).unwrap().as_str())?;
            let pbo_name = matches.get(1).unwrap().as_str().to_string();
            let sig_path = entry.path();

            signature_map
                .entry(pbo_name)
                .or_default()
                .push((authority, sig_path));
        }
    }

    for (pbo_name, pbo_path) in pbo_map {
        let signatures = signature_map.remove(&pbo_name).unwrap_or_default();

        if signatures.is_empty() {
            eprintln!(
                "No signatures found for PBO: {}, skipping verification.",
                pbo_name
            );
            continue;
        }

        pbo_files.push((pbo_path, signatures));
    }

    Ok(pbo_files)
}
