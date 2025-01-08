use anyhow::{Context, Result};
use biSignCore::keys::private_key::BIPrivateKey;
use biSignCore::keys::public_key::BIPublicKey;
use biSignCore::sign::signature::BiSignature;
use clap::Parser;
use std::fs::File;

mod args;

fn main() -> Result<()> {
    let mut file = File::open("data/fp_blended.bikey").unwrap();

    let key = BIPublicKey::from_reader(&mut file).unwrap();

    //println!("{:?}", key);

    let mut file = File::open("data/fp_blended.biprivatekey").unwrap();

    let key = BIPrivateKey::from_reader(&mut file).unwrap();

    //println!("{:?}", key);

    let mut file = File::open("data/min_rf_air_c.pbo.fp_blended.bisign").unwrap();

    let sig = BiSignature::from_reader(&mut file).unwrap();

    println!("{:?}", sig);
    
    let mut nSig = File::create("data/min_rf_air_c.pbo.fp_blended.bisign2").unwrap();
    sig.to_writer(&mut nSig).context("Failed to write signature")?;
    
    let mut nSig = File::open("data/min_rf_air_c.pbo.fp_blended.bisign2").unwrap();
    let sig2 = BiSignature::from_reader(&mut nSig).unwrap();
    
    println!("{:?}", sig2);
    
    Ok(())
}
