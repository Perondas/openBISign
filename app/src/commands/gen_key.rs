use bi_sign_core::keys::authority::Authority;
use bi_sign_core::keys::private_key::BIPrivateKey;
use bi_sign_core::keys::public_key::BIPublicKey;
use clap::Args;

#[derive(Args, Debug)]
pub struct GenKeyCommandArgs {
    pub authority: String,
    #[clap(default_value = "1024")]
    pub length: Option<u32>,
}

pub fn gen_key_command(args: GenKeyCommandArgs) -> anyhow::Result<()> {
    let authority = Authority::try_new(args.authority)?;

    let new_key = BIPrivateKey::new(authority, args.length.unwrap())?;

    let mut file = std::fs::File::create(format!("{}.biprivatekey", new_key.authority))?;
    new_key.to_writer(&mut file)?;

    let pub_key: BIPublicKey = new_key.into();
    let mut file = std::fs::File::create(format!("{}.bikey", pub_key.authority))?;
    pub_key.to_writer(&mut file)?;

    Ok(())
}
