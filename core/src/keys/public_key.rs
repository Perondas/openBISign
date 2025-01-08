use anyhow::Result;
use anyhow::{Context, Error};
use binrw::{BinRead, NullString};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use std::io::{Read, Seek};

#[derive(Debug)]
pub struct BIPublicKey {
    pub authority: String,
    key: RsaPublicKey,
}

impl BIPublicKey {
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<BIPublicKey> {
        let key = BinaryBiPublicKey::read(reader).context("Failed to read public key")?;
        key.try_into()
    }
}

#[derive(BinRead, Debug)]
#[brw(little, assert(body_len == key_length / 8 + 20))]
struct BinaryBiPublicKey {
    authority: NullString,
    // The length of the body in bytes
    body_len: u32,
    // I am unsure what this magic is, but it is always the same
    #[br(magic = b"\x06\x02\x00\x00\x00\x24\x00\x00", assert(sig_type == *b"RSA1"))]
    sig_type: [u8; 4],
    // In bit
    key_length: u32,
    #[br(count = body_len - 4 * 4 - key_length / 8)]
    exponent: Vec<u8>,
    #[br(count = key_length / 8)]
    key: Vec<u8>,
}

impl TryFrom<BinaryBiPublicKey> for BIPublicKey {
    type Error = Error;

    fn try_from(value: BinaryBiPublicKey) -> Result<Self> {
        Ok(BIPublicKey {
            authority: value.authority.to_string(),
            key: RsaPublicKey::new(
                BigUint::from_bytes_le(&value.key),
                BigUint::from_bytes_le(&value.exponent),
            )?,
        })
    }
}

impl From<BIPublicKey> for BinaryBiPublicKey {
    fn from(value: BIPublicKey) -> Self {
        BinaryBiPublicKey {
            authority: NullString::from(value.authority),
            body_len: 20 + value.key.n().to_bytes_le().len() as u32,
            sig_type: *b"RSA1",
            key_length: value.key.n().to_bytes_le().len() as u32 * 8,
            exponent: value.key.e().to_bytes_le(),
            key: value.key.n().to_bytes_le(),
        }
    }
}
