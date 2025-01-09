use anyhow::{Context, Error, Result};
use binrw::{BinRead, BinWrite, NullString};
use rsa::{BigUint, RsaPrivateKey};
use std::io::{Read, Seek};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use crate::pbo::test::hash_pbo;
use crate::sign::signature::BiSignature;
use crate::sign::version::BISignVersion::V3;

#[derive(Debug,Clone)]
pub struct BIPrivateKey {
    pub authority: String,
    key: RsaPrivateKey,
    length: u32,
}

impl BIPrivateKey{
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<BIPrivateKey> {
        let key = BinaryBiPrivateKey::read(reader).context("Failed to read private key")?;
        key.try_into()
    }

    pub fn sign_pbo<R: Read + Seek>(&self, reader: &mut R) -> Result<BiSignature> {
        let (hash1, hash2, hash3) = hash_pbo(reader, V3, self.length)?;
        
        let d = self.key.d();
        let n = self.key.n();
        

        let sig1 = hash1.modpow(d, n);
        let sig2 = hash2.modpow(d, n);
        let sig3 = hash3.modpow(d, n);
        
        Ok(
            BiSignature {
                authority: self.authority.clone(),
                version: V3,
                length: self.length,
                exponent: self.key.e().clone(),
                n: self.key.n().clone(),
                sig1,
                sig2,
                sig3,
            }
        )
    }
}

#[derive(BinRead, Debug)]
#[brw(little, assert(body_len == key_length / 16 * 9 + 20))]
struct BinaryBiPrivateKey {
    authority: NullString,
    // The length of the body in bytes
    body_len: u32,
    // I am unsure what this magic is, but it is always the same
    #[br(magic = b"\x07\x02\x00\x00\x00\x24\x00\x00", assert(sig_type == *b"RSA2"))]
    sig_type: [u8; 4],
    // In bit
    key_length: u32,
    #[br(count = body_len - 4 * 4 - key_length / 16 * 9)]
    exponent: Vec<u8>,
    #[br(count = key_length / 8)]
    n: Vec<u8>,
    #[br(count = key_length / 16)]
    p: Vec<u8>,
    #[br(count = key_length / 16)]
    q: Vec<u8>,
    #[br(count = key_length / 16)]
    dp: Vec<u8>,
    #[br(count = key_length / 16)]
    dq: Vec<u8>,
    #[br(count = key_length / 16)]
    qinv: Vec<u8>,
    #[br(count = key_length / 8)]
    d: Vec<u8>,
}

impl TryFrom<BinaryBiPrivateKey> for BIPrivateKey {
    type Error = Error;

    fn try_from(value: BinaryBiPrivateKey) -> Result<Self, Self::Error> {
        Ok(BIPrivateKey {
            authority: value.authority.to_string(),
            key: RsaPrivateKey::from_components(
                BigUint::from_bytes_le(&value.n),
                BigUint::from_bytes_le(&value.exponent),
                BigUint::from_bytes_le(&value.d),
                vec![
                    BigUint::from_bytes_le(&value.p),
                    BigUint::from_bytes_le(&value.q),
                ],
            )?,
            length: value.key_length,
        })
    }
}
