use crate::pbo::checksum::Checksum;
use crate::pbo::header::BinaryHeader;
use crate::pbo::mime::Mime;
use crate::sign::version::BISignVersion;
use anyhow::{anyhow, ensure};
use binrw::{BinRead, BinReaderExt, NullString};
use rsa::signature::digest::Digest;
use rsa::BigUint;
use sha1::Sha1;
use std::collections::HashMap;
use std::io::SeekFrom::Current;
use std::io::{Read, Seek};

pub fn hash_pbo<R: Read + Seek>(
    reader: &mut R,
    version: BISignVersion,
    length: u32,
) -> anyhow::Result<(BigUint, BigUint, BigUint)> {
    let mut properties = HashMap::new();
    let mut headers = Vec::new();

    // Get the version header
    let version_header = BinaryHeader::read(reader)?;

    ensure!(
        version_header.mime == Mime::Vers,
        "First header must be a version header"
    );

    // Get the properties
    loop {
        let key = NullString::read(reader)?.to_string();
        if key.is_empty() {
            break;
        }
        let value = NullString::read(reader)?.to_string();
        properties.insert(key, value);
    }

    // Get the headers
    loop {
        let header = BinaryHeader::read(reader)?;
        if header.filename.is_empty() {
            break;
        }
        headers.push(header);
    }

    // Read file and hash them
    let mut file_hasher = Sha1::new();
    let mut nothing = true;
    for header in &headers {
        if header.size != 0 && version.should_hash_file(&header.filename.to_string()) {
            let mut file = vec![0; header.size as usize];
            reader.read_exact(&mut file)?;
            file_hasher.update(&file);
            nothing = false;
        } else {
            reader.seek(Current(i64::from(header.size)))?;
        }
    }

    if nothing {
        file_hasher.update(version.nothing())
    }

    let file_hash = file_hasher.finalize().to_vec();

    reader.seek(Current(1))?;

    let checksum = Checksum::read(reader)?;
    let hash1 = checksum.data;

    if reader.read_le::<u8>().is_ok() {
        return Err(anyhow!("Unexpected data after checksum"));
    }

    let mut hasher = Sha1::new();
    hasher.update(checksum.data);
    hasher.update(hash_filenames(&headers));

    if let Some(prefix) = properties.get("prefix") {
        hasher.update(prefix.as_bytes());
        if !prefix.ends_with('\\') {
            hasher.update(b"\\");
        }
    }

    let hash2 = hasher.finalize().to_vec();

    let mut hasher = Sha1::new();
    hasher.update(file_hash);
    hasher.update(hash_filenames(&headers));
    if let Some(prefix) = properties.get("prefix") {
        hasher.update(prefix.as_bytes());
        if !prefix.ends_with('\\') {
            hasher.update(b"\\");
        }
    }
    let hash3 = hasher.finalize().to_vec();

    Ok((
        pad_hash(&hash1, (length / 8) as usize),
        pad_hash(&hash2, (length / 8) as usize),
        pad_hash(&hash3, (length / 8) as usize),
    ))
}

pub fn pad_hash(hash: &[u8], size: usize) -> BigUint {
    let mut vec: Vec<u8> = vec![0, 1];
    vec.resize(size - 36, 255);
    vec.extend(b"\x00\x30\x21\x30\x09\x06\x05\x2b");
    vec.extend(b"\x0e\x03\x02\x1a\x05\x00\x04\x14");
    vec.extend(hash);

    BigUint::from_bytes_be(&vec)
}

fn hash_filenames(headers: &[BinaryHeader]) -> Vec<u8> {
    let mut header_hasher = Sha1::new();
    for header in headers {
        if header.size != 0 {
            header_hasher.update(
                header
                    .filename
                    .to_string()
                    .replace('/', "\\")
                    .to_lowercase(),
            );
        }
    }
    header_hasher.finalize().to_vec()
}
