use crate::pbo::checksum::Checksum;
use crate::pbo::header::BinaryHeader;
use crate::pbo::mime::Mime;
use crate::pbo::hash::PBOHash;
use crate::sign::version::BISignVersion;
use anyhow::ensure;
use anyhow::Result;
use binrw::{BinRead, NullString};
use rsa::BigUint;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::SeekFrom::Current;
use std::io::{Read, Seek};
use std::path::Path;

#[derive(Debug)]
#[allow(dead_code)]
pub struct PBOHandle {
    properties: HashMap<String, String>,
    version_header: BinaryHeader,
    files: Vec<BinaryHeader>,
    checksum: Checksum,
    handle: std::fs::File,
    blob_start: u64,
}

impl PBOHandle {
    pub fn open_file(path: &Path) -> Result<Self> {
        let mut handle = std::fs::File::open(path)?;
        let mut properties = HashMap::new();
        let mut files = Vec::new();

        // Get the version header
        let version_header = BinaryHeader::read(&mut handle)?;

        ensure!(
            version_header.mime == Mime::Vers,
            "First header must be a version header"
        );

        // Get the properties
        loop {
            let key = NullString::read(&mut handle)?.to_string();
            if key.is_empty() {
                break;
            }
            let value = NullString::read(&mut handle)?.to_string();
            properties.insert(key, value);
        }

        // Get the headers
        loop {
            let header = BinaryHeader::read(&mut handle)?;
            if header.filename.is_empty() {
                break;
            }
            files.push(header);
        }

        // Skip past the blob + 1
        let blob_start = handle.stream_position()?;
        let blob_size = i64::from(files.iter().map(|f| f.size).sum::<u32>());

        handle.seek(Current(blob_size + 1))?;

        // Get the checksum
        let checksum = Checksum::read(&mut handle)?;

        // We should be at the end of the file
        ensure!(
            handle.stream_position()? == handle.metadata()?.len(),
            "File is not at the end"
        );

        Ok(Self {
            properties,
            version_header,
            files,
            checksum,
            handle,
            blob_start,
        })
    }

    pub fn generate_hash(&mut self, version: BISignVersion, length: u32) -> Result<PBOHash> {
        let hash1 = self.checksum.data;

        // Seek to the start of the blob
        self.handle
            .seek(std::io::SeekFrom::Start(self.blob_start))?;

        // Read file and hash them
        let mut file_hasher = sha1::Sha1::new();
        let mut nothing = true;
        for header in &self.files {
            if header.size != 0 && version.should_hash_file(&header.filename.to_string()) {
                let mut file = vec![0; header.size as usize];
                self.handle.read_exact(&mut file)?;
                file_hasher.update(&file);
                nothing = false;
            } else {
                self.handle.seek(Current(i64::from(header.size)))?;
            }
        }

        if nothing {
            file_hasher.update(version.nothing());
        }

        let file_hash = file_hasher.finalize().to_vec();

        let mut hasher = Sha1::new();
        hasher.update(self.checksum.data);
        hasher.update(hash_filenames(&self.files));

        if let Some(prefix) = self.properties.get("prefix") {
            hasher.update(prefix.as_bytes());
            if !prefix.ends_with('\\') {
                hasher.update(b"\\");
            }
        }

        let hash2 = hasher.finalize().to_vec();

        let mut hasher = Sha1::new();
        hasher.update(file_hash);
        hasher.update(hash_filenames(&self.files));
        if let Some(prefix) = self.properties.get("prefix") {
            hasher.update(prefix.as_bytes());
            if !prefix.ends_with('\\') {
                hasher.update(b"\\");
            }
        }
        let hash3 = hasher.finalize().to_vec();

        Ok(PBOHash(
            pad_hash(&hash1, (length / 8) as usize),
            pad_hash(&hash2, (length / 8) as usize),
            pad_hash(&hash3, (length / 8) as usize),
        ))
    }
}

#[must_use] pub fn pad_hash(hash: &[u8], size: usize) -> BigUint {
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
