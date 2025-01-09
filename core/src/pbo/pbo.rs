use crate::pbo::checksum::Checksum;
use crate::pbo::header::BinaryHeader;
use crate::pbo::mime::Mime;
use anyhow::{anyhow, ensure, Result};
use binrw::{BinRead, BinReaderExt, NullString};
use std::collections::HashMap;
use std::io::SeekFrom::Current;
use std::io::{Read, Seek};


#[derive(Debug)]
struct BinaryPBO {
    properties: HashMap<String, String>,
    version_header: BinaryHeader,
    headers: Vec<BinaryHeader>,
    blob_start: u64,
    file_starts: HashMap<String, u64>,
    checksum1: Checksum,
}

impl BinaryPBO {
    fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<Self> {
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

        let blob_start = reader.seek(Current(0))?;

        let mut file_starts = HashMap::new();
        let mut index = blob_start;

        for header in &headers {
            file_starts.insert(header.filename.to_string(), index);
            index += header.size as u64;
        }

        let body_len: i64 = headers.iter().map(|h| h.size as i64).sum();
        reader.seek(Current(body_len + 1))?;

        let checksum1 = Checksum::read(reader)?;
        
        if reader.read_le::<u8>().is_ok() {
            return Err(anyhow!("Unexpected data after checksum"));
        }

        Ok(Self {
            properties,
            version_header,
            headers,
            blob_start,
            file_starts,
            checksum1,
        })
    }
}


