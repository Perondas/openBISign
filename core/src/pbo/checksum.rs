use binrw::BinRead;

#[derive(Debug, BinRead, Clone)]
#[brw(little)]
pub(crate) struct Checksum {
    pub data: [u8; 20],
}
