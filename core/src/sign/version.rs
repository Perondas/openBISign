use binrw::{BinRead, BinWrite};

/// Version of BI's signature
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default, BinRead, BinWrite)]
pub enum BISignVersion {
    /// Version 2
    ///
    /// Hashes the following file extensions:
    /// - fxy
    /// - jpg
    /// - lip
    /// - ogg
    /// - p3d
    /// - paa
    /// - pac
    /// - png
    /// - rtm
    /// - rvmat
    /// - tga
    /// - wrp
    /// - wss
    #[br(magic = 2u32)]
    #[bw(magic = 2u32)]
    V2,
    #[default]
    /// Version 3
    ///
    /// Hashes the following file extensions:
    /// - bikb
    /// - cfg
    /// - ext
    /// - fsm
    /// - h
    /// - hpp
    /// - inc
    /// - sqf
    /// - sqfc
    /// - sqm
    /// - sqs
    #[br(magic = 3u32)]
    #[bw(magic = 3u32)]
    V3,
}
