use binrw::{BinRead, BinWrite};
use std::{
    ffi::OsStr,
    path::PathBuf
};

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
    #[brw(magic = 2u32)]
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
    #[brw(magic = 3u32)]
    V3,
}

impl BISignVersion {
    #[must_use]
    /// Should a file be hashed?
    pub fn should_hash_file(&self, name: &str) -> bool {
        let path = PathBuf::from(name);
        let ext = path.extension().unwrap_or_else(|| OsStr::new(""));
        match self {
            Self::V2 => [
                OsStr::new("fxy"),
                OsStr::new("jpg"),
                OsStr::new("lip"),
                OsStr::new("ogg"),
                OsStr::new("p3d"),
                OsStr::new("paa"),
                OsStr::new("pac"),
                OsStr::new("png"),
                OsStr::new("rtm"),
                OsStr::new("rvmat"),
                OsStr::new("tga"),
                OsStr::new("wrp"),
                OsStr::new("wss"),
            ]
            .contains(&ext),
            Self::V3 => [
                OsStr::new("bikb"),
                OsStr::new("cfg"),
                OsStr::new("ext"),
                OsStr::new("fsm"),
                OsStr::new("h"),
                OsStr::new("hpp"),
                OsStr::new("inc"),
                OsStr::new("sqf"),
                OsStr::new("sqfc"),
                OsStr::new("sqm"),
                OsStr::new("sqs"),
            ]
            .contains(&ext),
        }
    }

    #[must_use]
    /// Get the nothing string for the version
    pub const fn nothing(&self) -> &str {
        match self {
            Self::V2 => "nothing",
            Self::V3 => "gnihton",
        }
    }
}
