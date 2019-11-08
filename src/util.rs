//! utilities for developing this module

use crate::SampleHash;
use std::convert::TryInto;
use std::io::{Error, ErrorKind};

pub fn unwrap_try_into(hash: impl TryInto<SampleHash>) -> Result<SampleHash, Error> {
    hash.try_into().or(Err(Error::from(ErrorKind::InvalidData)))
}

/// check target is expected hashtype
#[macro_export]
macro_rules! check_hashtype {
    ($hash:expr => md5) => {
        $crate::sample_md5($hash)
    };
    ($hash:expr => sha1) => {
        $crate::sample_sha1($hash)
    };
    ($hash:expr => sha256) => {
        $crate::sample_sha256($hash)
    };
}
