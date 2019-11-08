use crate::SampleHash;
use std::convert::TryInto;
use std::io::{Error, ErrorKind};

pub fn unwrap_try_into(hash: impl TryInto<SampleHash>) -> Result<SampleHash, Error> {
    hash.try_into().or(Err(Error::from(ErrorKind::InvalidData)))
}

#[macro_export]
macro_rules! check_hashtype {
    ($hash:expr => md5) => {
        if let $crate::SampleHash::Md5(_) = $hash {
            Ok($hash)
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
        }
    };
    ($hash:expr => sha1) => {
        if let $crate::SampleHash::Sha1(_) = $hash {
            Ok($hash)
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
        }
    };
    ($hash:expr => sha256) => {
        if let $crate::SampleHash::Sha256(_) = $hash {
            Ok($hash)
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
        }
    };
}
