use crate::SampleHash;
use std::convert::TryInto;
use std::io::{Error, ErrorKind};

pub fn unwrap_try_into(hash: impl TryInto<SampleHash>) -> Result<SampleHash, Error> {
    hash.try_into()
        .or(Err(Error::from(ErrorKind::InvalidInput)))
}
