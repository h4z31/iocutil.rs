use crate::contenthash::ContentHash;
use crate::SampleHash;
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use std::io::{Error, Write};

/// Hash calculator
pub struct Hasher {
    sha256: Sha256,
    sha1: Sha1,
    md5: Md5,
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher {
            sha256: Sha256::new(),
            sha1: Sha1::new(),
            md5: Md5::new(),
        }
    }
}

impl Hasher {
    /// create new hasher
    pub fn new() -> Self {
        Hasher::default()
    }

    /// get hash digests
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let mut hasher = Hasher::default();
    /// let mut f = std::fs::File::open("./Cargo.toml").expect("failed to open Cargo.toml");
    /// std::io::copy(&mut f, &mut hasher).unwrap();
    /// println!("{:?}", hasher.digests());
    /// ```
    pub fn digests(&mut self) -> ContentHash {
        ContentHash {
            sha256: SampleHash::new(self.sha256.result_str()).unwrap(),
            sha1: SampleHash::new(self.sha1.result_str()).unwrap(),
            md5: SampleHash::new(self.md5.result_str()).unwrap(),
        }
    }
}

impl Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.sha256.input(buf);
        self.sha1.input(buf);
        self.md5.input(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
