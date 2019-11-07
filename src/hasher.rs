use crate::contenthash::ContentHash;
use crate::SampleHash;
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use std::io::{Error, Write};
use std::sync::Mutex;

/// Hash calculator
pub struct Hasher {
    sha256: Mutex<Sha256>,
    sha1: Mutex<Sha1>,
    md5: Mutex<Md5>,
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher {
            sha256: Mutex::new(Sha256::new()),
            sha1: Mutex::new(Sha1::new()),
            md5: Mutex::new(Md5::new()),
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
    pub fn digests(self) -> ContentHash {
        let mut sha256 = self.sha256.lock().unwrap();
        let mut sha1 = self.sha1.lock().unwrap();
        let mut md5 = self.md5.lock().unwrap();
        ContentHash {
            sha256: SampleHash::new(sha256.result_str()).unwrap(),
            sha1: SampleHash::new(sha1.result_str()).unwrap(),
            md5: SampleHash::new(md5.result_str()).unwrap(),
        }
    }
}

impl Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let mut sha256 = self.sha256.lock().unwrap();
        let mut sha1 = self.sha1.lock().unwrap();
        let mut md5 = self.md5.lock().unwrap();
        sha256.input(buf);
        sha1.input(buf);
        md5.input(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
