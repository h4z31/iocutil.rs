use crate::hasher::Hasher;
use crate::GenericResult;
use crate::SampleHash;
use std::path::Path;

#[derive(Eq, PartialEq, Clone, Hash, Debug)]
pub struct ContentHash {
    pub sha256: SampleHash,
    pub sha1: SampleHash,
    pub md5: SampleHash,
}

impl ContentHash {
    /// content hash of file
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let ch = ContentHash::of_file(r"./Cargo.toml").expect("failed to calc hash");
    /// println!("{:?}", ch);
    /// ```
    pub fn of_file(path: impl AsRef<Path>) -> GenericResult<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut hasher = Hasher::default();
        std::io::copy(&mut f, &mut hasher)?;
        Ok(hasher.digests())
    }
}
