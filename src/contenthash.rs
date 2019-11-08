use crate::hasher::Hasher;
use crate::check_hashtype;
use crate::util::unwrap_try_into;
use crate::GenericResult;
use crate::SampleHash;
use std::collections::HashSet;
use std::convert::TryInto;
use std::path::Path;

#[derive(Eq, PartialEq, Clone, Hash, Debug)]
pub struct ContentHash {
    pub sha256: SampleHash,
    pub sha1: SampleHash,
    pub md5: SampleHash,
}

impl Default for ContentHash {
    /// return ContentHash of empty bytes as default
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let c = ContentHash::default();
    /// assert_eq!(c.sha256.as_ref(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    /// assert_eq!(c.sha1.as_ref(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    /// assert_eq!(c.md5.as_ref(), "d41d8cd98f00b204e9800998ecf8427e");
    /// ```
    fn default() -> Self {
        ContentHash {
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".parse().unwrap(),
            md5: "d41d8cd98f00b204e9800998ecf8427e".parse().unwrap(),
        }
    }
}

impl ContentHash {
    /// create new object manually (not recommened)
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    /// let x = ContentHash::new(
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ///     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ///     "d41d8cd98f00b204e9800998ecf8427e"
    /// ).unwrap();
    /// assert_eq!(x, ContentHash::default());
    ///
    /// let y = ContentHash::new("a", "b", "c");
    /// assert!(y.is_err());
    ///
    /// let z = ContentHash::new(
    ///     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ///     "d41d8cd98f00b204e9800998ecf8427e",
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    /// );
    /// assert!(z.is_err());
    /// ```
    pub fn new(
        sha256: impl TryInto<SampleHash>,
        sha1: impl TryInto<SampleHash>,
        md5: impl TryInto<SampleHash>,
    ) -> GenericResult<Self> {
        let s256 = unwrap_try_into(sha256)?;
        let s1 = unwrap_try_into(sha1)?;
        let md5 = unwrap_try_into(md5)?;
        Ok(ContentHash {
            sha256: check_hashtype!(s256 => sha256)?,
            sha1: check_hashtype!(s1 => sha1)?,
            md5: check_hashtype!(md5 => md5)?,
        })
    }

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

/// remove overlap from target with blacklist
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
/// use iocutil::contenthash::remove_overlap;
///
/// let c = ContentHash::default();
///
/// let target = vec!["9fbdc5eca123e81571e8966b9b4e4a1e".to_owned(), c.sha256.as_ref().to_string()];
/// let blacklist = vec![c];
///
/// let ro = remove_overlap(target, blacklist);
/// assert_eq!(ro.len(), 1);
/// assert!(ro.contains(&sample!("9fbdc5eca123e81571e8966b9b4e4a1e")));
/// ```
pub fn remove_overlap(
    target: impl IntoIterator<Item = impl std::convert::TryInto<SampleHash>>,
    blacklist: impl IntoIterator<Item = ContentHash>,
) -> HashSet<SampleHash> {
    let target: HashSet<SampleHash> = SampleHash::uniquify(target);
    let blacklist: HashSet<SampleHash> = blacklist
        .into_iter()
        .map(|x| x.into_iter())
        .flat_map(|x| x)
        .collect();
    target.difference(&blacklist).cloned().collect()
}

impl IntoIterator for ContentHash {
    type Item = SampleHash;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let s = ContentHash::of_file("./Cargo.toml").unwrap();
    /// let set: std::collections::HashSet<SampleHash> = s.into_iter().collect();
    ///
    /// assert_eq!(set.len(), 3);
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        vec![self.sha256, self.sha1, self.md5].into_iter()
    }
}
