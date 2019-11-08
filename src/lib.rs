use crate::util::unwrap_try_into;
use failure::_core::fmt::{Error, Formatter};
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

type GenericResult<T> = std::result::Result<T, failure::Error>;

pub mod alienvault;
pub mod contenthash;
pub mod datetime;
pub mod hasher;
pub mod hashstr;
pub mod prelude;
pub mod scraper;
mod util;
pub mod virusbay;
pub mod virustotal;

/// manage a hash value (sha256/sha1/md5)
#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub enum SampleHash {
    Sha1(String),
    Sha256(String),
    Md5(String),
}

impl std::fmt::Display for SampleHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", self.as_ref())
    }
}

impl Into<String> for SampleHash {
    fn into(self) -> String {
        match self {
            SampleHash::Md5(x) => x,
            SampleHash::Sha1(x) => x,
            SampleHash::Sha256(x) => x,
        }
    }
}

impl AsRef<str> for SampleHash {
    fn as_ref(&self) -> &str {
        match self {
            SampleHash::Md5(x) => x.as_str(),
            SampleHash::Sha1(x) => x.as_str(),
            SampleHash::Sha256(x) => x.as_str(),
        }
    }
}

/// conversion
fn to_sample(value: impl AsRef<str>) -> Result<SampleHash, std::io::Error> {
    let s = value.as_ref().to_lowercase();
    match hashstr::detect(&s) {
        hashstr::HashType::MD5 => Ok(SampleHash::Md5(s)),
        hashstr::HashType::SHA1 => Ok(SampleHash::Sha1(s)),
        hashstr::HashType::SHA256 => Ok(SampleHash::Sha256(s)),
        _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
    }
}

impl TryFrom<&str> for SampleHash {
    type Error = failure::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(to_sample(value)?)
    }
}

impl TryFrom<&&str> for SampleHash {
    type Error = failure::Error;
    fn try_from(value: &&str) -> Result<Self, Self::Error> {
        Ok(to_sample(value)?)
    }
}

impl TryFrom<String> for SampleHash {
    type Error = failure::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(to_sample(value)?)
    }
}

impl TryFrom<&String> for SampleHash {
    type Error = failure::Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Ok(to_sample(value)?)
    }
}

impl FromStr for SampleHash {
    type Err = failure::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(to_sample(s)?)
    }
}

impl SampleHash {
    /// new SampleHash from md5/sha1/sha256 string
    pub fn new(hash: impl AsRef<str>) -> GenericResult<Self> {
        hash.as_ref().to_lowercase().parse()
    }

    /// map strings to SampleHash
    /// `try_map` is a better way if you want to map to Result (like Result<Vec<_>, _>).
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let hashes = vec![
    ///         "d41d8cd98f00b204e9800998ecf8427e",
    ///         "invalid_hash"
    ///     ];
    ///
    /// let r1: Result<Vec<_>, _> = SampleHash::map(&hashes);
    ///
    /// assert!(r1.is_err());
    ///
    /// let r2: Vec<Result<_, _>> = SampleHash::map(&hashes);
    ///
    /// assert_eq!(r2.len(), 2);
    /// assert!(r2.iter().nth(0).unwrap().is_ok());
    /// assert!(r2.iter().nth(1).unwrap().is_err());
    /// ```
    pub fn map<T>(hashes: impl IntoIterator<Item = impl TryInto<SampleHash>>) -> T
    where
        T: std::iter::FromIterator<GenericResult<SampleHash>>,
    {
        hashes
            .into_iter()
            .map(|x| unwrap_try_into(x).map_err(|e| e.into()))
            .collect()
    }

    /// try map strings to SampleHash
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    /// use std::collections::HashSet;
    ///
    /// let hashes1 = vec![
    ///     "d41d8cd98f00b204e9800998ecf8427e",
    ///     "d41d8cd98f00b204e9800998ecf8427e"
    /// ];
    ///
    /// let r1: HashSet<_> = SampleHash::try_map(hashes1).expect("failed to map");
    /// assert_eq!(r1.len(), 1);
    /// assert!(r1.contains(&sample!("d41d8cd98f00b204e9800998ecf8427e")));
    ///
    /// let hashes2 = vec![
    ///     "d41d8cd98f00b204e9800998ecf8427e",
    ///     "invalid_hash"
    /// ];
    ///
    /// let r2: Result<HashSet<_>, _> = SampleHash::try_map(&hashes2);
    /// assert!(r2.is_err());
    /// ```
    pub fn try_map<T>(
        hashes: impl IntoIterator<Item = impl TryInto<SampleHash>>,
    ) -> GenericResult<T>
    where
        T: std::iter::FromIterator<SampleHash>,
    {
        hashes
            .into_iter()
            .map(|x| unwrap_try_into(x).map_err(|e| e.into()))
            .collect()
    }

    /// uniquify the hashes
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let twice = vec![
    ///     "d41d8cd98f00b204e9800998ecf8427e",
    ///     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ///     // uniquify case-insensitive
    ///     "D41D8CD98F00B204E9800998ECF8427E",
    ///     "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
    ///     "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    ///     "a", // please note that invalid hashes are ignored
    /// ];
    ///
    /// let uniqued: Vec<_> = SampleHash::uniquify(twice);
    /// assert_eq!(uniqued.len(), 3);
    /// assert!(uniqued.contains(&sample!("d41d8cd98f00b204e9800998ecf8427e")));
    /// assert!(uniqued.contains(&sample!("da39a3ee5e6b4b0d3255bfef95601890afd80709")));
    /// assert!(uniqued.contains(&sample!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")));
    /// ```
    ///
    pub fn uniquify<T>(hashes: impl IntoIterator<Item = impl TryInto<SampleHash>>) -> T
    where
        T: std::iter::FromIterator<SampleHash>,
    {
        hashes
            .into_iter()
            .map(unwrap_try_into)
            .flat_map(|x| x) // filter failed to convert
            .collect::<HashSet<SampleHash>>()
            .into_iter()
            .collect()
    }

    /// find unique hashes in specified text
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let txt = r#"d41d8cd98f00b204e9800998ecf8427e,da39a3ee5e6b4b0d3255bfef95601890afd80709,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    /// D41D8CD98F00B204E9800998ECF8427E,DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
    /// "#;
    /// let hashes: Vec<_> = SampleHash::find(txt);
    /// // it scrapes unique hashes (ignore-case)
    /// assert_eq!(hashes.len(), 3);
    /// ```
    ///
    pub fn find<T>(text: impl AsRef<str>) -> T
    where
        T: std::iter::FromIterator<SampleHash>,
    {
        let v: GenericResult<HashSet<_>> = SampleHash::map(hashstr::find(&text));
        v.unwrap().into_iter().collect()
    }

    /// scrape hashes from specified url
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let hashes: std::collections::HashSet<_> = SampleHash::scrape("https://www.malware-traffic-analysis.net/2019/05/20/index.html").expect("failed to scrape https://www.malware-traffic-analysis.net/2019/05/20/index.html");
    /// assert_eq!(hashes.len(), 2);
    /// assert!(hashes.contains(&sample!("7f335f990851510ab9654e9fc1add2acec2c38a64563b711031769c58ecd45c0")));
    /// assert!(hashes.contains(&sample!("5a7042e698ce8e5cf6c4615e41a4205a52d9bb18a6ff214a967724c866cb72b4")));
    /// ```
    pub fn scrape<T>(url: impl AsRef<str>) -> GenericResult<T>
    where
        T: std::iter::FromIterator<SampleHash>,
    {
        Ok(SampleHash::find(scraper::get_article(url)?))
    }
}

/// # Example
///
/// ```
/// use iocutil::prelude::*;
/// let s1 = sample!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
/// assert_eq!(s1, SampleHash::Sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()));
///
/// // with hash type check
/// let s2 = sample!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" => sha256);
/// assert_eq!(s1, s2);
/// ```
///
/// ```should_panic
/// use iocutil::prelude::*;
/// // panic if it is not hash
/// sample!("a");
/// ```
///
/// ```should_panic
/// use iocutil::prelude::*;
/// // panic if hash type does not match
/// let s3 = sample!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" => md5); // panic
/// ```
#[macro_export]
macro_rules! sample {
    ($hash:literal) => {
        $crate::SampleHash::new($hash).unwrap()
    };
    ($hash:literal => sha256) => {
        $crate::sample_sha256($hash).unwrap()
    };
    ($hash:literal => sha1) => {
        $crate::sample_sha1($hash).unwrap()
    };
    ($hash:literal => md5) => {
        $crate::sample_md5($hash).unwrap()
    };
}

/// get sample if it is md5
pub fn sample_md5(hash: impl TryInto<SampleHash>) -> GenericResult<SampleHash> {
    let hash = unwrap_try_into(hash)?;
    if let SampleHash::Md5(_) = hash {
        Ok(hash)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into())
    }
}

/// get sample if it is sha1
pub fn sample_sha1(hash: impl TryInto<SampleHash>) -> GenericResult<SampleHash> {
    let hash = unwrap_try_into(hash)?;
    if let SampleHash::Sha1(_) = hash {
        Ok(hash)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into())
    }
}

/// get sample if it is sha256
pub fn sample_sha256(hash: impl TryInto<SampleHash>) -> GenericResult<SampleHash> {
    let hash = unwrap_try_into(hash)?;
    if let SampleHash::Sha256(_) = hash {
        Ok(hash)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn try_from_str_works() {
        let a1 = SampleHash::try_from("d41d8cd98f00b204e9800998ecf8427e").expect("failed to parse");
        let a2 = SampleHash::try_from("D41D8CD98F00B204E9800998ECF8427E").expect("failed to parse");
        assert_eq!(a1, a2);

        let b1 = SampleHash::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709")
            .expect("failed to parse");
        let b2 = SampleHash::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
            .expect("failed to parse");
        assert_eq!(b1, b2);

        let c1 = SampleHash::try_from(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .expect("failed to parse");
        let c2 = SampleHash::try_from(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        )
        .expect("failed to parse");
        assert_eq!(c1, c2);

        assert!(SampleHash::try_from("invalid_hash").is_err());
    }

    #[test]
    fn new_works() {
        let a1 = SampleHash::new("d41d8cd98f00b204e9800998ecf8427e").expect("parse error..");
        let a2 = SampleHash::new("D41D8CD98F00B204E9800998ECF8427E").expect("parse error..");
        let b1 =
            SampleHash::new("d41d8cd98f00b204e9800998ecf8427e".to_string()).expect("parse error..");
        let b2 =
            SampleHash::new("D41D8CD98F00B204E9800998ECF8427E".to_string()).expect("parse error..");
        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
        assert_eq!(a1, b2);
    }

    #[test]
    fn from_hashes_works() {
        let v = vec![
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ];
        let s: GenericResult<Vec<_>> = SampleHash::map(v);
        assert_eq!(s.unwrap().len(), 3);

        let v = vec![
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ];
        let s: GenericResult<Vec<_>> = SampleHash::map(v);
        assert_eq!(s.unwrap().len(), 3);

        let v = &[
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ];
        let s: GenericResult<Vec<_>> = SampleHash::map(v);
        assert_eq!(s.unwrap().len(), 3);

        let v = &[
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ];
        let s: GenericResult<Vec<_>> = SampleHash::map(v);
        assert_eq!(s.unwrap().len(), 3);
    }

    #[test]
    fn try_from_string_works() {
        let a1 = SampleHash::try_from("d41d8cd98f00b204e9800998ecf8427e".to_string())
            .expect("failed to parse");
        let a2 = SampleHash::try_from("D41D8CD98F00B204E9800998ECF8427E".to_string())
            .expect("failed to parse");
        assert_eq!(a1, a2);

        let b1 = SampleHash::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string())
            .expect("failed to parse");
        let b2 = SampleHash::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709".to_string())
            .expect("failed to parse");
        assert_eq!(b1, b2);

        let c1 = SampleHash::try_from(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        )
        .expect("failed to parse");
        let c2 = SampleHash::try_from(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".to_string(),
        )
        .expect("failed to parse");
        assert_eq!(c1, c2);

        assert!(SampleHash::try_from("invalid_hash".to_string()).is_err());
    }

    #[test]
    fn try_parse_works() {
        let _: SampleHash = "d41d8cd98f00b204e9800998ecf8427e"
            .parse()
            .expect("failed to parse");
        let _: SampleHash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            .parse()
            .expect("failed to parse");
        let _: SampleHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("failed to parse");
        let x: Result<SampleHash, _> = "invalid_hash".parse();
        assert!(x.is_err());
    }
}
