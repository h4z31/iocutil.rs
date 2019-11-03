use std::collections::HashSet;
use std::convert::TryFrom;
use std::str::FromStr;

pub mod prelude;
pub mod virustotal;

/// SampleHash
#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub enum SampleHash {
    Sha1(String),
    Sha256(String),
    Md5(String),
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
    let v = value.as_ref();
    let s = v.to_owned();
    match midy::detect(&v) {
        midy::HashType::MD5 => Ok(SampleHash::Md5(s)),
        midy::HashType::SHA1 => Ok(SampleHash::Sha1(s)),
        midy::HashType::SHA256 => Ok(SampleHash::Sha256(s)),
        _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
    }
}

impl TryFrom<&str> for SampleHash {
    type Error = failure::Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(to_sample(value)?)
    }
}

impl TryFrom<String> for SampleHash {
    type Error = failure::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
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
    pub fn new(hash: impl AsRef<str>) -> Result<Self, failure::Error> {
        hash.as_ref().parse()
    }

    /// map AsRef<str> to SampleHash
    pub fn map(
        hashes: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Vec<Self>, failure::Error> {
        hashes.into_iter().map(Self::new).collect()
    }
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
///     "d41d8cd98f00b204e9800998ecf8427e",
///     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
/// ];
///
/// let hashes = SampleHash::map(twice).expect("failed to parse");
/// assert_eq!(hashes.len(), 6);
/// let uniqued: Vec<SampleHash> = uniquify(hashes);
/// assert_eq!(uniqued.len(), 3);
/// ```
///
pub fn uniquify<T>(hashes: impl IntoIterator<Item = SampleHash>) -> T
where
    T: std::iter::FromIterator<SampleHash>,
{
    let uniqued: HashSet<SampleHash> = hashes.into_iter().collect();
    uniqued.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn try_from_str_works() {
        assert!(SampleHash::try_from("d41d8cd98f00b204e9800998ecf8427e").is_ok());
        assert!(SampleHash::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709").is_ok());
        assert!(SampleHash::try_from(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        .is_ok());
        assert!(SampleHash::try_from("invalid_hash").is_err());
    }

    #[test]
    fn new_works() {
        SampleHash::new("d41d8cd98f00b204e9800998ecf8427e").expect("parse error..");
        SampleHash::new("d41d8cd98f00b204e9800998ecf8427e".to_string()).expect("parse error..");
    }

    #[test]
    fn from_hashes_works() {
        let v = vec![
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ];
        let s = SampleHash::map(v).expect("parse error..");
        assert_eq!(s.len(), 3);

        let v = vec![
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ];
        let s = SampleHash::map(v).expect("parse error..");
        assert_eq!(s.len(), 3);

        let v = &[
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ];
        let s = SampleHash::map(v).expect("parse error..");
        assert_eq!(s.len(), 3);

        let v = &[
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ];
        let s = SampleHash::map(v).expect("parse error..");
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn try_from_string_works() {
        assert!(SampleHash::try_from("d41d8cd98f00b204e9800998ecf8427e".to_string()).is_ok());
        assert!(
            SampleHash::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()).is_ok()
        );
        assert!(SampleHash::try_from(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
        )
        .is_ok());
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
        let x: Result<SampleHash, failure::Error> = "invalid_hash".parse();
        assert!(x.is_err());
    }
}
