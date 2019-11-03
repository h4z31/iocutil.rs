use std::collections::HashSet;
use std::convert::TryFrom;
use std::str::FromStr;

pub mod hashstr;
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
        hash.as_ref().to_lowercase().parse()
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
///     "D41D8CD98F00B204E9800998ECF8427E",
///     "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
///     "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
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

/// scrape the hashes from specified text
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
///
/// let txt = r#"d41d8cd98f00b204e9800998ecf8427e,da39a3ee5e6b4b0d3255bfef95601890afd80709,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
/// D41D8CD98F00B204E9800998ECF8427E,DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
/// "#;
/// let hashes: Vec<SampleHash> = scrape(txt);
/// // it scrapes unique hashes (ignore-case)
/// assert_eq!(hashes.len(), 3);
/// ```
///
pub fn scrape<T>(text: impl AsRef<str>) -> T
where
    T: std::iter::FromIterator<SampleHash>,
{
    SampleHash::map(hashstr::find(&text))
        .unwrap() // this must be success
        .into_iter()
        .collect()
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
        let x: Result<SampleHash, failure::Error> = "invalid_hash".parse();
        assert!(x.is_err());
    }
}
