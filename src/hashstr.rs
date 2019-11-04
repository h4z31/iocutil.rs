use std::collections::HashSet;

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref MD5_PATTERN: Regex =
        Regex::new(r"(^|[[:^xdigit:]])(?P<target>[[:xdigit:]]{32})([[:^xdigit:]]|$)").unwrap();
    static ref SHA1_PATTERN: Regex =
        Regex::new(r"(^|[[:^xdigit:]])(?P<target>[[:xdigit:]]{40})([[:^xdigit:]]|$)").unwrap();
    static ref SHA256_PATTERN: Regex =
        Regex::new(r"(^|[[:^xdigit:]])(?P<target>[[:xdigit:]]{64})([[:^xdigit:]]|$)").unwrap();
    static ref HASH_PATTERN: Regex = Regex::new(
        r"(^|[[:^xdigit:]])(?P<target>[[:xdigit:]]{32}|[[:xdigit:]]{40}|[[:xdigit:]]{64})([[:^xdigit:]]|$)"
    )
    .unwrap();
}

#[derive(Debug, Eq, PartialEq)]
pub enum HashType {
    Unknown,
    MD5,
    SHA1,
    SHA256,
}

/// is specified text is md5 hex digest?
pub fn is_md5(target: &impl AsRef<str>) -> bool {
    let target = target.as_ref();
    MD5_PATTERN.is_match(target) && (target.len() == 32)
}

/// is specified text is sha1 hex digest?
pub fn is_sha1(target: &impl AsRef<str>) -> bool {
    let target = target.as_ref();
    SHA1_PATTERN.is_match(target.as_ref()) && (target.len() == 40)
}

/// is specified text is sha256 hex digest?
pub fn is_sha256(target: &impl AsRef<str>) -> bool {
    let target = target.as_ref();
    SHA256_PATTERN.is_match(target.as_ref()) && (target.len() == 64)
}

/// detect hash type of specified text
pub fn detect(target: &impl AsRef<str>) -> HashType {
    match target {
        _ if is_md5(target) => HashType::MD5,
        _ if is_sha1(target) => HashType::SHA1,
        _ if is_sha256(target) => HashType::SHA256,
        _ => HashType::Unknown,
    }
}

/// is empty hash value?
pub fn is_empty(target: &impl AsRef<str>) -> bool {
    match target.as_ref().to_lowercase().as_str() {
        "d41d8cd98f00b204e9800998ecf8427e" => true,         // md5
        "da39a3ee5e6b4b0d3255bfef95601890afd80709" => true, // sha1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" => true, // sha256
        _ => false,
    }
}

/// find md5 hash string from specified text
pub fn find_md5(target: &impl AsRef<str>) -> HashSet<String> {
    MD5_PATTERN
        .captures_iter(target.as_ref())
        .map(|x| x["target"].to_lowercase())
        .collect()
}

/// find sha1 hash string from specified text
pub fn find_sha1(target: &impl AsRef<str>) -> HashSet<String> {
    SHA1_PATTERN
        .captures_iter(target.as_ref())
        .map(|x| x["target"].to_lowercase())
        .collect()
}

/// find sha256 hash string from specified text
pub fn find_sha256(target: &impl AsRef<str>) -> HashSet<String> {
    SHA256_PATTERN
        .captures_iter(target.as_ref())
        .map(|x| x["target"].to_lowercase())
        .collect()
}

/// find hash string from specified text
pub fn find(target: &impl AsRef<str>) -> HashSet<String> {
    HASH_PATTERN
        .captures_iter(target.as_ref())
        .map(|x| x["target"].to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_md5() {
        assert_eq!(is_md5(&"d41d8cd98f00b204e9800998ecf8427e"), true);
        assert_eq!(is_md5(&"D41D8CD98F00B204E9800998ECF8427E"), true);
        assert_eq!(is_md5(&"d41d8cd98f00b204e9800998ecf8427"), false);
        assert_eq!(is_md5(&"D41D8CD98F00B204E9800998ECF8427"), false);
        assert_eq!(is_md5(&":d41d8cd98f00b204e9800998ecf8427e:"), false);
        assert_eq!(is_md5(&":d41d8cd98f00b204e9800998ecf8427e:"), false);
    }

    #[test]
    fn test_is_sha1() {
        assert_eq!(is_sha1(&"da39a3ee5e6b4b0d3255bfef95601890afd80709"), true);
        assert_eq!(is_sha1(&"da39a3ee5e6b4b0d3255bfef95601890afd8070"), false);
        assert_eq!(is_sha1(&"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"), true);
        assert_eq!(is_sha1(&"DA39A3EE5E6B4B0D3255BFEF95601890AFD8070"), false);
        assert_eq!(is_sha1(&":da39a3ee5e6b4b0d3255bfef95601890afd80709"), false);
        assert_eq!(is_sha1(&"da39a3ee5e6b4b0d3255bfef95601890afd80709:"), false);
    }

    #[test]
    fn test_is_sha256() {
        assert_eq!(
            is_sha256(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            true,
        );
        assert_eq!(
            is_sha256(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"),
            false,
        );
        assert_eq!(
            is_sha256(&"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
            true,
        );
        assert_eq!(
            is_sha256(&"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B85"),
            false,
        );
        assert_eq!(
            is_sha256(&":e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            false,
        );
        assert_eq!(
            is_sha256(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:"),
            false,
        );
    }

    #[test]
    fn test_detect() {
        assert_eq!(HashType::MD5, detect(&"d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(
            HashType::SHA1,
            detect(&"da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            HashType::SHA256,
            detect(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(HashType::Unknown, detect(&"something not hash text"));
    }

    #[test]
    fn test_is_empty() {
        assert_eq!(true, is_empty(&"d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(true, is_empty(&"da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert_eq!(
            true,
            is_empty(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );

        assert_eq!(true, is_empty(&"D41D8CD98F00B204E9800998ECF8427E"));
        assert_eq!(true, is_empty(&"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"));
        assert_eq!(
            true,
            is_empty(&"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
        );

        assert_eq!(false, is_empty(&"d41d8cd98f00b204e9800998ecf8427f"));
        assert_eq!(false, is_empty(&"da39a3ee5e6b4b0d3255bfef95601890afd80710"));
        assert_eq!(
            false,
            is_empty(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856")
        );
    }

    #[test]
    fn test_find_md5() {
        let target = r#"
            d41d8cd98f00b204e9800998ecf8427e
            D41D8CD98F00B204E9800998ECF8427E
            da39a3ee5e6b4b0d3255bfef95601890afd80709
            DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
        "#;
        let found = find_md5(&target);
        assert_eq!(1, found.len());
        assert_eq!(true, found.contains("d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn test_find_sha1() {
        let target = r#"
            d41d8cd98f00b204e9800998ecf8427e
            D41D8CD98F00B204E9800998ECF8427E
            da39a3ee5e6b4b0d3255bfef95601890afd80709
            DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
        "#;
        let found = find_sha1(&target);
        assert_eq!(1, found.len());
        assert_eq!(
            true,
            found.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
    }

    #[test]
    fn test_find_sha256() {
        let target = r#"
            d41d8cd98f00b204e9800998ecf8427e
            D41D8CD98F00B204E9800998ECF8427E
            da39a3ee5e6b4b0d3255bfef95601890afd80709
            DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
        "#;
        let found = find_sha256(&target);
        assert_eq!(1, found.len());
        assert_eq!(
            true,
            found.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn test_find() {
        let target = r#"
            d41d8cd98f00b204e9800998ecf8427e
            D41D8CD98F00B204E9800998ECF8427E
            da39a3ee5e6b4b0d3255bfef95601890afd80709
            DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
        "#;
        let found = find(&target);
        assert_eq!(3, found.len());
        assert_eq!(true, found.contains("d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(
            true,
            found.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            true,
            found.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }
}
