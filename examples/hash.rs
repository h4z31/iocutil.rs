use iocutil::prelude::*;
use std::collections::HashSet;

fn main() {
    // use SampleHash to manage a hash.
    // it validate hash (sha256 / sha1 / md5).
    let a1 = SampleHash::new("d41d8cd98f00b204e9800998ecf8427e").unwrap();

    // you can use sample! macro for literals (it will panic if you specify invalid input)
    let a1 = sample!("d41d8cd98f00b204e9800998ecf8427e");

    let a2 = sample!("D41D8CD98F00B204E9800998ECF8427E");

    // ignore case
    assert_eq!(a1, a2);

    // find hashes in text
    let text = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, D41D8CD98F00B204E9800998ECF8427E";
    let found: HashSet<_> = SampleHash::find(text);

    assert_eq!(found.len(), 2);
    assert!(found.contains(&sample!(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )));
    assert!(found.contains(&sample!("d41d8cd98f00b204e9800998ecf8427e")));

    // uniquify hashes
    let targets = vec![
        "d41d8cd98f00b204e9800998ecf8427e",
        "D41D8CD98F00B204E9800998ECF8427E",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    ];

    let unique: Vec<_> = SampleHash::uniquify(targets);
    assert_eq!(unique.len(), 3);

    // SampleHash is compatible with &str (it implements AsRef<str>)
    fn test(x: impl AsRef<str>) {
        println!("{}", x.as_ref());
    }

    test(sample!(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
}
