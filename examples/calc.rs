use iocutil::prelude::*;

fn main() {
    // use ContentHash to bundle of hashes(sha256 / sha1 / md5)

    // calculate hashes of file content
    let c = ContentHash::of_file(r"C:\Windows\notepad.exe").unwrap();
    println!("notepad.exe => {:?}", c);

    // calculate hashes of arbitrary content which implements std::io::Read with Hasher
    let mut hasher = Hasher::new();
    let mut res = reqwest::get("https://example.com/").unwrap();
    std::io::copy(&mut res, &mut hasher).unwrap();

    let c: ContentHash = hasher.digests();
    println!("example.com => {:?}", c);
}
