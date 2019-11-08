# iocutil.rs

IoC utilities for malware researchers

## usage

add trailing config into `[dependencies]` your `Cargo.toml`

```toml
iocutil="0.1"
```

and import in your Rust code

```rust
use iocutil::prelude::*;
```

## how it helps you?

### hash

#### manipulation

```rust
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
```

#### calculate hash

```rust
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
```

#### scrape from url

```rust
let hashes: Vec<_> = SampleHash::scrape(
    "https://www.malware-traffic-analysis.net/2019/05/20/index.html"
    ).unwrap();

hashes
    .into_iter()
    .for_each(|x| println!("{}", x));
```

* SampleHash::scrape targets only text in article elements (or body if not found)
    * less noise

### API Clients

#### VirusTotal

```rust
// read apikey from environment variable `$VTAPIKEY`
let client = VirusTotalClient::default();

// search new samples for recent one week(limit 300 samples)
// this requires private API. It consume a request per 300 hashes.
let samples: Vec<_> = client.search(
        fs!(at!(1, days ago) =>),
        Some(300)
    ).unwrap();

samples.into_iter().for_each(|x| println!("{}", x));

// or

let report = client
    .query_filereport(samples.first().unwrap())
    .unwrap();
```
other features:

* download file
* allinfo report
* etc.

#### AlienVault OTX

```rust
// read apikey from environment variable `$OTX_APIKEY`
let client = AlienVaultOTXClient::default();

let pulses: Vec<Pulse> = client.pulses_from(at!(1, weeks ago)).unwrap();

pulses
    .into_iter()
    .inspect(|x| println!("\n# {}\n", x.name))
    .map(|x| x.into())
    .flat_map(|x: Vec<SampleHash>| x)
    .for_each(|x: SampleHash| println!("* {}", x))
```
other features:

* query a hash indicator

## future work

* add api clients for reverse.it and so on
* support other IoCs (like IPs, URLs)

* documentation

## Author

* 0x75960 <0x75960@strelka.cc>
