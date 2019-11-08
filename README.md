# iocutil.rs

IoC utilities for malware researchers

## usage

add trailing config into `[dependencies]` your `Cargo.toml`

```toml
iocutil="0.1.0"
```

and import in your Rust code

```rust
use iocutil::prelude::*;
```

## what does it do?

### hash manipulation

#### calc

```rust
let c = ContentHash::of_file(r"C:\Windows\notepad.exe").unwrap();

println!("sha256: {}\nsha1: {}\nmd5: {}", c.sha256, c.sha1, c.md5);
```

#### retrieve

```rust
let hashes: Vec<_> = SampleHash::scrape(
    "https://www.malware-traffic-analysis.net/2019/05/20/index.html"
    ).unwrap();

hashes
    .into_iter()
    .for_each(|x| println!("{}", x));
```

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
