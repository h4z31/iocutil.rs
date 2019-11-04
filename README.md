# iocutil

IoC utility for malware researchers

## What does it do?

* utility for hash values
    * highly easy manipulatable format(`SampleHash`)
        * compatible with `AsRef<str>` functions
        * case-insensitive equivalence (save hashes as lowercase)
    * hash validation(md5/sha1/sha256)
    * uniquify hashes 
    * scrape hashes from web page
        * with less noise (it targets texts only `article` (or `body` if `artcile` not found))
    * find hashes in text
    
* api client for some intelligence services
    * VirusTotal
    * VirusBay
    * AlienVault OTX

## usage

add trailing config into your `Cargo.toml`

```toml
iocutil = {version="0.1", git="https://github.com/0x75960/iocutil.rs"}
```

and use in your code like...

```rust
use iocutil::prelude::*;

let h = SampleHash::scrape(
    "https://www.malware-traffic-analysis.net/2019/05/20/index.html"
    ).expect("failed to retrieve hashes")?;

let vtclient = VirusTotalClient::default();

let frs = vtclient.batch_query(h);

frs.into_iter().flat_map(|x| x).for_each(|x| println!("{}", x.positives));
```

## future work

* add api clients for 
    * reverse.it
    
* documentation
