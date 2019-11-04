# iocutil

IoC utility for malware researcher

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
