# iocutil

IoC utility

## usage

add trailing config into your `Cargo.toml`

```toml
iocutil = {version="0.1", git="https://github.com/0x75960/iocutil.rs"}
```

and use in your code like...

```rust
use iocutil::prelude::*;

let h = SampleHash::new("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?;
let vtclient = VirusTotalClient::default();
let fr = vtclient.query_filereport(h)?;

println!("{:?}", fr);
```
