use iocutil::prelude::*;

fn main() {
    let hashes: Vec<_> =
        SampleHash::scrape("https://www.malware-traffic-analysis.net/2019/05/20/index.html")
            .unwrap();

    hashes.into_iter().for_each(|x| println!("{}", x));
}
