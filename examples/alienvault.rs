use iocutil::prelude::*;

fn main() {
	// read apikey from environment variable `$OTX_APIKEY`
	let client = AlienVaultOTXClient::default();

	let pulses: Vec<Pulse> = client.pulses_from(at!(1, weeks ago)).unwrap();

	pulses
	    .into_iter()
	    .inspect(|x| println!("\n# {}\n", x.name))
	    .map(|x| x.into())
	    .flat_map(|x: Vec<SampleHash>| x)
	    .for_each(|x: SampleHash| println!("* {}", x))
}