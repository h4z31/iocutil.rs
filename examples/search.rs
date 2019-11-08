use iocutil::prelude::*;

fn main() {
	let client = VirusTotalClient::default();

	let query = format!(
		"{} AND {} AND submitter:JP", 
		p!(1 => 10),
		fs!(at!(1, weeks ago) =>)
	);
	
	let hashes: Vec<_> = client.search(query, Some(600));

	hashes
	    .into_iter()
	    .for_each(|x| println!("{}", x));
}