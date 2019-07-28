/*
//! Certificate Transparency stuff with some detailed explanation.

// First, serveral utility functions

mod utils;
use utils::{hex_to_u8, sha256, u8_to_hex, combine_tree_hash, largest_power_of_2_smaller_than};

// Consistency proof

fn main() {
	use std::env;
	use std::str::FromStr;
	let args: Vec<String> = env::args().skip(1).collect();
	assert_eq!(args.len(), 4);
	let perv_size = u64::from_str(&args[0]).unwrap();
	let curr_size = u64::from_str(&args[1]).unwrap();
	let perv_root = hex_to_u8(&args[2]);
	let curr_root = hex_to_u8(&args[3]);
	assert_eq!(perv_root.len(), 32);
	assert_eq!(curr_root.len(), 32);
	let perv_root = unsafe { *(&perv_root[..] as *const [u8] as *const [u8; 32]) };
	let curr_root = unsafe { *(&curr_root[..] as *const [u8] as *const [u8; 32]) };
	use std::io;
	use std::io::Read;
	let mut stdin = io::stdin();
	let mut read_buf = String::new();
	stdin.read_to_string(&mut read_buf).unwrap();
	let srv_proof: Vec<Vec<u8>> = read_buf.lines().filter(|l| *l != "").map(|l| hex_to_u8(l)).collect();
	if let Err(verify_err) = check_consistency_proof(perv_size, curr_size, &srv_proof.iter().map(|arr| {
		assert_eq!(arr.len(), 32);
		unsafe { *(&arr[..] as *const [u8] as *const [u8; 32]) }
	}).collect(), &perv_root, &curr_root) {
		eprintln!("unable to verify: {}", verify_err);
		std::process::exit(1);
	}
	println!("verified: {} + proof => {}", u8_to_hex(&perv_root), u8_to_hex(&curr_root));
}

*/
