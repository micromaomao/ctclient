#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ctclient;

fuzz_target!(|data: &[u8]| {
	let _ = ctclient::CTClient::from_bytes(data);
});
