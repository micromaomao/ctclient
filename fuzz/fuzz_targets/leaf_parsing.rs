#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ctclient;

fuzz_target!(|data: &[u8]| {
	let _ = ctclient::internal::Leaf::from_raw(data, include_bytes!("./extra.precert"));
	let _ = ctclient::internal::Leaf::from_raw(data, include_bytes!("./extra.x509leaf"));
});
