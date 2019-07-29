#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ctclient;

fuzz_target!(|data: &[u8]| {
	let _ = ctclient::internal::Leaf::from_raw(include_bytes!("./le.precert"), data);
	let _ = ctclient::internal::Leaf::from_raw(include_bytes!("./le.x509leaf"), data);
});
