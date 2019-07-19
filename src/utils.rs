pub use openssl::sha::sha256;

#[test]
fn sha256_test() {
	assert_eq!(u8_to_hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	assert_eq!(u8_to_hex(&sha256(b"hello")), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

pub fn hex_to_u8(hex: &str) -> Vec<u8> {
	if hex.len() % 2 != 0 {
		panic!("partial hex?");
	}
	let mut vec = Vec::new();
	vec.reserve(hex.len() / 2);
	for i in 0..(hex.len() / 2) {
		let hex = &hex[i*2..(i+1)*2];
		vec.push(u8::from_str_radix(hex, 16).unwrap());
	}
	vec
}

pub fn u8_to_hex(bytes: &[u8]) -> String {
	let mut buf = String::new();
	for i in bytes {
		buf.push_str(&format!("{:02x?}", i));
	}
	buf
}

#[test]
fn hex_to_u8_test() {
	assert_eq!(hex_to_u8("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
}
#[test]
fn u8_to_hex_test() {
	assert_eq!(u8_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
	assert_eq!(u8_to_hex(&[0x01, 0x02, 0x03, 0x04]), "01020304");
}
