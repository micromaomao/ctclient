//! Some utility functions.

pub use openssl::sha::sha256;

#[test]
fn sha256_test() {
  assert_eq!(u8_to_hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert_eq!(u8_to_hex(&sha256(b"hello")), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

/// Convert a hex string with no whitespace or other sepreator into `&[u8]`.
///
/// # Example:
/// ```rust
/// # use ctclient::utils::hex_to_u8;
/// assert_eq!(&hex_to_u8("aabb"), b"\xaa\xbb");
/// ```
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

/// Convert a `&[u8]` byte array to a lower-case, no-sepreator hex string.
///
/// # Example:
/// ```rust
/// # use ctclient::utils::u8_to_hex;
/// assert_eq!(&u8_to_hex(b"\xaa\xbb"), "aabb");
/// ```
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
  assert_eq!(hex_to_u8("DEADBEEF"), vec![0xde, 0xad, 0xbe, 0xef]);
}
#[test]
fn u8_to_hex_test() {
  assert_eq!(u8_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
  assert_eq!(u8_to_hex(&[0x01, 0x02, 0x03, 0x04]), "01020304");
}

/// Calculate `sha256(0x01 || left || right)`
pub fn combine_tree_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
  let mut buf = Vec::new();
  buf.reserve(32 + 32 + 1);
  buf.push(1);
  buf.extend_from_slice(left);
  buf.extend_from_slice(right);
  sha256(&buf[..])
}

/// For a tree of size `n`, return the size of the left branch of the root.
pub fn largest_power_of_2_smaller_than(mut n: u64) -> u64 {
  if n <= 1 {
    return 0;
  }
  if n == 2 {
    return 1;
  }
  n -= 1;
  // I'm sure the compiler can optimize this nicely.
  let mut pow: u64 = 1;
  loop {
    n /= 2;
    pow *= 2;
    if n == 1 {
      return pow;
    }
  }
}

#[test]
fn test_largest_power_of_2_smaller_than() {
  assert_eq!(largest_power_of_2_smaller_than(0), 0);
  assert_eq!(largest_power_of_2_smaller_than(1), 0);
  assert_eq!(largest_power_of_2_smaller_than(2), 1);
  assert_eq!(largest_power_of_2_smaller_than(3), 2);
  assert_eq!(largest_power_of_2_smaller_than(4), 2);
  assert_eq!(largest_power_of_2_smaller_than(5), 4);
  assert_eq!(largest_power_of_2_smaller_than(6), 4);
  assert_eq!(largest_power_of_2_smaller_than(7), 4);
  assert_eq!(largest_power_of_2_smaller_than(8), 4);
  assert_eq!(largest_power_of_2_smaller_than(9), 8);

  assert_eq!(largest_power_of_2_smaller_than(1u64<<33u64), 1u64<<32u64);
  assert_eq!(largest_power_of_2_smaller_than((1u64<<34u64) - 100u64), 1u64<<33u64);
}
