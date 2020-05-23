fn main() {
  let openssl_version = unsafe { openssl_sys::OpenSSL_version_num() };
  if openssl_version < 0x010100000 {
    eprintln!("This crate must be linked with OpenSSL version >= 1.1.0.");
    std::process::exit(1);
  }
}
