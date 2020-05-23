use std::process::exit;
use std::time::{Duration, SystemTime};

use openssl::x509::X509;

use ctclient::internal::{construct_precert_leaf_hash, parse_certificate_sct_list, SCTInner};
use ctclient::utils::u8_to_hex;

fn main() {
  let args: Vec<_> = std::env::args_os().collect();
  if args.len() != 2 {
    eprintln!("Expected 1 argument: chain.pem");
    exit(1);
  }
  let pem_path = args.into_iter().nth(1).unwrap();
  let chain = X509::stack_from_pem(&std::fs::read(pem_path).expect("Unable to read pem")).expect("Unable to parse pem");
  if chain.len() < 2 {
    eprintln!("Expected at least 2 certs.");
    exit(1);
  }
  let sct_list = parse_certificate_sct_list(chain[0].as_ref(), chain[1].as_ref()).expect("Unable to parse sct list");
  if sct_list.is_empty() {
    println!("Did not found any SCTs in the certificate.");
    exit(0);
  }
  for (i, sct) in sct_list.iter().enumerate() {
    println!("SCT {}:", i + 1);
    let log_id_b64 = base64::encode(&sct.log_id);
    println!("  log_id = {}", log_id_b64);
    let timestamp = sct.timestamp;
    let time = SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(timestamp)).unwrap();
    println!("  timestamp = {} ({} days ago)", timestamp, (time.elapsed().unwrap().as_secs_f32() / 60f32 / 60f32 / 24f32).round());
    let leaf_hash = match &sct.entry {
      SCTInner::PreCert {tbs, issuer_key_hash} => {
        construct_precert_leaf_hash(&tbs[..], &issuer_key_hash[..], sct.timestamp, &sct.extensions_data)
      },
      _ => unimplemented!()
    };
    println!("  calculated leaf hash: {}", u8_to_hex(&leaf_hash));
  }
}
