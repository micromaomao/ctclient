use std::process::exit;
use std::time::{Duration, SystemTime};

use openssl::x509::X509;

use ctclient::CTClient;
use ctclient::google_log_list::LogList;
use ctclient::utils::u8_to_hex;
use ctclient::internal::get_entries;

fn main() {
  env_logger::init();

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
  let sct_list = ctclient::SignedCertificateTimestamp::from_cert_sct_extension(chain[0].as_ref(), chain[1].as_ref()).expect("Unable to parse sct list");
  if sct_list.is_empty() {
    println!("Did not found any SCTs in the certificate.");
    exit(0);
  }
  let ll = LogList::get().expect("Unable to fetch log list from Google.");
  for (i, sct) in sct_list.iter().enumerate() {
    println!("SCT {}:", i + 1);
    let log_id_b64 = base64::encode(&sct.log_id);
    println!("  log_id = {}", log_id_b64);
    let timestamp = sct.timestamp;
    let time = SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(timestamp)).unwrap();
    println!("  timestamp = {} ({} days ago)", timestamp, (time.elapsed().unwrap().as_secs_f32() / 60f32 / 60f32 / 24f32).round());
    let leaf_hash = sct.derive_leaf_hash();
    println!("  calculated leaf hash: {}", u8_to_hex(&leaf_hash));
    let log = ll.find_by_id(&sct.log_id);
    if let Some(log) = log {
      println!("  log is {}", log.base_url);
      if let Err(e) = sct.verify(&openssl::pkey::PKey::public_key_from_der(&log.pub_key).unwrap()) {
        println!("  Error: unable to verify SCT signature: {}", e);
      }
      let lc = CTClient::new_from_latest_th(&log.base_url, &log.pub_key);
      if lc.is_err() {
        println!("    unable to connect to log: {}", lc.unwrap_err());
        continue;
      }
      let lc = lc.unwrap();
      match lc.check_inclusion_proof_for_sct(&sct) {
        Ok(index) => {
          println!("    inclusion proof checked, leaf index is {}", index);
          for ent in get_entries(lc.get_reqwest_client(), lc.get_base_url(), index..(index+1)) {
            match ent {
              Err(e) => {
                println!("    unable to get entry: {}", e);
              },
              Ok(ent) => {
                if let Some(prec) = ent.x509_chain.first() {
                  println!("    precert: {}", base64::encode(prec));
                }
              }
            }
          }
        }
        Err(e) => {
          println!("    inclusion proof errored: {}", e);
        }
      }
    } else {
      println!("  log is not known.");
    }
    // todo: move the inclusion proof check code into CTClient?
  }
}
