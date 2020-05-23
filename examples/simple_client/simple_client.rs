use ctclient::CTClient;
use log::{info, LevelFilter};
use ctclient::utils;
use std::env;
use std::process::exit;
use rusqlite::{Connection, OptionalExtension, NO_PARAMS};
use std::convert::{TryInto, TryFrom};
use rusqlite::types::Value;
use openssl::x509::X509;
use ctclient::certutils::get_dns_names;

fn main () {
  env_logger::builder().filter_module(env!("CARGO_PKG_NAME"), LevelFilter::Info).init();

  if env::args_os().len() != 2 {
    eprintln!("Usage: ctclient <save-db>");
    exit(1);
  }
  let save_path = env::args_os().nth(1).unwrap();
  let save_db = match Connection::open(&save_path) {
    Ok(f) => f,
    Err(e) => {
      eprintln!("Can't open save db: {}", &e);
      exit(1);
    }
  };
  if save_db.query_row("SELECT null FROM sqlite_master WHERE name = 'ctlogs'", NO_PARAMS, |_| {Ok(())}).optional().unwrap() == None {
    save_db.execute_batch(include_str!("save_db_init.sql")).expect("Can't run init.sql");
  }
  let (url, pub_key, init_tree_size, init_tree_hash) = save_db.query_row("SELECT url, pub_key, checked_tree_size, checked_tree_head FROM ctlogs", NO_PARAMS, |row| {
    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, u64::try_from(row.get_raw(2).as_i64()?).expect("negative tree size?"), row.get::<_, Vec<u8>>(3)?))
  }).unwrap();
  let mut client = if init_tree_size == 0 && init_tree_hash == [0u8; 32] {
    CTClient::new_from_latest_th(&url, &pub_key).unwrap()
  } else {
    CTClient::new_from_perv_tree_hash(&url, &pub_key, init_tree_hash[..].try_into().unwrap(), init_tree_size).unwrap()
  };
  let mut last_thash: [u8; 32] = init_tree_hash[..].try_into().unwrap();
  loop {
    let sthresult = client.update(Some(|certs: &[X509]| {
      let head = &certs[0];
      let mut dns_names = match get_dns_names(head) {
        Ok(d) => d,
        Err(e) => {
          eprintln!("Error getting dns names from certificate: {}", e);
          return;
        }
      };
      dns_names.sort_unstable();
      dns_names.dedup_by(|a, b| a.eq_ignore_ascii_case(&b));
      for n in dns_names.iter_mut() {
        *n = n.to_ascii_lowercase();
        if n.ends_with(".merkleforest.xyz") || n == "merkleforest.xyz" {
          save_db.execute(r#"INSERT INTO "found_my_certs" (log_id, x509_der, ca_der) VALUES (0, ?, ?);"#, &[
            Value::Blob(head.to_der().unwrap()),
            Value::Blob(certs[1].to_der().unwrap())
          ]).expect("Unable to record cert");
          println!("Found cert with the following dns names: {}", dns_names.join(", "));
          break;
        }
      }
    }));
    if let Some(sth) = sthresult.tree_head() {
      save_db.execute(r#"INSERT INTO "received_signed_tree_heads" (log_id, tree_size, "timestamp", tree_hash, signature) VALUES (0, ?, ?, ?, ?)"#, &[
        Value::Integer(sth.tree_size.try_into().unwrap()), Value::Integer(sth.timestamp.try_into().unwrap()),
        Value::Blob(sth.root_hash.to_vec()), Value::Blob(sth.signature.to_vec())
      ]).expect("Failed to insert");
    }
    if sthresult.is_err() {
      eprintln!("Update error: {}", &sthresult.unwrap_err());
    } else {
      let th = sthresult.tree_head().unwrap();
      let new_thash = th.root_hash;
      if new_thash == last_thash {
        info!("Stayed the same.");
        std::thread::sleep(std::time::Duration::from_secs(10));
      } else {
        info!("Updated to {} {}", th.tree_size, &utils::u8_to_hex(&th.root_hash));
        last_thash = new_thash;
        save_db.execute(r#"UPDATE ctlogs SET checked_tree_size = ?, checked_tree_head = ? WHERE url = ?"#, &[
          Value::Integer(th.tree_size.try_into().unwrap()), Value::Blob(th.root_hash.to_vec()),
          Value::Text(url.clone())
        ]).expect("Failed to update state");
      }
    }
  }
}
