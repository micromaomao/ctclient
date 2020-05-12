use ctclient::CTClient;
use log::info;
use ctclient::utils;
use std::fs;
use std::env;
use std::process::exit;
use std::io::{Read, Write, SeekFrom, Seek};

fn main () {
	env_logger::init();

	if env::args().len() != 2 {
		eprintln!("Usage: ctclient <save-file>");
		exit(1);
	}
	let save_path = env::args().nth(1).unwrap();
	let mut save_file = match fs::OpenOptions::new().create(true).read(true).write(true).open(&save_path) {
		Ok(f) => f,
		Err(e) => {
			eprintln!("Can't open save file: {}", &e);
			exit(1);
		}
	};
	let mut save_read = Vec::new();
	let mut client;
	match save_file.read_to_end(&mut save_read) {
		Ok(size) => {
			let public_key = base64::decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==").unwrap();
			if size == 0 {
				client = match CTClient::new_from_latest_th("https://ct.googleapis.com/logs/argon2020/", &public_key) {
					Ok(k) => k,
					Err(e) => {
						eprintln!("{}", &e);
						exit(1);
					}
				};
			} else {
				client = match CTClient::from_bytes(&save_read) {
					Ok(k) => k,
					Err(e) => {
						eprintln!("Invalid save: {}", &e);
						exit(1);
					}
				}
			}
		},
		Err(e) => {
			eprintln!("Can't read file: {}", &e);
			exit(1);
		}
	}
	let mut last_tsize;
	{
		let th = client.get_checked_tree_head();
		info!("Current tree head: {} (size = {})", utils::u8_to_hex(&th.1), th.0);
		last_tsize = th.0;
	}
	loop {
		if let Err(e) = client.update() {
			eprintln!("Update error: {}", &e);
		}
		let bytes = client.as_bytes().unwrap();
		save_file.seek(SeekFrom::Start(0)).unwrap();
		save_file.write_all(&bytes).unwrap();
		save_file.seek(SeekFrom::Start(0)).unwrap();
		save_file.set_len(bytes.len() as u64).unwrap();
		let now_th = client.get_checked_tree_head().0;
		if now_th == last_tsize {
			std::thread::sleep(std::time::Duration::from_secs(10));
		} else {
      last_tsize = now_th;
		}
	}
}
