use ctclient::CTClient;
use env_logger;
use log::error;
mod utils;
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
			if size == 0 {
				client = match CTClient::new_from_latest_th("https://ct.googleapis.com/logs/argon2019/", &utils::hex_to_u8("3059301306072a8648ce3d020106082a8648ce3d030107034200042373109be1f35ef6986b6995961078ce49dbb404fc712c5a92606825c04a1aa1b0612d1b8714a9baf00133591d0530e94215e755d72af8b4a2ba45c946918756")) {
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
	loop {
		let bytes = client.as_bytes().unwrap();
		save_file.seek(SeekFrom::Start(0)).unwrap();
		save_file.write_all(&bytes).unwrap();
		save_file.seek(SeekFrom::Start(0)).unwrap();
		save_file.set_len(bytes.len() as u64).unwrap();
		if let Err(e) = client.update() {
			eprintln!("Update error: {}", &e);
		}
		std::thread::yield_now();
	}
}
