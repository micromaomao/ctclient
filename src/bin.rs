use ctclient::CTClient;
use env_logger;
use log::error;
mod utils;

fn main () {
	env_logger::init();

	let jha = std::thread::spawn(move || {
		// let mut ctclient = CTClient::new_from_latest_th("https://ct.googleapis.com/logs/argon2019/", &utils::hex_to_u8("3059301306072a8648ce3d020106082a8648ce3d030107034200042373109be1f35ef6986b6995961078ce49dbb404fc712c5a92606825c04a1aa1b0612d1b8714a9baf00133591d0530e94215e755d72af8b4a2ba45c946918756")[..]).unwrap();
		let mut ctclient = CTClient::new_from_perv_tree_hash("https://ct.googleapis.com/logs/argon2019/", &utils::hex_to_u8("3059301306072a8648ce3d020106082a8648ce3d030107034200042373109be1f35ef6986b6995961078ce49dbb404fc712c5a92606825c04a1aa1b0612d1b8714a9baf00133591d0530e94215e755d72af8b4a2ba45c946918756")[..],
					unsafe {*(&utils::hex_to_u8("fdf3566cd40781902680028149efc2bb691fdff9db1b86ca0e5b23e9ef0e803f")[..] as *const [u8] as *const [u8; 32])}, 654434065u64).unwrap();
		loop {
			if let Err(e) = ctclient.update() {
				error!("google ct update error: {}; ignoring.", &e);
			}
			std::thread::sleep(std::time::Duration::from_secs(1));
		}
	});

	// let jhb = std::thread::spawn(move || {
	// 	let mut ctclient = CTClient::new_from_latest_th("https://ct.cloudflare.com/logs/nimbus2019/", &utils::hex_to_u8("3059301306072a8648ce3d020106082a8648ce3d030107034200049191f3d6fe6bf1af4b99748c7a0619020e145be520e7a1ad35f2530cd159bae6c42588167f815c0b90fe664630b6d5d30d2a383a46a71bd6f7008e2cc08436f2")[..]).unwrap();
	// 	loop {
	// 		if let Err(e) = ctclient.update() {
	// 			error!("cloudflare ct update error: {}; ignoring.", &e);
	// 		}
	// 		std::thread::sleep(std::time::Duration::from_secs(1));
	// 	}
	// });

	jha.join().unwrap();
	// jhb.join();
}
