use ctclient::CTClient;
mod utils;

fn main () {
	let ctclient = CTClient::new_from_latest_th("https://ct.googleapis.com/logs/argon2019/", &utils::hex_to_u8("3059301306072a8648ce3d020106082a8648ce3d030107034200042373109be1f35ef6986b6995961078ce49dbb404fc712c5a92606825c04a1aa1b0612d1b8714a9baf00133591d0530e94215e755d72af8b4a2ba45c946918756")[..]);
	println!("{:?}", &ctclient);
}
