use crate::Error;
use crate::internal::new_http_client;

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
struct ResponseJSON {
  operators: Vec<OperatorJSON>
}

#[derive(Debug, Deserialize, Clone)]
struct OperatorJSON {
  name: String,
  email: Vec<String>,
  logs: Vec<LogJson>
}

#[derive(Debug, Deserialize, Clone)]
struct LogJson {
  key: String,
  log_id: String,
  mmd: u64,
  url: String
}

#[derive(Debug, Clone)]
pub struct LogList {
  pub map_id_to_log: HashMap<Vec<u8>, Log>
}

#[derive(Debug, Clone)]
pub struct Log {
  pub pub_key: Vec<u8>,
  pub base_url: String
}

impl LogList {
  pub fn get() -> Result<LogList, Error> {
    let client = new_http_client()?;
    let json: ResponseJSON = client.get("https://www.gstatic.com/ct/log_list/v2/log_list.json").send().map_err(|e| Error::NetIO(e))?
        .json().map_err(|e| Error::MalformedResponseBody(format!("{}", e)))?;
    let mut hm: HashMap<Vec<u8>, Log> = HashMap::with_capacity(
      json.operators.iter().map(|x| x.logs.len()).sum()
    );
    fn b64_dec_err(e: base64::DecodeError) -> Error {
      Error::MalformedResponseBody(format!("Unable to decode base64: {}", e))
    }
    for op in json.operators.iter() {
      for log in op.logs.iter() {
        let log_id = base64::decode(&log.log_id).map_err(b64_dec_err)?;
        let pub_key = base64::decode(&log.key).map_err(b64_dec_err)?;
        let base_url = log.url.to_owned();
        if hm.contains_key(&log_id) {
          return Err(Error::MalformedResponseBody("Multiple logs returned with the same id.".to_owned()));
        }
        hm.insert(log_id, Log {
          pub_key, base_url
        });
      }
    }

    Ok(LogList {
      map_id_to_log: hm
    })
  }

  pub fn find_by_id(&self, id: &[u8]) -> Option<&Log> {
    self.map_id_to_log.get(id)
  }
}

#[test]
fn test() {
  let ll = LogList::get().unwrap();
  let nb_logs = ll.map_id_to_log.len();
  assert!(nb_logs > 0);
  assert_eq!(ll.find_by_id(&base64::decode("sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=").unwrap()).unwrap().base_url, "https://ct.googleapis.com/logs/argon2020/");
}
