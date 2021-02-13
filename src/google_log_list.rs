//! Downloading of log list from Google.

use crate::Error;
use crate::internal::new_http_client;

use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryInto;

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
  url: String,
  state: HashMap<String, serde_json::Value>,
  description: String
}

/// A downloaded log list.
#[derive(Debug, Clone)]
pub struct LogList {
  pub map_id_to_log: HashMap<[u8; 32], Log>
}

/// A log in [`LogList`].
#[derive(Debug, Clone)]
pub struct Log {
  pub pub_key: Vec<u8>,
  pub base_url: String,
  pub state: LogState,
  pub description: String
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum LogState {
  Pending,
  Qualified,
  Usable,
  Readonly,
  Retired,
  Rejected
}

impl LogList {
  /// Download the log list at runtime from [`https://www.gstatic.com/ct/log_list/v2/log_list.json`](https://www.gstatic.com/ct/log_list/v2/log_list.json).
  pub fn get() -> Result<LogList, Error> {
    LogList::get_with_url("https://www.gstatic.com/ct/log_list/v2/log_list.json")
  }

  /// Download the log list at runtime.
  pub fn get_with_url(url: &str) -> Result<LogList, Error> {
    let client = new_http_client()?;
    let json: ResponseJSON = client.get(url).send().map_err(|e| Error::NetIO(e))?
        .json().map_err(|e| Error::MalformedResponseBody(format!("{}", e)))?;
    let mut hm: HashMap<[u8; 32], Log> = HashMap::with_capacity(
      json.operators.iter().map(|x| x.logs.len()).sum()
    );
    fn b64_dec_err(e: base64::DecodeError) -> Error {
      Error::MalformedResponseBody(format!("Unable to decode base64: {}", e))
    }
    for op in json.operators.iter() {
      for log in op.logs.iter() {
        let log_id = base64::decode(&log.log_id).map_err(b64_dec_err)?;
        if log_id.len() != 32 {
          return Err(Error::MalformedResponseBody(format!("Invalid log_id length: {}", log_id.len())));
        }
        let log_id: [u8; 32] = log_id[..].try_into().unwrap();
        let pub_key = base64::decode(&log.key).map_err(b64_dec_err)?;
        let base_url = log.url.to_owned();
        if hm.contains_key(&log_id) {
          return Err(Error::MalformedResponseBody("Multiple logs returned with the same id.".to_owned()));
        }
        let state_keys: Vec<&str> = log.state.keys().map(|x| &x[..]).collect();
        use LogState::*;
        let log_state = match &state_keys[..] {
          ["pending"] => Pending,
          ["qualified"] => Qualified,
          ["usable"] => Usable,
          ["readonly"] => Readonly,
          ["retired"] => Retired,
          ["rejected"] => Rejected,
          _ => return Err(Error::MalformedResponseBody(format!("Invalid log state object: {:?}", &log.state)))
        };
        hm.insert(log_id, Log {
          pub_key, base_url, state: log_state, description: log.description.clone()
        });
      }
    }

    Ok(LogList {
      map_id_to_log: hm
    })
  }

  /// Lookup a [`Log`] by its 32-byte `log_id`.
  pub fn find_by_id<'a, 'b>(&'a self, id: &'b [u8; 32]) -> Option<&'a Log> {
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
