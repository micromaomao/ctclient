use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct STH {
  pub tree_size: u64,
  pub timestamp: u64,
  pub sha256_root_hash: String,
  pub tree_head_signature: String,
}
