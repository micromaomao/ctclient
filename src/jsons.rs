//! Structs for parsing server response.

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct STH {
  pub tree_size: u64,
  pub timestamp: u64,
  pub sha256_root_hash: String,
  pub tree_head_signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConsistencyProof {
  pub consistency: Vec<String>,
}
