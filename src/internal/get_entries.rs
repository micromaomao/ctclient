use std::convert::TryFrom;
use std::ops::Range;

use crate::Error;
use crate::jsons;

use super::get_json;
use super::Leaf;

/// An iterator over `Result<Leaf, Error>`.
///
/// After the first Err result, the iterator will not produce anything else.
pub struct GetEntriesIter<'a> {
  requested_range: Range<u64>,
  done: bool,
  last_gotten_entries: (Range<u64>, Vec<Option<jsons::LeafEntry>>),
  next_index: u64,
  batch_size: u64,

  client: &'a reqwest::blocking::Client,
  base_url: &'a reqwest::Url,
}

impl<'a> GetEntriesIter<'a> {
  fn new(range: std::ops::Range<u64>, client: &'a reqwest::blocking::Client, base_url: &'a reqwest::Url) -> Self {
    Self{
      last_gotten_entries: (range.start..range.start, Vec::new()),
      next_index: range.start,
      requested_range: range,
      done: false,
      batch_size: 500,

      client, base_url
    }
  }
}

impl<'a> Iterator for GetEntriesIter<'a> {
  type Item = Result<Leaf, Error>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    if self.next_index >= self.requested_range.end {
      self.done = true;
      return None;
    }
    let (ref mut last_gotten_range, ref mut last_gotten_entries) = self.last_gotten_entries;
    assert!(self.next_index >= last_gotten_range.start);
    assert!(self.next_index <= last_gotten_range.end);
    if self.next_index == last_gotten_range.end {
      assert!(self.requested_range.end > last_gotten_range.end); // The case where there's no more to be fetched is checked at the beginning of this function.
      let mut next_sub_range = last_gotten_range.end..u64::min(last_gotten_range.end + self.batch_size, self.requested_range.end);
      let try_next_entries = get_json(self.client, self.base_url, &format!("ct/v1/get-entries?start={}&end={}", next_sub_range.start, next_sub_range.end - 1)).map(|x: jsons::GetEntries| x.entries);
      if let Ok(next_entries) = try_next_entries {
        next_sub_range.end = next_sub_range.start + next_entries.len() as u64;
        if next_entries.is_empty() {
          self.last_gotten_entries = (next_sub_range, Vec::new());
          self.done = true;
          None
        } else {
          self.last_gotten_entries = (next_sub_range, next_entries.into_iter().map(Some).collect());
          self.next_index += 1;
          let leaf_entry = self.last_gotten_entries.1[0].take().unwrap();
          match Leaf::try_from(&leaf_entry) {
            Ok(leaf) => {
              Some(Ok(leaf))
            },
            Err(e) => {
              self.done = true;
              Some(Err(e))
            }
          }
        }
      } else {
        let err = try_next_entries.unwrap_err();
        self.done = true;
        Some(Err(err))
      }
    } else {
      assert_eq!(last_gotten_entries.len() as u64, last_gotten_range.end - last_gotten_range.start);
      let leaf_entry = last_gotten_entries[(self.next_index - last_gotten_range.start) as usize].take().unwrap();
      self.next_index += 1;
      match Leaf::try_from(&leaf_entry) {
        Ok(leaf) => {
          Some(Ok(leaf))
        },
        Err(e) => {
          self.done = true;
          Some(Err(e))
        }
      }
    }
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    if self.done {
      return (0, Some(0));
    }
    let rem_size = self.requested_range.end - self.next_index;
    if rem_size >= 1 {
      (1, Some(rem_size as usize))
    } else {
      (0, Some(0))
    }
  }
}

/// Request leaf entries from the CT log. Does not verify if these entries are
/// consistent with the tree or anything like that. Returns an iterator over the
/// leaves.
///
/// After the first Err result, the iterator will not produce anything else.
///
/// Uses `O(1)` memory itself.
pub fn get_entries<'a>(client: &'a reqwest::blocking::Client, base_url: &'a reqwest::Url, range: Range<u64>) -> GetEntriesIter<'a> {
  GetEntriesIter::new(range, client, base_url)
}
