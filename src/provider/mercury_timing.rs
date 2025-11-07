//! Timing infrastructure for Mercury performance analysis
//!
//! This module provides instrumentation to measure the performance of various
//! operations in the Mercury polynomial commitment scheme.
//!
//! Enable with the `mercury-timing` feature flag.

#![allow(dead_code)]

use std::sync::Mutex;
use std::time::Instant;

/// Global timing data collection
static TIMING_DATA: Mutex<Option<TimingCollector>> = Mutex::new(None);

/// Represents a single timing measurement
#[derive(Debug, Clone)]
pub struct TimingEntry {
  /// Name/identifier of the section being timed
  pub section: String,
  /// Duration in microseconds
  pub duration_us: u64,
  /// Timestamp relative to timing initialization in microseconds
  pub timestamp: u64,
}

/// Collects timing measurements
#[derive(Debug)]
pub struct TimingCollector {
  entries: Vec<TimingEntry>,
  start_time: Instant,
}

impl TimingCollector {
  fn new() -> Self {
    Self {
      entries: Vec::new(),
      start_time: Instant::now(),
    }
  }

  fn record(&mut self, section: String, duration_us: u64) {
    let timestamp = self.start_time.elapsed().as_micros() as u64;
    self.entries.push(TimingEntry {
      section,
      duration_us,
      timestamp,
    });
  }

  fn get_entries(&self) -> Vec<TimingEntry> {
    self.entries.clone()
  }

  fn clear(&mut self) {
    self.entries.clear();
  }
}

/// Initialize the timing collector
pub fn init_timing() {
  let mut data = TIMING_DATA.lock().unwrap();
  *data = Some(TimingCollector::new());
}

/// Record a timing entry
pub fn record_timing(section: &str, duration_us: u64) {
  if let Ok(mut data) = TIMING_DATA.lock() {
    if let Some(collector) = data.as_mut() {
      collector.record(section.to_string(), duration_us);
    }
  }
}

/// Get all timing entries
pub fn get_timing_entries() -> Vec<TimingEntry> {
  if let Ok(data) = TIMING_DATA.lock() {
    if let Some(collector) = data.as_ref() {
      return collector.get_entries();
    }
  }
  Vec::new()
}

/// Clear all timing data
pub fn clear_timing() {
  if let Ok(mut data) = TIMING_DATA.lock() {
    if let Some(collector) = data.as_mut() {
      collector.clear();
    }
  }
}

/// Output timing data as JSON
pub fn output_timing_json() -> String {
  let entries = get_timing_entries();
  let mut json = String::from("{\n  \"timings\": [\n");
  
  for (i, entry) in entries.iter().enumerate() {
    json.push_str(&format!(
      "    {{\n      \"section\": \"{}\",\n      \"duration_us\": {},\n      \"timestamp\": {}\n    }}",
      entry.section, entry.duration_us, entry.timestamp
    ));
    if i < entries.len() - 1 {
      json.push_str(",\n");
    } else {
      json.push_str("\n");
    }
  }
  
  json.push_str("  ]\n}");
  json
}

/// RAII guard for timing a section
pub struct TimingGuard {
  section: String,
  start: Instant,
}

impl TimingGuard {
  /// Create a new timing guard for the given section
  pub fn new(section: &str) -> Self {
    Self {
      section: section.to_string(),
      start: Instant::now(),
    }
  }
}

impl Drop for TimingGuard {
  fn drop(&mut self) {
    let duration_us = self.start.elapsed().as_micros() as u64;
    record_timing(&self.section, duration_us);
  }
}

/// Macro to time a section of code
#[macro_export]
macro_rules! time_section {
  ($section:expr, $code:block) => {{
    #[cfg(feature = "mercury-timing")]
    {
      let _guard = $crate::provider::mercury_timing::TimingGuard::new($section);
      $code
    }
    #[cfg(not(feature = "mercury-timing"))]
    {
      $code
    }
  }};
}

/// Macro to conditionally execute timing code
#[macro_export]
macro_rules! if_timing {
  ($code:block) => {{
    #[cfg(feature = "mercury-timing")]
    {
      $code
    }
  }};
}
