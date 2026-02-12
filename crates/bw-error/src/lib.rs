//! Error handling utilities for bw_remote.
//!
//! Re-exports the `bw_error` proc macro and provides the `FlatError` trait.

pub mod flat_error;

pub use bw_error_macro::bw_error;
