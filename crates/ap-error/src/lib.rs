//! Error handling utilities for access-protocol.
//!
//! Re-exports the `ap_error` proc macro and provides the `FlatError` trait.

pub mod flat_error;

pub use ap_error_macro::ap_error;
