//! FlatError trait for error variant identification.

/// Trait for errors that can report their variant name.
pub trait FlatError {
    /// Returns the name of the error variant as a static string.
    fn error_variant(&self) -> &'static str;
}
