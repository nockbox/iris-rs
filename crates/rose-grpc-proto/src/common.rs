use thiserror::Error;

/// Helper trait for extracting required fields from protobuf-generated types.
pub trait Required<T> {
    fn required(self, kind: &'static str, field: &'static str) -> Result<T, ConversionError>;
}

impl<T> Required<T> for Option<T> {
    fn required(self, kind: &'static str, field: &'static str) -> Result<T, ConversionError> {
        self.ok_or(ConversionError::MissingField(kind, field))
    }
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("{0} is missing field: {1}")]
    MissingField(&'static str, &'static str),
    #[error("Invalid value: {0}")]
    Invalid(&'static str),
    #[error("Conversion error: {0}")]
    Other(&'static str),
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
}
