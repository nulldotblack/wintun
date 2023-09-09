/// Error type used to convey that a value is outside of a range that it must fall inside
#[derive(Debug)]
pub struct OutOfRangeData<T> {
    pub range: std::ops::RangeInclusive<T>,
    pub value: T,
}

/// Error type returned when preconditions of this API are broken
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("std::io::Error {0}")]
    Io(#[from] std::io::Error),

    #[error("CapacityNotPowerOfTwo {0}")]
    CapacityNotPowerOfTwo(u32),

    #[error("CapacityOutOfRange {0:?}")]
    CapacityOutOfRange(OutOfRangeData<u32>),

    #[error("{0}")]
    String(String),

    #[error("libloading {0}")]
    LibLoading(#[from] libloading::Error),

    #[error("windows::core::Error {0}")]
    WindowsCore(#[from] windows::core::Error),
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::String(value)
    }
}

impl From<&String> for Error {
    fn from(value: &String) -> Self {
        Error::String(value.clone())
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Error::String(value.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
