/// Error type used to convey that a value is outside of a range that it must fall inside
#[derive(Debug)]
pub struct OutOfRangeData<T> {
    pub range: std::ops::RangeInclusive<T>,
    pub value: T,
}

/// Error type returned when preconditions of this API are broken
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("CapacityNotPowerOfTwo {0}")]
    CapacityNotPowerOfTwo(u32),

    #[error("CapacityOutOfRange {0:?}")]
    CapacityOutOfRange(OutOfRangeData<u32>),

    #[error("{0}")]
    String(String),

    #[error(transparent)]
    LibLoading(#[from] libloading::Error),

    #[error(transparent)]
    WindowsCore(#[from] windows::core::Error),

    #[error(transparent)]
    FromUtf16Error(#[from] std::string::FromUtf16Error),

    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),

    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Infallible(#[from] std::convert::Infallible),

    #[error("Session shutting down")]
    ShuttingDown,
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

impl From<Box<dyn std::error::Error>> for Error {
    fn from(value: Box<dyn std::error::Error>) -> Self {
        Error::String(value.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Io(io) => io,
            _ => std::io::Error::new(std::io::ErrorKind::Other, value),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
