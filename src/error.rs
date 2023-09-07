/// Error type used to convey that a value is outside of a range that it must fall inside
#[derive(Debug)]
pub struct OutOfRangeData<T> {
    pub range: std::ops::RangeInclusive<T>,
    pub value: T,
}

/// Error type returned when preconditions of this API are broken
#[derive(Debug)]
pub enum Error {
    CapacityNotPowerOfTwo(u32),
    CapacityOutOfRange(OutOfRangeData<u32>),
    SysError(String),
    LibLoading(libloading::Error),
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::SysError(value)
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Error::SysError(value.to_string())
    }
}

impl From<libloading::Error> for Error {
    fn from(value: libloading::Error) -> Self {
        Error::LibLoading(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::CapacityOutOfRange(data) => write!(
                f,
                "Capacity {} out of range. Must be within {}..={}",
                data.value,
                data.range.start(),
                data.range.end()
            ),
            Error::CapacityNotPowerOfTwo(cap) => {
                write!(f, "Capacity {} is not a power of two", cap)
            }
            Error::SysError(msg) => write!(f, "System error: {}", msg),
            Error::LibLoading(err) => write!(f, "Library loading error: {}", err),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;
