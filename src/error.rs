use std::fmt::Display;

pub type WintunError = Box<dyn std::error::Error>;

#[derive(Debug)]
pub struct OutOfRangeData<T> {
    pub(crate) range: std::ops::RangeInclusive<T>,
    pub(crate) value: T,
}

#[derive(Debug)]
pub enum ApiError {
    CapacityNotPowerOfTwo(u32),
    CapacityOutOfRange(OutOfRangeData<u32>),
}

impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ApiError::CapacityOutOfRange(data) => write!(
                f,
                "Capacity {} out of range. Must be within {}..={}",
                data.value, data.range.start(), data.range.end()
            ),
            ApiError::CapacityNotPowerOfTwo(cap) => {
                write!(f, "Capacity {} is not a power of two", cap)
            }
        }
    }
}

impl std::error::Error for ApiError {}
