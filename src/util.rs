use std::{mem::MaybeUninit, ptr};
use widestring::U16Str;
use winapi::{
    shared::ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT},
    um::{errhandlingapi, winbase, winnt::MAKELANGID},
};

/// A wrapper struct that allows a type to be Send and Sync
#[derive(Copy, Clone, Debug)]
pub(crate) struct UnsafeHandle<T>(pub T);

/// We never read from the pointer. It only serves as a handle we pass to the kernel or C code that
/// doesn't have the same mutable aliasing restrictions we have in Rust
unsafe impl<T> Send for UnsafeHandle<T> {}
unsafe impl<T> Sync for UnsafeHandle<T> {}

/// Returns a a human readable error message from a windows error code
pub fn get_error_message(err_code: u32) -> String {
    const LEN: usize = 256;
    let mut buf = MaybeUninit::<[u16; LEN]>::uninit();

    //SAFETY: name is a allocated on the stack above therefore it must be valid, non-null and
    //aligned for u16
    let first = unsafe { *buf.as_mut_ptr() }.as_mut_ptr();
    //Write default null terminator in case WintunGetAdapterName leaves name unchanged
    unsafe { first.write(0u16) };
    let chars_written = unsafe {
        winbase::FormatMessageW(
            winbase::FORMAT_MESSAGE_FROM_SYSTEM | winbase::FORMAT_MESSAGE_IGNORE_INSERTS,
            ptr::null(),
            err_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as u32,
            first,
            LEN as u32,
            ptr::null_mut(),
        )
    };

    //SAFETY: first is a valid, non-null, aligned, pointer
    let first = unsafe { U16Str::from_ptr(first, chars_written as usize) }.to_string_lossy();
    format!("{} ({})", first, err_code)
}

pub(crate) fn get_last_error() -> String {
    let err_code = unsafe { errhandlingapi::GetLastError() };
    get_error_message(err_code)
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

/// Returns the major and minor version of the wintun driver
pub fn get_running_driver_version(wintun: &crate::Wintun) -> Result<Version, crate::Error> {
    let version = unsafe { wintun.WintunGetRunningDriverVersion() };
    if version == 0 {
        Err(crate::Error::SysError(get_last_error()))
    } else {
        let v = version.to_be_bytes();
        Ok(Version {
            major: u16::from_be_bytes([v[0], v[1]]),
            minor: u16::from_be_bytes([v[2], v[3]]),
        })
    }
}
