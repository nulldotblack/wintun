use crate::wintun_raw;

use winapi::{
    shared::ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT},
    um::{winbase, winnt::MAKELANGID},
};

use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;

use widestring::U16Str;

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
    format!(
        "{} ({})",
        unsafe { U16Str::from_ptr(first, chars_written as usize) }.to_string_lossy(),
        err_code
    )
}

/// Returns the major and minor version of the wintun driver
pub fn get_running_driver_version(wintun: &Arc<wintun_raw::wintun>) -> (u16, u16) {
    let version = unsafe { wintun.WintunGetRunningDriverVersion() };
    (((version >> 16) & 0xFF) as u16, (version & 0xFF) as u16)
}
