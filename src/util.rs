use crate::Error;
use std::{mem::MaybeUninit, ptr};
use widestring::{U16CStr, U16Str};
use winapi::{
    shared::{
        ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT},
        winerror,
    },
    um::{errhandlingapi, ipexport, iphlpapi, winbase, winnt::MAKELANGID},
};

/// A wrapper struct that allows a type to be Send and Sync
#[derive(Copy, Clone, Debug)]
pub(crate) struct UnsafeHandle<T>(pub T);

/// We never read from the pointer. It only serves as a handle we pass to the kernel or C code that
/// doesn't have the same mutable aliasing restrictions we have in Rust
unsafe impl<T> Send for UnsafeHandle<T> {}
unsafe impl<T> Sync for UnsafeHandle<T> {}

fn get_interface_info_sys() -> Result<Vec<ipexport::IP_ADAPTER_INDEX_MAP>, Error> {
    let mut buf_len: u32 = 0;
    //First figure out the size of the buffer needed to store the adapter info
    //SAFETY: We are upholding the contract of GetInterfaceInfo. buf_len is a valid pointer to
    //stack memory
    let result =
        unsafe { iphlpapi::GetInterfaceInfo(std::ptr::null_mut(), &mut buf_len as *mut u32) };
    if result != winerror::NO_ERROR && result != winerror::ERROR_INSUFFICIENT_BUFFER {
        let err_msg = get_error_message(result);
        log::error!("Failed to get interface info: {}", err_msg);
        return Err(format!("GetInterfaceInfo failed: {}", err_msg).into());
    }

    //Allocate a buffer of the requested size
    //IP_INTERFACE_INFO must be aligned by at least 4 byte boundaries so use u32 as the
    //underlying data storage type
    let buf_elements = buf_len as usize / std::mem::size_of::<u32>() + 1;
    //Round up incase integer division truncated a byte that filled a partial element
    let mut buf: Vec<u32> = vec![0; buf_elements];

    let buf_bytes = buf.len() * std::mem::size_of::<u32>();
    assert!(buf_bytes >= buf_len as usize);

    //SAFETY:
    //
    //  1. We are upholding the contract of GetInterfaceInfo.
    //  2. `final_buf_len` is an aligned, valid pointer to stack memory
    //  3. buf is a valid, non-null pointer to at least `buf_len` bytes of heap memory,
    //     aligned to at least 4 byte boundaries
    //
    //Get the info
    let mut final_buf_len: u32 = buf_len;
    let result = unsafe {
        iphlpapi::GetInterfaceInfo(
            buf.as_mut_ptr() as *mut ipexport::IP_INTERFACE_INFO,
            &mut final_buf_len as *mut u32,
        )
    };
    if result != winerror::NO_ERROR {
        let err_msg = get_error_message(result);
        //TODO: maybe over allocate the buffer in case the needed size changes between the two
        //calls to GetInterfaceInfo if another adapter is added
        log::error!(
            "Failed to get interface info a second time: {}. Original len: {}, final len: {}",
            err_msg,
            buf_len,
            final_buf_len
        );
        return Err(format!("GetInterfaceInfo failed a second time: {}", err_msg).into());
    }
    let info = buf.as_mut_ptr() as *const ipexport::IP_INTERFACE_INFO;
    //SAFETY:
    // info is a valid, non-null, at least 4 byte aligned pointer obtained from
    // Vec::with_capacity that is readable for up to `buf_len` bytes which is guaranteed to be
    // larger than on IP_INTERFACE_INFO struct as the kernel would never ask for less memory then
    // what it will write. The largest type inside IP_INTERFACE_INFO is a u32 therefore
    // a painter to IP_INTERFACE_INFO requires an alignment of at leant 4 bytes, which
    // Vec<u32>::as_mut_ptr() provides
    let adapter_base = unsafe { &*info };
    let adapter_count = adapter_base.NumAdapters;
    let first_adapter = &adapter_base.Adapter as *const ipexport::IP_ADAPTER_INDEX_MAP;

    // SAFETY:
    //  1. first_adapter is a valid, non null pointer, aligned to at least 4 byte boundaries
    //     obtained from moving a multiple of 4 offset into the buf given by Vec::with_capacity.
    //  2. We gave GetInterfaceInfo a buffer of at least least `buf_len` bytes to work with and it
    //     succeeded in writing the adapter information within the bounds of that buffer, otherwise
    //     it would've failed. Because the operation succeeded, we know that reading n=NumAdapters
    //     IP_ADAPTER_INDEX_MAP structs stays within the bounds of buf's buffer
    let interfaces = unsafe { std::slice::from_raw_parts(first_adapter, adapter_count as usize) };

    let mut v = Vec::with_capacity(adapter_count as usize);
    for interface in interfaces {
        v.push(*interface);
    }
    Ok(v)
}

pub(crate) fn get_interface_info() -> Result<Vec<(u32, String)>, Error> {
    let interfaces = get_interface_info_sys()?;
    let mut v = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        let name =
            unsafe { U16CStr::from_ptr_str(&interface.Name as *const u16).to_string_lossy() };
        //Nam is something like: \DEVICE\TCPIP_{29C47F55-C7BD-433A-8BF7-408DFD3B3390}
        //where the GUID is the {29C4...90}, separated by dashes
        let open = name.chars().position(|c| c == '{').ok_or(format!(
            "Failed to find {{ character inside adapter name: {}",
            name
        ))?;
        let close = name.chars().position(|c| c == '}').ok_or(format!(
            "Failed to find }} character inside adapter name: {}",
            name
        ))?;
        // v.push((interface.Index, name[open..close]));
        v.push((interface.Index, name[open..=close].to_string()));
    }
    Ok(v)
}

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
