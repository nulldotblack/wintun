use crate::error;
use crate::session;
use crate::util;
use crate::wintun_raw;

use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;

use itertools::Itertools;
use log::*;
use once_cell::sync::OnceCell;
use rand::Rng;

use widestring::U16CStr;
use widestring::U16CString;

use winapi::{
    shared::{
        ifdef, netioapi, nldef,
        ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT},
        winerror, ws2def, ws2ipdef,
    },
    um::{ipexport, iphlpapi, synchapi},
};

pub struct Adapter {
    adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
    wintun: Arc<wintun_raw::wintun>,
    guid: u128,
}

pub struct CreateData {
    pub adapter: Adapter,
    pub reboot_required: bool,
}

fn encode_utf16(string: &str, max_characters: u32) -> Result<U16CString, error::WintunError> {
    let utf16 = U16CString::from_str(string)?;
    if utf16.len() >= max_characters as usize {
        //max_characters is the maximum number of characters including the null terminator. And .len() measures the
        //number of characters (excluding the null terminator). Therefore we can hold a string with
        //max_characters - 1 because the null terminator sits in the last element. However a string
        //of length max_characters needs max_characters + 1 to store the null terminator the >=
        //check holds
        Err(format!(
            //TODO: Better error handling
            "Length too large. Size: {}, Max: {}",
            utf16.len(),
            max_characters
        )
        .into())
    } else {
        Ok(utf16)
    }
}

fn encode_pool_name(name: &str) -> Result<U16CString, error::WintunError> {
    encode_utf16(name, wintun_raw::WINTUN_MAX_POOL)
}

fn encode_adapter_name(name: &str) -> Result<U16CString, error::WintunError> {
    encode_utf16(name, wintun_raw::MAX_ADAPTER_NAME)
}

fn get_adapter_name(
    wintun: &Arc<wintun_raw::wintun>,
    adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
) -> String {
    let mut name = MaybeUninit::<[u16; wintun_raw::MAX_ADAPTER_NAME as usize]>::uninit();

    //SAFETY: name is a allocated on the stack above therefore it must be valid, non-null and
    //aligned for u16
    let first = unsafe { *name.as_mut_ptr() }.as_mut_ptr();
    //Write default null terminator in case WintunGetAdapterName leaves name unchanged
    unsafe { first.write(0u16) };
    unsafe { wintun.WintunGetAdapterName(adapter, first) };

    //SAFETY: first is a valid, non-null, aligned, null terminated pointer
    unsafe { U16CStr::from_ptr_str(first) }.to_string_lossy()
}

fn get_adapter_luid(
    wintun: &Arc<wintun_raw::wintun>,
    adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
) -> u64 {
    let mut luid = 0u64;
    unsafe { wintun.WintunGetAdapterLUID(adapter, &mut luid as *mut u64) };
    luid
}

pub struct EnumeratedAdapter {
    pub name: String,
    pub luid: wintun_raw::NET_LUID,
}

impl Adapter {
    //TODO: Call get last error for error information on failure and improve error types

    /// Creates a new wintun adapter
    pub fn create(
        wintun: &Arc<wintun_raw::wintun>,
        pool: &str,
        name: &str,
        guid: Option<u128>,
    ) -> Result<CreateData, error::WintunError> {
        let pool_utf16 = encode_pool_name(pool)?;
        let name_utf16 = encode_adapter_name(name)?;

        let guid = match guid {
            Some(guid) => guid,
            None => {
                let mut guid_bytes: [u8; 16] = [0u8; 16];
                rand::thread_rng().fill(&mut guid_bytes);
                u128::from_ne_bytes(guid_bytes)
            }
        };
        //SAFETY: guid is a unique integer so transmuting either all zeroes or the user's preferred
        //guid to the winapi guid type is safe and will allow the windows kernel to see our GUID
        let guid_struct: wintun_raw::GUID = unsafe { std::mem::transmute(guid) };

        //We can't simply get the address of guid in the closure because it needs to live for at least as
        //long as the call to WintunCreateAdapter so do need all these variables and lines of code
        let guid_ptr = &guid_struct as *const wintun_raw::GUID;

        let mut reboot_required = 0u8;

        crate::log::set_default_logger_if_unset(&wintun);

        //SAFETY: the function is loaded from the wintun dll properly, we are providing valid
        //pointers, and all the strings are correct null terminated UTF-16. This safety rationale
        //applies for all Wintun* functions below
        let result = unsafe {
            wintun.WintunCreateAdapter(
                pool_utf16.as_ptr(),
                name_utf16.as_ptr(),
                guid_ptr,
                &mut reboot_required as *mut u8,
            )
        };

        if result == ptr::null_mut() {
            Err("Failed to crate adapter".into())
        } else {
            Ok(CreateData {
                adapter: Adapter {
                    adapter: result,
                    wintun: wintun.clone(),
                    guid,
                },
                reboot_required: reboot_required != 0,
            })
        }
    }

    pub fn open(
        wintun: &Arc<wintun_raw::wintun>,
        pool: &str,
        name: &str,
    ) -> Result<Adapter, error::WintunError> {
        let _ = encode_pool_name(pool)?;

        let pool_utf16 = encode_pool_name(pool)?;
        let name_utf16 = encode_adapter_name(name)?;

        crate::log::set_default_logger_if_unset(&wintun);

        let result = unsafe { wintun.WintunOpenAdapter(pool_utf16.as_ptr(), name_utf16.as_ptr()) };

        if result == ptr::null_mut() {
            Err("WintunOpenAdapter failed".into())
        } else {
            Ok(Adapter {
                adapter: result,
                wintun: wintun.clone(),
                guid: todo!(),
            })
        }
    }

    pub fn list_all(
        wintun: &Arc<wintun_raw::wintun>,
        pool: &str,
    ) -> Result<Vec<EnumeratedAdapter>, error::WintunError> {
        let pool_utf16 = encode_pool_name(pool)?;
        let mut result = Vec::new();

        //Maybe oneday this will be part of the language, or a proc macro
        struct CallbackData<'a> {
            vec: &'a mut Vec<EnumeratedAdapter>,
            wintun: &'a Arc<wintun_raw::wintun>,
        }

        extern "C" fn enumerate_one(
            adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
            param: wintun_raw::LPARAM,
        ) -> u8 {
            let data = unsafe { (param as *mut CallbackData).as_mut() }.unwrap();
            data.vec.push(EnumeratedAdapter {
                name: get_adapter_name(data.wintun, adapter),
                luid: get_adapter_luid(data.wintun, adapter),
            });
            1
        }
        let mut data = CallbackData {
            vec: &mut result,
            wintun,
        };

        unsafe {
            wintun.WintunEnumAdapters(
                pool_utf16.as_ptr(),
                Some(enumerate_one),
                (&mut data as *mut CallbackData) as wintun_raw::LPARAM,
            )
        };

        Ok(result)
    }

    pub fn delete(self, force_close_sessions: bool) -> Result<bool, ()> {
        let mut reboot_required = 0u8;

        let result = unsafe {
            self.wintun.WintunDeleteAdapter(
                self.adapter,
                u8::from(force_close_sessions),
                &mut reboot_required as *mut u8,
            )
        };

        if result != 0 {
            Ok(reboot_required != 0)
        } else {
            Err(())
        }
    }

    pub fn start_session(&self, capacity: u32) -> Result<session::Session, error::WintunError> {
        let range = wintun_raw::WINTUN_MIN_RING_CAPACITY..=wintun_raw::WINTUN_MAX_RING_CAPACITY;
        if !range.contains(&capacity) {
            return Err(Box::new(error::ApiError::CapacityOutOfRange(
                error::OutOfRangeData {
                    range,
                    value: capacity,
                },
            )));
        }
        if !capacity.is_power_of_two() {
            return Err(Box::new(error::ApiError::CapacityNotPowerOfTwo(capacity)));
        }

        let result = unsafe { self.wintun.WintunStartSession(self.adapter, capacity) };

        if result == ptr::null_mut() {
            Err("WintunStartSession failed".into())
        } else {
            Ok(session::Session {
                session: session::UnsafeHandle(result),
                wintun: self.wintun.clone(),
                read_event: OnceCell::new(),
                shutdown_event: unsafe {
                    //SAFETY: We follow the contract required by CreateEventA. See MSDN
                    //(the pointers are allowed to be null, and 0 is okay for the others)
                    session::UnsafeHandle(synchapi::CreateEventA(
                        std::ptr::null_mut(),
                        0,
                        0,
                        std::ptr::null_mut(),
                    ))
                },
            })
        }
    }

    pub fn get_luid(&self) -> u64 {
        get_adapter_luid(&self.wintun, self.adapter)
    }

    pub fn get_adapter_name(&self) -> String {
        get_adapter_name(&self.wintun, self.adapter)
    }

    pub fn get_adapter_index(&self) -> Result<u32, error::WintunError> {
        let mut buf_len: u32 = 0;
        let result =
            unsafe { iphlpapi::GetInterfaceInfo(std::ptr::null_mut(), &mut buf_len as *mut u32) };
        if result != winerror::NO_ERROR && result != winerror::ERROR_INSUFFICIENT_BUFFER {
            let err_msg = util::get_error_message(result);
            error!("Failed to get interface info: {}", err_msg);
            return Err(format!("GetInterfaceInfo failed: {}", err_msg).into());
        }
        let mut buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
        buf.resize(buf_len as usize, 0);
        let mut final_buf_len: u32 = buf_len;
        let result = unsafe {
            iphlpapi::GetInterfaceInfo(
                buf.as_mut_ptr() as *mut ipexport::IP_INTERFACE_INFO,
                &mut final_buf_len as *mut u32,
            )
        };
        if result != winerror::NO_ERROR {
            let err_msg = util::get_error_message(result);
            error!(
                "Failed to get interface info a second time: {}. Original len: {}, final len: {}",
                err_msg, buf_len, final_buf_len
            );
            return Err(format!("GetInterfaceInfo failed a second time: {}", err_msg).into());
        }
        let info = buf.as_mut_ptr() as *const ipexport::IP_INTERFACE_INFO;
        let adapter_base = unsafe { &*info };
        let adapter_count = adapter_base.NumAdapters;
        info!("Got {} adapters", adapter_count);
        let first_adapter = &adapter_base.Adapter as *const ipexport::IP_ADAPTER_INDEX_MAP;

        let interfaces =
            unsafe { std::slice::from_raw_parts(first_adapter, adapter_count as usize) };

        for interface in interfaces {
            let name =
                unsafe { U16CStr::from_ptr_str(&interface.Name as *const u16).to_string_lossy() };
            let open = name.chars().position(|c| c == '{');
            let close = name.chars().position(|c| c == '}');
            let digits: Vec<u8> = name[open.unwrap()..close.unwrap()]
                .chars()
                .filter(|c| c.is_digit(16))
                .chunks(2)
                .into_iter()
                .map(|mut chunk| {
                    let a = chunk.next().unwrap();
                    let b = chunk.next().unwrap();
                    let chars: [u8; 2] = [a as u8, b as u8];
                    let s = std::str::from_utf8(&chars).unwrap();
                    u8::from_str_radix(s, 16).unwrap()
                })
                .collect();

            let mut match_count = 0;
            for byte in self.guid.to_ne_bytes() {
                if digits.contains(&byte) {
                    match_count += 1;
                }
            }
            if match_count == digits.len() {
                return Ok(interface.Index);
            }
        }
        Err("Unable to find matching GUID".into())
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        trace!("dropping");
        //Free adapter on drop
        //This is why we need an Arc of wintun
        unsafe { self.wintun.WintunFreeAdapter(self.adapter) };
        self.adapter = ptr::null_mut();
    }
}
