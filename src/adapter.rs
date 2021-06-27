use crate::error;
use crate::session;
use crate::wintun_raw;

use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;

use log::*;
use once_cell::sync::OnceCell;
use widestring::U16CStr;
use widestring::U16CString;

pub struct Adapter {
    adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
    wintun: Arc<wintun_raw::wintun>,
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

        let guid_struct = wintun_raw::GUID {
            __bindgen_anon_1: wintun_raw::_GUID__bindgen_ty_1 {
                Bytes: match guid {
                    Some(guid) => guid.to_ne_bytes(),
                    None => [0u8; 16],
                },
            },
        };
        let guid_ptr = guid.map_or(ptr::null(), |_| &guid_struct as *const wintun_raw::GUID);

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
            })
        }
    }

    pub fn get_luid(&self) -> u64 {
        get_adapter_luid(&self.wintun, self.adapter)
    }

    pub fn get_adapter_name(&self) -> String {
        get_adapter_name(&self.wintun, self.adapter)
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
