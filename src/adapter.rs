use crate::session;
use crate::wintun_raw;
use crate::error;

use std::ptr;
use std::sync::Arc;

use once_cell::sync::OnceCell;
use widestring::U16CString;
use log::*;

pub struct Adapter {
    adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
    wintun: Arc<wintun_raw::wintun>,
}

pub struct CreateData {
    pub adapter: Adapter,
    pub reboot_required: bool,
}

fn check_pool_name(pool: &str) -> Result<(), error::WintunError> {
    if pool.len() >= wintun_raw::WINTUN_MAX_POOL as usize {
        //WINTUN_MAX_POOL is the max size including the null terminator. Because rust strings
        //are not null terminated that means the largest string we can provide from rust land
        //is when pool.len() <= 255. Therefore >= works nicely for including the null
        //terminator without having to add one
        Err(format!(
            "Pool length too large. Size: {}, Max: {}",
            pool.len(),
            wintun_raw::WINTUN_MAX_POOL
        )
        .into())
    } else {
        Ok(())
    }
}

impl Adapter {
    //TODO: Call get last error for error information on failure

    /// Creates a new wintun adapter
    pub fn create(
        wintun: &Arc<wintun_raw::wintun>,
        pool: &str,
        name: &str,
        guid: Option<u128>,
    ) -> Result<CreateData, error::WintunError> {
        let _ = check_pool_name(pool)?;

        let pool_utf16 = U16CString::from_str(pool)?;
        let name_utf16 = U16CString::from_str(name)?;

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
        //applies for all Wintun* functions
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
        let _ = check_pool_name(pool)?;

        let pool_utf16 = U16CString::from_str(pool)?;
        let name_utf16 = U16CString::from_str(name)?;

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
