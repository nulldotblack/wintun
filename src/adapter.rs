/// Representation of a winton adapter with safe idiomatic bindings to the functionality provided by
/// the WintunAdapter* C functions.
///
/// The [`Adapter::create`] and [`Adapter::open`] functions serve as the entry point to using
/// wintun functionality
use crate::{
    error::{Error, OutOfRangeData},
    session,
    util::{self, UnsafeHandle},
    wintun_raw, Wintun,
};
use std::{ffi::OsStr, os::windows::prelude::OsStrExt, ptr, sync::Arc, sync::OnceLock};
use windows::{
    core::{GUID, PCSTR, PCWSTR},
    Win32::{
        Foundation::FALSE,
        NetworkManagement::{IpHelper::IP_ADAPTER_ADDRESSES_LH, Ndis::NET_LUID_LH},
        System::{
            Com::{CLSIDFromString, StringFromGUID2},
            Threading::CreateEventA,
        },
    },
};

/// Wrapper around a <https://git.zx2c4.com/wintun/about/#wintun_adapter_handle>
pub struct Adapter {
    adapter: UnsafeHandle<wintun_raw::WINTUN_ADAPTER_HANDLE>,
    wintun: Wintun,
    guid: u128,
    name: String,
}

fn get_adapter_luid(wintun: &Wintun, adapter: wintun_raw::WINTUN_ADAPTER_HANDLE) -> NET_LUID_LH {
    let mut luid: wintun_raw::NET_LUID = unsafe { std::mem::zeroed() };
    unsafe { wintun.WintunGetAdapterLUID(adapter, &mut luid as *mut wintun_raw::NET_LUID) };
    unsafe { std::mem::transmute(luid) }
}

impl Adapter {
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_guid(&self) -> u128 {
        self.guid
    }

    //TODO: Call get last error for error information on failure and improve error types

    /// Creates a new wintun adapter inside the name `name` with tunnel type `tunnel_type`
    ///
    /// Optionally a GUID can be specified that will become the GUID of this adapter once created.
    /// Adapters obtained via this function will be able to return their adapter index via
    /// [`Adapter::get_adapter_index`]
    pub fn create(
        wintun: &Wintun,
        name: &str,
        tunnel_type: &str,
        guid: Option<u128>,
    ) -> Result<Arc<Adapter>, Error> {
        let name_utf16: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let tunnel_type_utf16: Vec<u16> = OsStr::new(tunnel_type)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let guid = match guid {
            Some(guid) => guid,
            None => GUID::new()?.to_u128(),
        };

        crate::log::set_default_logger_if_unset(wintun);

        let guid_struct: wintun_raw::GUID = unsafe { std::mem::transmute(GUID::from_u128(guid)) };
        let guid_ptr = &guid_struct as *const wintun_raw::GUID;

        let result = unsafe {
            wintun.WintunCreateAdapter(name_utf16.as_ptr(), tunnel_type_utf16.as_ptr(), guid_ptr)
        };

        if result.is_null() {
            Err("Failed to create adapter".into())
        } else {
            Ok(Arc::new(Adapter {
                adapter: UnsafeHandle(result),
                wintun: wintun.clone(),
                guid,
                name: name.to_string(),
            }))
        }
    }

    /// Attempts to open an existing wintun interface name `name`.
    ///
    /// Adapters opened via this call will have an unknown GUID meaning [`Adapter::get_adapter_index`]
    /// will always fail because knowing the adapter's GUID is required to determine its index.
    /// Currently a workaround is to delete and re-create a new adapter every time one is needed so
    /// that it gets created with a known GUID, allowing [`Adapter::get_adapter_index`] to works as
    /// expected. There is likely a way to get the GUID of our adapter using the Windows Registry
    /// or via the Win32 API, so PR's that solve this issue are always welcome!
    pub fn open(wintun: &Wintun, name: &str) -> Result<Arc<Adapter>, Error> {
        let name_utf16: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        crate::log::set_default_logger_if_unset(wintun);

        let result = unsafe { wintun.WintunOpenAdapter(name_utf16.as_ptr()) };

        if result.is_null() {
            Err("WintunOpenAdapter failed".into())
        } else {
            let mut guid = None;
            util::get_adapters_addresses(|address: IP_ADAPTER_ADDRESSES_LH| {
                let frindly_name = PCWSTR(address.FriendlyName.0 as *const u16);
                let frindly_name = unsafe { frindly_name.to_string()? };
                if frindly_name == name {
                    let adapter_name = unsafe { address.AdapterName.to_string()? };
                    let adapter_name_utf16: Vec<u16> = adapter_name
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();
                    let adapter_name_ptr: *const u16 = adapter_name_utf16.as_ptr();
                    let adapter = unsafe { CLSIDFromString(PCWSTR(adapter_name_ptr))? };
                    guid = Some(adapter);
                }
                Ok(())
            })?;
            let guid = guid.ok_or("Unable to find matching GUID")?.to_u128();
            Ok(Arc::new(Adapter {
                adapter: UnsafeHandle(result),
                wintun: wintun.clone(),
                guid,
                name: name.to_string(),
            }))
        }
    }

    /// Delete an adapter, consuming it in the process
    pub fn delete(self) -> Result<(), Error> {
        //Dropping an adapter closes it
        drop(self);
        // Return a result here so that if later the API changes to be fallible, we can support it
        // without making a breaking change
        Ok(())
    }

    /// Initiates a new wintun session on the given adapter.
    ///
    /// Capacity is the size in bytes of the ring buffer used internally by the driver. Must be
    /// a power of two between [`crate::MIN_RING_CAPACITY`] and [`crate::MIN_RING_CAPACITY`].
    pub fn start_session(self: &Arc<Self>, capacity: u32) -> Result<session::Session, Error> {
        let range = crate::MIN_RING_CAPACITY..=crate::MAX_RING_CAPACITY;
        if !range.contains(&capacity) {
            return Err(Error::CapacityOutOfRange(OutOfRangeData {
                range,
                value: capacity,
            }));
        }
        if !capacity.is_power_of_two() {
            return Err(Error::CapacityNotPowerOfTwo(capacity));
        }

        let result = unsafe { self.wintun.WintunStartSession(self.adapter.0, capacity) };

        if result.is_null() {
            Err("WintunStartSession failed".into())
        } else {
            let shutdown_event =
                unsafe { CreateEventA(None, FALSE, FALSE, PCSTR(std::ptr::null()))? };
            Ok(session::Session {
                session: UnsafeHandle(result),
                wintun: self.wintun.clone(),
                read_event: OnceLock::new(),
                shutdown_event,
                adapter: Arc::clone(self),
            })
        }
    }

    /// Returns the Win32 LUID for this adapter
    pub fn get_luid(&self) -> NET_LUID_LH {
        get_adapter_luid(&self.wintun, self.adapter.0)
    }

    /// Returns the Win32 interface index of this adapter. Useful for specifying the interface
    /// when executing `netsh interface ip` commands
    pub fn get_adapter_index(&self) -> Result<u32, Error> {
        let name = GUID::from_u128(self.guid);
        let mut buffer = [0u16; 40];
        unsafe { StringFromGUID2(&name, &mut buffer) };
        let name = unsafe { PCWSTR(&buffer as *const u16).to_string()? };

        let mut adapter_index = None;

        util::get_adapters_addresses(|address| {
            let name_iter = unsafe { address.AdapterName.to_string()? };
            if name_iter == name {
                adapter_index = unsafe { Some(address.Anonymous1.Anonymous.IfIndex) };
                // adapter_index = Some(address.Ipv6IfIndex);
            }
            Ok(())
        })?;
        adapter_index.ok_or(format!("Unable to find matching {}", name).into())
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        //Close adapter on drop
        //This is why we need an Arc of wintun
        unsafe { self.wintun.WintunCloseAdapter(self.adapter.0) };
        self.adapter = UnsafeHandle(ptr::null_mut());
    }
}
