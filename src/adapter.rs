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
use std::{
    ffi::OsStr,
    net::{IpAddr, Ipv4Addr},
    os::windows::prelude::OsStrExt,
    process::Command,
    ptr,
    sync::Arc,
    sync::OnceLock,
};
use windows::{
    core::{GUID, PCSTR, PCWSTR},
    Win32::{
        Foundation::FALSE,
        NetworkManagement::{
            IpHelper::{ConvertLengthToIpv4Mask, IP_ADAPTER_ADDRESSES_LH},
            Ndis::NET_LUID_LH,
        },
        System::{Com::CLSIDFromString, Threading::CreateEventA},
    },
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Returns the major and minor version of the wintun driver
pub fn get_running_driver_version(wintun: &crate::Wintun) -> Result<Version, crate::Error> {
    let version = unsafe { wintun.WintunGetRunningDriverVersion() };
    if version == 0 {
        Err(crate::Error::from(util::get_last_error()))
    } else {
        let v = version.to_be_bytes();
        Ok(Version {
            major: u16::from_be_bytes([v[0], v[1]]),
            minor: u16::from_be_bytes([v[2], v[3]]),
        })
    }
}

/// Wrapper around a <https://git.zx2c4.com/wintun/about/#wintun_adapter_handle>
pub struct Adapter {
    adapter: UnsafeHandle<wintun_raw::WINTUN_ADAPTER_HANDLE>,
    wintun: Wintun,
    guid: u128,
}

fn get_adapter_luid(wintun: &Wintun, adapter: wintun_raw::WINTUN_ADAPTER_HANDLE) -> NET_LUID_LH {
    let mut luid: wintun_raw::NET_LUID = unsafe { std::mem::zeroed() };
    unsafe { wintun.WintunGetAdapterLUID(adapter, &mut luid as *mut wintun_raw::NET_LUID) };
    unsafe { std::mem::transmute(luid) }
}

impl Adapter {
    /// Returns the `Friendly Name` of this adapter,
    /// which is the human readable name shown in Windows
    pub fn get_name(&self) -> Result<String, Error> {
        let name = util::guid_to_win_style_string(&GUID::from_u128(self.guid))?;
        let mut friendly_name = None;

        util::get_adapters_addresses(|address| {
            let name_iter = unsafe { address.AdapterName.to_string()? };
            if name_iter == name {
                friendly_name = unsafe { Some(address.FriendlyName.to_string()?) };
            }
            Ok(())
        })?;
        friendly_name.ok_or(format!("Unable to find matching {}", name).into())
    }

    /// Sets the `Friendly Name` of this adapter,
    /// which is the human readable name shown in Windows
    ///
    /// Note: This is different from `Adapter Name`, which is a GUID.
    pub fn set_name(&self, name: &str) -> Result<(), Error> {
        // use command `netsh interface set interface name="oldname" newname="mynewname"`
        let old_name = self.get_name()?;
        let out = Command::new("netsh")
            .arg("interface")
            .arg("set")
            .arg("interface")
            .arg(format!("name=\"{}\"", old_name).as_str())
            .arg(format!("newname=\"{}\"", name).as_str())
            .output()?;
        if !out.status.success() {
            return Err(format!("Failed to set name: {}", String::from_utf8_lossy(&out.stderr)).into());
        }
        Ok(())
    }

    pub fn get_guid(&self) -> u128 {
        self.guid
    }

    /// Creates a new wintun adapter inside the name `name` with tunnel type `tunnel_type`
    ///
    /// Optionally a GUID can be specified that will become the GUID of this adapter once created.
    /// Adapters obtained via this function will be able to return their adapter index via
    /// [`Adapter::get_adapter_index`]
    pub fn create(wintun: &Wintun, name: &str, tunnel_type: &str, guid: Option<u128>) -> Result<Arc<Adapter>, Error> {
        let name_utf16: Vec<_> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let tunnel_type_utf16: Vec<u16> = tunnel_type.encode_utf16().chain(std::iter::once(0)).collect();

        let guid = match guid {
            Some(guid) => guid,
            None => GUID::new()?.to_u128(),
        };

        crate::log::set_default_logger_if_unset(wintun);

        let guid_struct: wintun_raw::GUID = unsafe { std::mem::transmute(GUID::from_u128(guid)) };
        let guid_ptr = &guid_struct as *const wintun_raw::GUID;

        let result = unsafe { wintun.WintunCreateAdapter(name_utf16.as_ptr(), tunnel_type_utf16.as_ptr(), guid_ptr) };

        if result.is_null() {
            Err("Failed to create adapter".into())
        } else {
            Ok(Arc::new(Adapter {
                adapter: UnsafeHandle(result),
                wintun: wintun.clone(),
                guid,
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
        let name_utf16: Vec<u16> = OsStr::new(name).encode_wide().chain(std::iter::once(0)).collect();

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
                    let adapter_name_utf16: Vec<u16> = adapter_name.encode_utf16().chain(std::iter::once(0)).collect();
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
            return Err(Error::CapacityOutOfRange(OutOfRangeData { range, value: capacity }));
        }
        if !capacity.is_power_of_two() {
            return Err(Error::CapacityNotPowerOfTwo(capacity));
        }

        let result = unsafe { self.wintun.WintunStartSession(self.adapter.0, capacity) };

        if result.is_null() {
            Err("WintunStartSession failed".into())
        } else {
            let shutdown_event = unsafe { CreateEventA(None, FALSE, FALSE, PCSTR::null())? };
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

    /// Returns `MTU` of this adapter
    pub fn get_mtu(&self) -> Result<usize, Error> {
        let luid = self.get_luid();
        Ok(util::get_adapter_mtu(&luid)?)
    }

    /// Returns the Win32 interface index of this adapter. Useful for specifying the interface
    /// when executing `netsh interface ip` commands
    pub fn get_adapter_index(&self) -> Result<u32, Error> {
        let name = util::guid_to_win_style_string(&GUID::from_u128(self.guid))?;
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

    /// Sets the IP address for this adapter, using command `netsh`.
    pub fn set_address(&self, address: Ipv4Addr) -> Result<(), Error> {
        let binding = self.get_addresses()?;
        let old_address = binding.iter().find(|addr| matches!(addr, IpAddr::V4(_)));
        let mask = match old_address {
            Some(IpAddr::V4(addr)) => self.get_netmask_of_address(&(*addr).into())?,
            _ => "255.255.255.0".parse()?,
        };
        let gateway = self
            .get_gateways()?
            .iter()
            .find(|addr| matches!(addr, IpAddr::V4(_)))
            .cloned();
        self.set_network_addresses_tuple(address.into(), mask, gateway)?;
        Ok(())
    }

    /// Sets the gateway for this adapter, using command `netsh`.
    pub fn set_gateway(&self, gateway: Option<Ipv4Addr>) -> Result<(), Error> {
        let binding = self.get_addresses()?;
        let address = binding.iter().find(|addr| matches!(addr, IpAddr::V4(_)));
        let address = match address {
            Some(IpAddr::V4(addr)) => addr,
            _ => return Err("Unable to find IPv4 address".into()),
        };
        let mask = self.get_netmask_of_address(&(*address).into())?;
        let gateway = gateway.map(|addr| addr.into());
        self.set_network_addresses_tuple((*address).into(), mask, gateway)?;
        Ok(())
    }

    /// Sets the subnet mask for this adapter, using command `netsh`.
    pub fn set_netmask(&self, mask: Ipv4Addr) -> Result<(), Error> {
        let binding = self.get_addresses()?;
        let address = binding.iter().find(|addr| matches!(addr, IpAddr::V4(_)));
        let address = match address {
            Some(IpAddr::V4(addr)) => addr,
            _ => return Err("Unable to find IPv4 address".into()),
        };
        let gateway = self
            .get_gateways()?
            .iter()
            .find(|addr| matches!(addr, IpAddr::V4(_)))
            .cloned();
        self.set_network_addresses_tuple((*address).into(), mask.into(), gateway)?;
        Ok(())
    }

    /// Sets the DNS servers for this adapter
    pub fn set_dns_servers(&self, dns_servers: &[IpAddr]) -> Result<(), Error> {
        let interface = GUID::from(self.get_guid());
        Ok(util::set_interface_dns_settings(interface, dns_servers)?)
    }

    /// Sets the network addresses of this adapter, including network address, subnet mask, and gateway
    pub fn set_network_addresses_tuple(
        &self,
        address: IpAddr,
        mask: IpAddr,
        gateway: Option<IpAddr>,
    ) -> Result<(), Error> {
        let name = self.get_name()?;
        // Command line: `netsh interface ipv4 set address name="YOUR_INTERFACE_NAME" source=static address=IP_ADDRESS mask=SUBNET_MASK gateway=GATEWAY`
        // or shorter command: `netsh interface ipv4 set address name="YOUR_INTERFACE_NAME" static IP_ADDRESS SUBNET_MASK GATEWAY`
        // for example: `netsh interface ipv4 set address name="Wi-Fi" static 192.168.3.8 255.255.255.0 192.168.3.1`
        let mut binding = Command::new("netsh");
        let mut cmd = binding
            .arg("interface")
            .arg(if address.is_ipv4() { "ipv4" } else { "ipv6" })
            .arg("set")
            .arg("address")
            .arg(format!("name=\"{}\"", name).as_str())
            .arg("source=static")
            .arg(format!("address={}", address).as_str())
            .arg(format!("mask={}", mask).as_str());
        if let Some(gateway) = gateway {
            cmd = cmd.arg(format!("gateway={}", gateway).as_str());
        }
        let out = cmd.output()?;
        if !out.status.success() {
            return Err(format!("Failed to set address: {}", String::from_utf8_lossy(&out.stderr)).into());
        }
        Ok(())
    }

    /// Returns the IP addresses of this adapter, including IPv4 and IPv6 addresses
    pub fn get_addresses(&self) -> Result<Vec<IpAddr>, Error> {
        let name = util::guid_to_win_style_string(&GUID::from_u128(self.guid))?;

        let mut adapter_addresses = vec![];

        util::get_adapters_addresses(|adapter| {
            let name_iter = unsafe { adapter.AdapterName.to_string()? };
            if name_iter == name {
                let mut current_address = adapter.FirstUnicastAddress;
                while !current_address.is_null() {
                    let address = unsafe { (*current_address).Address };
                    let address = util::retrieve_ipaddr_from_socket_address(&address);
                    if let Err(err) = address {
                        log::error!("Failed to parse address: {}", err);
                    } else {
                        adapter_addresses.push(address?);
                    }
                    unsafe {
                        current_address = (*current_address).Next;
                    }
                }
            }
            Ok(())
        })?;

        Ok(adapter_addresses)
    }

    /// Returns the gateway addresses of this adapter, including IPv4 and IPv6 addresses
    pub fn get_gateways(&self) -> Result<Vec<IpAddr>, Error> {
        let name = util::guid_to_win_style_string(&GUID::from_u128(self.guid))?;
        let mut gateways = vec![];
        util::get_adapters_addresses(|adapter| {
            let name_iter = unsafe { adapter.AdapterName.to_string()? };
            if name_iter == name {
                let mut current_gateway = adapter.FirstGatewayAddress;
                while !current_gateway.is_null() {
                    let gateway = unsafe { (*current_gateway).Address };
                    let gateway = util::retrieve_ipaddr_from_socket_address(&gateway);
                    if let Err(err) = gateway {
                        log::error!("Failed to parse gateway: {}", err);
                    } else {
                        gateways.push(gateway?);
                    }
                    unsafe {
                        current_gateway = (*current_gateway).Next;
                    }
                }
            }
            Ok(())
        })?;
        Ok(gateways)
    }

    /// Returns the subnet mask of the given address
    pub fn get_netmask_of_address(&self, target_address: &IpAddr) -> Result<IpAddr, Error> {
        let name = util::guid_to_win_style_string(&GUID::from_u128(self.guid))?;
        let mut subnet_mask = None;
        util::get_adapters_addresses(|adapter| {
            let name_iter = unsafe { adapter.AdapterName.to_string()? };
            if name_iter == name {
                let mut current_address = adapter.FirstUnicastAddress;
                while !current_address.is_null() {
                    let address = unsafe { (*current_address).Address };
                    let address = util::retrieve_ipaddr_from_socket_address(&address);
                    if let Err(ref err) = address {
                        log::warn!("Failed to parse address: {}", err);
                    }
                    let address = address?;
                    if address == *target_address {
                        let masklength = unsafe { (*current_address).OnLinkPrefixLength };
                        match address {
                            IpAddr::V4(_) => {
                                let mut mask = 0_u32;
                                unsafe { ConvertLengthToIpv4Mask(masklength as u32, &mut mask as *mut u32)? };
                                subnet_mask = Some(IpAddr::V4(Ipv4Addr::from(mask.to_le_bytes())));
                            }
                            IpAddr::V6(_) => {
                                subnet_mask = Some(IpAddr::V6(util::ipv6_netmask_for_prefix(masklength)?));
                            }
                        }
                        break;
                    }
                    unsafe {
                        current_address = (*current_address).Next;
                    }
                }
            }
            Ok(())
        })?;

        Ok(subnet_mask.ok_or("Unable to find matching address")?)
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
