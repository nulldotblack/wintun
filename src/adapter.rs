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
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::FALSE,
        NetworkManagement::{IpHelper::ConvertLengthToIpv4Mask, Ndis::NET_LUID_LH},
        System::Threading::CreateEventA,
    },
};

/// Wrapper around a <https://git.zx2c4.com/wintun/about/#wintun_adapter_handle>
pub struct Adapter {
    adapter: UnsafeHandle<wintun_raw::WINTUN_ADAPTER_HANDLE>,
    wintun: Wintun,
    guid: u128,
    index: u32,
    luid: NET_LUID_LH,
}

impl Adapter {
    /// Returns the `Friendly Name` of this adapter,
    /// which is the human readable name shown in Windows
    pub fn get_name(&self) -> Result<String, Error> {
        let name = crate::ffi::luid_to_alias(&self.luid)?;
        Ok(util::decode_utf16(&name))
    }

    /// Sets the `Friendly Name` of this adapter,
    /// which is the human readable name shown in Windows
    ///
    /// Note: This is different from `Adapter Name`, which is a GUID.
    pub fn set_name(&self, name: &str) -> Result<(), Error> {
        // use command `netsh interface set interface name="oldname" newname="mynewname"`

        let args = &[
            "interface",
            "set",
            "interface",
            &format!("name=\"{}\"", self.get_name()?),
            &format!("newname=\"{}\"", name),
        ];
        util::run_command("netsh", args)?;

        Ok(())
    }

    pub fn get_guid(&self) -> u128 {
        self.guid
    }

    /// Creates a new wintun adapter inside the name `name` with tunnel type `tunnel_type`
    ///
    /// Optionally a GUID can be specified that will become the GUID of this adapter once created.
    pub fn create(wintun: &Wintun, name: &str, tunnel_type: &str, guid: Option<u128>) -> Result<Arc<Adapter>, Error> {
        let name_utf16: Vec<_> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let tunnel_type_utf16: Vec<u16> = tunnel_type.encode_utf16().chain(std::iter::once(0)).collect();

        let guid = match guid {
            Some(guid) => guid,
            None => {
                let mut guid: GUID = unsafe { std::mem::zeroed() };
                unsafe { windows_sys::Win32::System::Rpc::UuidCreate(&mut guid as *mut GUID) };
                util::win_guid_to_u128(&guid)
            }
        };

        crate::log::set_default_logger_if_unset(wintun);

        let guid_struct: wintun_raw::GUID = unsafe { std::mem::transmute(GUID::from_u128(guid)) };
        let guid_ptr = &guid_struct as *const wintun_raw::GUID;

        let result = unsafe { wintun.WintunCreateAdapter(name_utf16.as_ptr(), tunnel_type_utf16.as_ptr(), guid_ptr) };

        if result.is_null() {
            Err("Failed to create adapter".into())
        } else {
            let luid = crate::ffi::alias_to_luid(&name_utf16)?;
            let index = crate::ffi::luid_to_index(&luid)?;
            Ok(Arc::new(Adapter {
                adapter: UnsafeHandle(result),
                wintun: wintun.clone(),
                guid,
                index,
                luid,
            }))
        }
    }

    /// Attempts to open an existing wintun interface name `name`.
    pub fn open(wintun: &Wintun, name: &str) -> Result<Arc<Adapter>, Error> {
        let name_utf16: Vec<u16> = OsStr::new(name).encode_wide().chain(std::iter::once(0)).collect();

        crate::log::set_default_logger_if_unset(wintun);

        let result = unsafe { wintun.WintunOpenAdapter(name_utf16.as_ptr()) };

        if result.is_null() {
            Err("WintunOpenAdapter failed".into())
        } else {
            let luid = crate::ffi::alias_to_luid(&name_utf16)?;
            let index = crate::ffi::luid_to_index(&luid)?;
            let guid = crate::ffi::luid_to_guid(&luid)?;
            let guid = unsafe { std::mem::transmute::<GUID, u128>(guid) };
            Ok(Arc::new(Adapter {
                adapter: UnsafeHandle(result),
                wintun: wintun.clone(),
                guid,
                index,
                luid,
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
    /// a power of two between [`crate::MIN_RING_CAPACITY`] and [`crate::MAX_RING_CAPACITY`] inclusive.
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
            let shutdown_event = unsafe { CreateEventA(std::ptr::null_mut(), FALSE, FALSE, std::ptr::null_mut()) };
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
        self.luid
    }

    /// Set `MTU` of this adapter
    pub fn set_mtu(&self, mtu: usize) -> Result<(), Error> {
        let name = self.get_name()?;
        Ok(util::set_adapter_mtu(&name, mtu)?)
    }

    /// Returns `MTU` of this adapter
    pub fn get_mtu(&self) -> Result<usize, Error> {
        let luid = self.get_luid();
        Ok(util::get_adapter_mtu(&luid)?)
    }

    /// Returns the Win32 interface index of this adapter. Useful for specifying the interface
    /// when executing `netsh interface ip` commands
    pub fn get_adapter_index(&self) -> Result<u32, Error> {
        Ok(self.index)
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
        let interface = GUID::from_u128(self.get_guid());
        if let Err(err) = util::set_interface_dns_servers(interface, dns_servers) {
            log::error!("Failed to set DNS servers in first attempt: {}", err);
            util::set_adapter_dns_servers(&self.get_name()?, dns_servers)?;
        }
        Ok(())
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
            let name_iter = unsafe { util::win_pstr_to_string(adapter.AdapterName) }?;
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
            let name_iter = unsafe { util::win_pstr_to_string(adapter.AdapterName) }?;
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
            let name_iter = unsafe { util::win_pstr_to_string(adapter.AdapterName) }?;
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
                                match unsafe { ConvertLengthToIpv4Mask(masklength as u32, &mut mask as *mut u32) } {
                                    0 => {}
                                    err => return Err(std::io::Error::from_raw_os_error(err as i32).into()),
                                }
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
