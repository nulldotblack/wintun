use crate::Error;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{
            GetLastError, LocalFree, ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, NO_ERROR,
            WIN32_ERROR,
        },
        NetworkManagement::{
            IpHelper::{
                FreeMibTable, GetAdaptersAddresses, GetIfTable2, GetInterfaceInfo, DNS_INTERFACE_SETTINGS,
                DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_GATEWAYS,
                GAA_FLAG_INCLUDE_PREFIX, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
                IP_ADAPTER_INDEX_MAP, IP_INTERFACE_INFO, MIB_IF_ROW2, MIB_IF_TABLE2,
            },
            Ndis::{IfOperStatusUp, NET_LUID_LH},
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS},
        System::{
            Com::StringFromGUID2,
            Diagnostics::Debug::{FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM},
            SystemServices::{LANG_NEUTRAL, SUBLANG_DEFAULT},
        },
    },
};

pub(crate) const fn win_guid_to_u128(guid: &GUID) -> u128 {
    let data4_u64 = u64::from_be_bytes(guid.data4);
    ((guid.data1 as u128) << 96) | ((guid.data2 as u128) << 80) | ((guid.data3 as u128) << 64) | (data4_u64 as u128)
}

pub(crate) unsafe fn win_pstr_to_string(pstr: ::windows_sys::core::PSTR) -> Result<String, Error> {
    Ok(std::ffi::CStr::from_ptr(pstr as *const std::ffi::c_char)
        .to_str()
        .map_err(|e| format!("Invalid UTF-8 sequence: {}", e))?
        .to_owned())
}

pub(crate) unsafe fn win_pwstr_to_string(pwstr: ::windows_sys::core::PWSTR) -> Result<String, Error> {
    if pwstr.is_null() {
        return Err("Null pointer received".into());
    }

    let mut len = 0;
    while *pwstr.add(len) != 0 {
        len += 1;
    }

    let slice = std::slice::from_raw_parts(pwstr, len);

    use std::os::windows::ffi::OsStringExt;
    let os_string = std::ffi::OsString::from_wide(slice);
    os_string
        .into_string()
        .map_err(|e| format!("Invalid UTF-8 sequence: {:?}", e).into())
}

/// A wrapper struct that allows a type to be Send and Sync
#[derive(Copy, Clone, Debug)]
pub(crate) struct UnsafeHandle<T>(pub T);

/// We never read from the pointer. It only serves as a handle we pass to the kernel or C code that
/// doesn't have the same mutable aliasing restrictions we have in Rust
unsafe impl<T> Send for UnsafeHandle<T> {}
unsafe impl<T> Sync for UnsafeHandle<T> {}

pub(crate) fn guid_to_win_style_string(guid: &GUID) -> Result<String, Error> {
    let mut buffer = [0u16; 40];
    unsafe { StringFromGUID2(guid, &mut buffer as *mut u16, buffer.len() as i32) };
    let guid = unsafe { win_pwstr_to_string(buffer.as_ptr() as _)? };
    Ok(guid)
}

pub(crate) fn ipv6_netmask_for_prefix(prefix: u8) -> Result<Ipv6Addr, &'static str> {
    if prefix > 128 {
        return Err("Prefix value must be between 0 and 128.");
    }
    let mut mask: [u16; 8] = [0; 8];
    let mut i = 0;
    let mut remaining = prefix;
    while remaining >= 16 {
        mask[i] = 0xffff;
        remaining -= 16;
        i += 1;
    }
    if remaining > 0 {
        mask[i] = 0xffff << (16 - remaining);
    }
    Ok(Ipv6Addr::new(
        mask[0], mask[1], mask[2], mask[3], mask[4], mask[5], mask[6], mask[7],
    ))
}

/// Returns the active network interface's gateway addresses,
/// for convenience to user to configure routing table.
pub fn get_active_network_interface_gateways() -> std::io::Result<Vec<IpAddr>> {
    let mut addrs = vec![];
    get_adapters_addresses(|adapter| {
        if adapter.OperStatus == IfOperStatusUp
            && [IF_TYPE_IEEE80211, IF_TYPE_ETHERNET_CSMACD].contains(&adapter.IfType)
        {
            let mut current_gateway = adapter.FirstGatewayAddress;
            while !current_gateway.is_null() {
                let gateway = unsafe { &*current_gateway };
                {
                    let sockaddr_ptr = gateway.Address.lpSockaddr;
                    let sockaddr = unsafe { &*(sockaddr_ptr as *const SOCKADDR) };
                    let a = unsafe { sockaddr_to_socket_addr(sockaddr) }?;
                    addrs.push(a.ip());
                }
                current_gateway = gateway.Next;
            }
        }
        Ok(())
    })?;
    Ok(addrs)
}

pub(crate) fn set_interface_dns_servers(interface: GUID, dns: &[IpAddr]) -> crate::Result<()> {
    // format L"1.1.1.1,8.8.8.8", or L"1.1.1.1 8.8.8.8".
    let dns = dns.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
    let dns = dns.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();

    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as _,
        NameServer: dns.as_ptr() as _,
        Domain: std::ptr::null_mut(),
        SearchList: std::ptr::null_mut(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: std::ptr::null_mut(),
    };

    // The SetInterfaceDnsSettings function was first introduced in Windows 10,
    // to compatible with Windows 7, we use the dynamic loading method to call the function.
    // unsafe { SetInterfaceDnsSettings(interface, &settings as *const _) }

    type TheFn = unsafe extern "system" fn(interface: GUID, settings: *const DNS_INTERFACE_SETTINGS) -> WIN32_ERROR;
    let library = unsafe { ::libloading::Library::new("iphlpapi.dll")? };
    let func: TheFn = unsafe { library.get(b"SetInterfaceDnsSettings\0").map(|sym| *sym)? };
    match unsafe { func(interface, &settings as *const _) } {
        0 => Ok(()),
        e => Err(std::io::Error::from_raw_os_error(e as i32).into()),
    }
}

pub(crate) fn set_adapter_dns_servers(adapter: &str, dns: &[IpAddr]) -> crate::Result<()> {
    if dns.is_empty() {
        return Ok(());
    }
    let ip_str = if dns[0].is_ipv4() { "ipv4" } else { "ipv6" };

    // netsh interface ipv4 set dns name="MyAdapter" source="static" address="8.8.8.8"
    // netsh interface ipv4 add dns name="MyAdapter" index=2 address="8.8.4.4"
    let name = format!("name=\"{}\"", adapter);
    let addr = format!("address=\"{}\"", dns[0]);
    let args = vec!["interface", ip_str, "set", "dns", &name, "source=\"static\"", &addr];
    run_command("netsh", &args)?;
    let mut index = 2;
    for dns in dns.iter().skip(1) {
        let addr = format!("address=\"{}\"", dns);
        let idx = format!("index={}", index);
        let args = vec!["interface", ip_str, "add", "dns", &name, &idx, &addr];
        run_command("netsh", &args)?;
        index += 1;
    }

    Ok(())
}

pub(crate) fn retrieve_ipaddr_from_socket_address(address: &SOCKET_ADDRESS) -> Result<IpAddr, Error> {
    unsafe { Ok(sockaddr_to_socket_addr(address.lpSockaddr)?.ip()) }
}

pub(crate) unsafe fn sockaddr_to_socket_addr(sock_addr: *const SOCKADDR) -> std::io::Result<SocketAddr> {
    use std::io::{Error, ErrorKind};
    let address = match (*sock_addr).sa_family {
        AF_INET => sockaddr_in_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN)),
        AF_INET6 => sockaddr_in6_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN6)),
        _ => return Err(Error::new(ErrorKind::Other, "Unsupported address type")),
    };
    Ok(address)
}

pub(crate) unsafe fn sockaddr_in_to_socket_addr(sockaddr_in: &SOCKADDR_IN) -> SocketAddr {
    let ip_bytes = sockaddr_in.sin_addr.S_un.S_addr.to_ne_bytes();
    let ip = std::net::IpAddr::from(ip_bytes);
    let port = u16::from_be(sockaddr_in.sin_port);
    SocketAddr::new(ip, port)
}

pub(crate) unsafe fn sockaddr_in6_to_socket_addr(sockaddr_in6: &SOCKADDR_IN6) -> SocketAddr {
    let ip = std::net::IpAddr::from(sockaddr_in6.sin6_addr.u.Byte);
    let port = u16::from_be(sockaddr_in6.sin6_port);
    SocketAddr::new(ip, port)
}

pub(crate) fn get_adapters_addresses<F>(mut callback: F) -> Result<(), Error>
where
    F: FnMut(IP_ADAPTER_ADDRESSES_LH) -> Result<(), Error>,
{
    let mut size = 0;
    let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    let family = AF_UNSPEC as u32;

    // Make an initial call to GetAdaptersAddresses to get the
    // size needed into the size variable
    let result = unsafe { GetAdaptersAddresses(family, flags, std::ptr::null_mut(), std::ptr::null_mut(), &mut size) };

    if result != ERROR_BUFFER_OVERFLOW {
        return Err(format!("GetAdaptersAddresses failed: {}", format_message(result)?).into());
    }
    // Allocate memory for the buffer
    let mut addresses: Vec<u8> = vec![0; (size + 4) as usize];

    // Make a second call to GetAdaptersAddresses to get the actual data we want
    let result = unsafe {
        let addr = addresses.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        GetAdaptersAddresses(family, flags, std::ptr::null_mut(), addr, &mut size)
    };

    if ERROR_SUCCESS != result {
        return Err(format!("GetAdaptersAddresses failed: {}", format_message(result)?).into());
    }

    // If successful, output some information from the data we received
    let mut current_addresses = addresses.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current_addresses.is_null() {
        unsafe {
            callback(*current_addresses)?;
            current_addresses = (*current_addresses).Next;
        }
    }
    Ok(())
}

fn get_interface_info_sys<F>(mut callback: F) -> Result<(), Error>
where
    F: FnMut(IP_ADAPTER_INDEX_MAP) -> Result<(), Error>,
{
    let mut buf_len: u32 = 0;
    //First figure out the size of the buffer needed to store the adapter info
    //SAFETY: We are upholding the contract of GetInterfaceInfo. buf_len is a valid pointer to
    //stack memory
    let result = unsafe { GetInterfaceInfo(std::ptr::null_mut(), &mut buf_len as *mut u32) };
    if result != NO_ERROR && result != ERROR_INSUFFICIENT_BUFFER {
        let err_msg = format_message(result).map_err(Error::from)?;
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
        GetInterfaceInfo(
            buf.as_mut_ptr() as *mut IP_INTERFACE_INFO,
            &mut final_buf_len as *mut u32,
        )
    };
    if result != NO_ERROR {
        let err_msg = format_message(result).map_err(Error::from)?;
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
    let info = buf.as_mut_ptr() as *const IP_INTERFACE_INFO;
    //SAFETY:
    // info is a valid, non-null, at least 4 byte aligned pointer obtained from
    // Vec::with_capacity that is readable for up to `buf_len` bytes which is guaranteed to be
    // larger than on IP_INTERFACE_INFO struct as the kernel would never ask for less memory then
    // what it will write. The largest type inside IP_INTERFACE_INFO is a u32 therefore
    // a painter to IP_INTERFACE_INFO requires an alignment of at leant 4 bytes, which
    // Vec<u32>::as_mut_ptr() provides
    let adapter_base = unsafe { &*info };
    let adapter_count = adapter_base.NumAdapters;
    let first_adapter = &adapter_base.Adapter as *const IP_ADAPTER_INDEX_MAP;

    // SAFETY:
    //  1. first_adapter is a valid, non null pointer, aligned to at least 4 byte boundaries
    //     obtained from moving a multiple of 4 offset into the buf given by Vec::with_capacity.
    //  2. We gave GetInterfaceInfo a buffer of at least least `buf_len` bytes to work with and it
    //     succeeded in writing the adapter information within the bounds of that buffer, otherwise
    //     it would've failed. Because the operation succeeded, we know that reading n=NumAdapters
    //     IP_ADAPTER_INDEX_MAP structs stays within the bounds of buf's buffer
    let interfaces = unsafe { std::slice::from_raw_parts(first_adapter, adapter_count as usize) };

    for interface in interfaces {
        callback(*interface)?;
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn get_interface_info() -> Result<Vec<(u32, String)>, Error> {
    let mut v = vec![];
    get_interface_info_sys(|mut interface| {
        let name = unsafe { win_pwstr_to_string(&mut interface.Name as _)? };
        // Nam is something like: \DEVICE\TCPIP_{29C47F55-C7BD-433A-8BF7-408DFD3B3390}
        // where the GUID is the {29C4...90}, separated by dashes
        let guid = name
            .split('{')
            .nth(1)
            .and_then(|s| s.split('}').next())
            .ok_or(format!("Failed to find GUID inside adapter name: {}", name))?;
        v.push((interface.Index, guid.to_string()));
        Ok(())
    })?;
    Ok(v)
}

#[allow(non_snake_case)]
#[inline]
fn MAKELANGID(p: u32, s: u32) -> u32 {
    ((s & 0x0000ffff) << 10) | (p & 0x0000ffff)
}

/// Returns a a human readable error message from a windows error code
pub fn format_message(error_code: u32) -> Result<String, Box<dyn std::error::Error>> {
    let buf: *mut u16 = std::ptr::null_mut();

    let chars_written = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            std::ptr::null_mut(),
            error_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            &buf as *const windows_sys::core::PWSTR as *mut u16,
            0,
            std::ptr::null_mut(),
        )
    };
    if chars_written == 0 {
        return Ok(get_last_error()?);
    }
    let result = unsafe { win_pwstr_to_string(buf)? };
    // Win32 returns the same handle if LocalFree fails.
    if unsafe { !LocalFree(buf as *mut _).is_null() } {
        log::trace!("LocalFree failed: {:?}", get_last_error());
    }

    Ok(result)
}

pub(crate) fn get_last_error() -> std::io::Result<String> {
    get_os_error_from_id(unsafe { GetLastError() as _ })?;
    Ok("No error".to_string())
}

pub(crate) fn get_os_error_from_id(id: i32) -> std::io::Result<()> {
    match id {
        0 => Ok(()),
        e => Err(std::io::Error::from_raw_os_error(e)),
    }
}

pub(crate) fn set_adapter_mtu(name: &str, mtu: usize) -> std::io::Result<()> {
    // command line: `netsh interface ipv4 set subinterface "MyAdapter" mtu=1500 store=persistent`
    let args = &[
        "interface",
        "ipv4",
        "set",
        "subinterface",
        &format!("\"{}\"", name),
        &format!("mtu={}", mtu),
        "store=persistent",
    ];
    run_command("netsh", args)?;
    Ok(())
}

/// Runs a command and returns an error if the command fails, just convenience for users.
#[doc(hidden)]
pub fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

pub(crate) fn get_adapter_mtu(luid: &NET_LUID_LH) -> std::io::Result<usize> {
    unsafe {
        let mut if_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        match GetIfTable2(&mut if_table as *mut *mut _) {
            0 => (),
            e => return Err(std::io::Error::from_raw_os_error(e as i32)),
        }

        let num_entries = (*if_table).NumEntries as usize;
        let mut mtu = None;

        let luid = &luid.Info as *const _ as *const _NET_LUID_LH_INFO;

        let table = &(*if_table).Table as *const MIB_IF_ROW2;
        let table = std::slice::from_raw_parts(table, num_entries);

        for if_row in table {
            let info = &if_row.InterfaceLuid.Info as *const _ as *const _NET_LUID_LH_INFO;

            if (*info).IfType() == (*luid).IfType() && (*info).NetLuidIndex() == (*luid).NetLuidIndex() {
                mtu = Some(if_row.Mtu as usize);
                break;
            }
        }

        // There is no return value for `FreeMibTable`, so we ignore the return value
        FreeMibTable(if_table as *mut _);
        mtu.ok_or(std::io::Error::new(std::io::ErrorKind::NotFound, "Adapter not found"))
    }
}

pub fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}

#[repr(C, align(1))]
#[derive(c2rust_bitfields::BitfieldStruct)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
struct _NET_LUID_LH_INFO {
    #[bitfield(name = "Reserved", ty = "u64", bits = "0..=23")]
    #[bitfield(name = "NetLuidIndex", ty = "u64", bits = "24..=47")]
    #[bitfield(name = "IfType", ty = "u64", bits = "48..=63")]
    _Value: [u8; 8],
}
