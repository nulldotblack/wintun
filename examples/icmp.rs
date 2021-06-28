/// Semi port of WinTun's c example: https://git.zx2c4.com/wintun/tree/example/example.c
use wintun;

use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{mem::MaybeUninit, ptr};

use winapi::shared::ipmib;
use winapi::um::ipexport;
use winapi::{
    shared::{
        ifdef, netioapi, nldef,
        ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT},
        winerror, ws2def, ws2ipdef,
    },
    um::{errhandlingapi, iphlpapi, iptypes, winbase, winnt::MAKELANGID},
};

use log::*;
use packet::Builder;
use widestring::U16Str;

static RUNNING: AtomicBool = AtomicBool::new(true);

fn get_error_message(err_code: u32) -> String {
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

/// Converts a rust ip addr to a SOCKADDR_INET
fn ip_addr_to_win_addr(addr: IpAddr) -> ws2ipdef::SOCKADDR_INET {
    let mut result: ws2ipdef::SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match addr {
        IpAddr::V4(v4) => {
            *unsafe { result.si_family_mut() } = ws2def::AF_INET as u16;
            unsafe { result.Ipv4_mut().sin_addr = std::mem::transmute(v4.octets()) };
        }
        IpAddr::V6(v6) => {
            *unsafe { result.si_family_mut() } = ws2def::AF_INET6 as u16;
            unsafe { result.Ipv6_mut().sin6_addr = std::mem::transmute(v6.segments()) };
        }
    }

    result
}

fn main() {
    env_logger::init();

    let wintun = wintun::load_from_path("examples/wintun/bin/amd64/wintun.dll")
        .expect("Failed to load wintun dll");

    info!("Listing adapters");
    for adapter in wintun::Adapter::list_all(&wintun, "Wireguard").unwrap() {
        info!(" {} - {}", adapter.name, adapter.luid);
    }

    let adapter =
        match wintun::Adapter::open(&wintun, "Example", "Demo") {
            Ok(a) => {
                info!("Opened adapter successfully");
                a
            }
            Err(_) => {
                match wintun::Adapter::create(&wintun, "Example", "Demo", None) {
                Ok(d) => {
                    info!("Created adapter successfully! Should reboot: {}", d.reboot_required);
                    d.adapter
                },
                Err(err) => panic!("Failed to open adapter and failed to create adapter. Is process running as admin? Error: {}", err),
            }
            }
        };
    let interface_address: IpAddr = "10.6.7.7".parse().unwrap();

    //Add an ip address to the interface
    let luid = adapter.get_luid();
    unsafe {
        let mut row: netioapi::MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        netioapi::InitializeUnicastIpAddressEntry(
            &mut row as *mut netioapi::MIB_UNICASTIPADDRESS_ROW,
        );
        row.InterfaceLuid = std::mem::transmute(luid);
        row.Address = ip_addr_to_win_addr(interface_address);
        row.OnLinkPrefixLength = 24;
        let result = netioapi::CreateUnicastIpAddressEntry(
            &row as *const netioapi::MIB_UNICASTIPADDRESS_ROW,
        );
        if result != winerror::NO_ERROR && result != winerror::ERROR_OBJECT_ALREADY_EXISTS {
            error!("Failed to set ip address: {}", get_error_message(result));
            return;
        }
    }
    //Get the ip address of the default gateway so we can re-route all traffic to us, then the
    //gateway
    let gateway = unsafe {
        let mut row: ipmib::MIB_IPFORWARDROW = std::mem::zeroed();
        let result = iphlpapi::GetBestRoute(
            u32::from_be_bytes([1, 1, 1, 1]),
            0,
            &mut row as *mut ipmib::MIB_IPFORWARDROW,
        );
        if result != winerror::NO_ERROR {
            error!("Failed to get best route: {}", get_error_message(result));
            return;
        }
        trace!("Route: {:?}", row.dwForwardDest.to_ne_bytes());
        trace!("Mask: {:?}", row.dwForwardMask.to_ne_bytes());
        trace!("Policy: {:?}", row.dwForwardPolicy);
        trace!("NextHop: {:?}", row.dwForwardNextHop.to_ne_bytes());
        let gateway_bytes = row.dwForwardNextHop.to_ne_bytes();
        if gateway_bytes == [0, 0, 0, 0] {
            warn!("Gateway is 0.0.0.0. This may cause problems.");
            warn!("Usually it is something like 192.168.0.1");
            warn!("Is another VPN connection active?");
        }
        IpAddr::V4(gateway_bytes.into())
    };
    info!("Gateway is: {}", gateway);

    let wintun_adapter_index = adapter.get_adapter_index().expect("Failed to get adapter index");
    info!("Index is {}", wintun_adapter_index);

    /*
    let mut routes = Vec::new();
    unsafe {
        info!("Using luid: {}", luid);
        let mut row: netioapi::MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        netioapi::InitializeIpForwardEntry(&mut row as *mut netioapi::MIB_IPFORWARD_ROW2);
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;
        row.Protocol = nldef::MIB_IPPROTO_NETMGMT;
        row.Metric = 0; //Highest priority
        row.DestinationPrefix.Prefix = ip_addr_to_win_addr(interface_address);
        row.DestinationPrefix.PrefixLength = 24;
        row.InterfaceLuid = std::mem::transmute(luid);
        row.NextHop = ip_addr_to_win_addr(gateway);
        routes.push(row);
    }
    for route in &routes {
        let result = unsafe {
            netioapi::CreateIpForwardEntry2(route as *const netioapi::MIB_IPFORWARD_ROW2)
        };
        if result != winerror::NO_ERROR {
            error!("Failed to add route: {}", get_error_message(result));
            return;
        }
    }*/

    let file = File::create("out.pcap").unwrap();

    let header = pcap_file::pcap::PcapHeader {
        magic_number: 0xa1b2c3d4,
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: pcap_file::DataLink::RAW,
    };
    let mut writer = pcap_file::PcapWriter::with_header(header, file).unwrap();
    let main_session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .expect("Failed to create session"),
    );

    let reader_session = main_session.clone();
    let writer_session = main_session.clone();

    let reader = std::thread::spawn(move || {
        info!("Starting reader");
        while RUNNING.load(Ordering::Relaxed) {
            match reader_session.receive_blocking() {
                Ok(mut packet) => {
                    let bytes = packet.bytes_mut();
                    writer.write(1, 0, bytes, bytes.len() as u32).unwrap();
                    if bytes.len() < 20 {
                        info!("Got packet without room for an ip header: {:?}", bytes);
                    } else {
                        info!("Read {} bytes", bytes.len());
                        let ipv4 = match packet::ip::v4::Packet::new(bytes) {
                            Ok(p) => p,
                            Err(err) => {
                                warn!("Got bad packet: {}", err);
                                continue;
                            }
                        };
                        info!("got packet: {:?}", ipv4);
                    }
                }
                Err(err) => {
                    error!("Got error while reading: {:?}", err);
                    break;
                }
            }
        }
    });
    let writer = std::thread::spawn(move || {
        info!("Starting writer");

        let v4_dest = match interface_address {
            IpAddr::V4(v4) => v4,
            _ => panic!("Address must be ipv4"),
        };
        while RUNNING.load(Ordering::Relaxed) {
            let mut packet = writer_session.allocate_send_packet(28).unwrap();
            let buf = packet::buffer::Slice::new(packet.as_mut());

            let ipv4 = packet::ip::v4::Builder::with(buf)
                .unwrap()
                .id(0x2d87)
                .unwrap()
                .ttl(64)
                .unwrap()
                .source("10.6.7.8".parse().unwrap())
                .unwrap()
                .destination(v4_dest)
                .unwrap()
                .icmp()
                .unwrap()
                .echo()
                .unwrap()
                .request()
                .unwrap()
                .identifier(42)
                .unwrap()
                .sequence(2)
                .unwrap()
                .build()
                .unwrap();

            info!("Sent {} bytes", ipv4.len());
            writer_session.send_packet(packet);
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });

    println!("Press enter to stop example");

    let mut string = String::new();
    let _ = std::io::stdin().read_line(&mut string);
    RUNNING.store(false, Ordering::Relaxed);

    info!("Stopping session");
    main_session.shutdown();

    reader.join().unwrap();
    writer.join().unwrap();

    info!("Finished session successfully!");

    adapter.delete(false).unwrap();
}
