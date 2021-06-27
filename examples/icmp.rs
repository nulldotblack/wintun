/// Semi port of WinTun's c example: https://git.zx2c4.com/wintun/tree/example/example.c
use wintun;

use std::fs::File;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use std::{mem::MaybeUninit, ptr};

use winapi::{
    shared::{
        ifdef, netioapi,
        ntdef::{LANG_NEUTRAL, SUBLANG_DEFAULT},
        winerror, ws2def, ws2ipdef,
    },
    um::{errhandlingapi, iphlpapi, iptypes, winbase, winnt::MAKELANGID},
};

use log::*;
use packet::Builder;
use widestring::{U16CStr, U16Str};

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
    unsafe { U16Str::from_ptr(first, chars_written as usize) }.to_string_lossy()
}

fn main() {
    env_logger::init();

    let wintun = wintun::load_from_path("examples/wintun/bin/amd64/wintun.dll")
        .expect("Failed to load wintun dll");

    info!("Listing adapters");
    for adapter in wintun::Adapter::list_all(&wintun, "Wireguard").unwrap() {
        info!(" {} - {}", adapter.name, adapter.luid);
    }

    let adapter = match wintun::Adapter::open(&wintun, "Example", "Demo") {
        Ok(a) => {
            info!("Opened adapter successfully");
            a
        },
        Err(_) => {
            match wintun::Adapter::create(&wintun, "Example", "Demo", None) {
                Ok(a) => {
                    info!("Created adapter successfully! Should reboot: {}", a.reboot_required);
                    a.adapter
                },
                Err(err) => panic!("Failed to open adapter and failed to create adapter. Is process running as admin? Error: {}", err),
            }
        }
    };

    //Add an ip address to the interface
    let luid = adapter.get_luid();
    unsafe {
        let mut row: netioapi::MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        netioapi::InitializeUnicastIpAddressEntry(
            &mut row as *mut netioapi::MIB_UNICASTIPADDRESS_ROW,
        );
        row.InterfaceLuid = std::mem::transmute(luid);
        row.Address.Ipv4_mut().sin_family = ws2def::AF_INET as u16;
        row.Address.Ipv4_mut().sin_addr = std::mem::transmute(u32::from_be_bytes([10, 6, 7, 7]));
        row.OnLinkPrefixLength = 24;
        let result = netioapi::CreateUnicastIpAddressEntry(
            &row as *const netioapi::MIB_UNICASTIPADDRESS_ROW,
        );
        if result != winerror::NO_ERROR && result != winerror::ERROR_OBJECT_ALREADY_EXISTS {
            error!("Failed to set ip address: {}", get_error_message(result));
            return;
        }
    }
    /*
    //Get the ip address of the default gateway so we can re-route all traffic to us, then the
    //gateway
    let gateway = unsafe {
        let flags = iptypes::GAA_FLAG_INCLUDE_GATEWAYS
            //| iptypes::GAA_FLAG_INCLUDE_ALL_INTERFACES
            | iptypes::GAA_FLAG_SKIP_DNS_SERVER
            | iptypes::GAA_FLAG_SKIP_MULTICAST;

        //Get the length first
        let mut buf_len: u32 = 0;
        let result = iphlpapi::GetAdaptersAddresses(
            ws2def::AF_INET as u32,
            flags,
            std::ptr::null_mut(),
            ptr::null_mut(),
            &mut buf_len as *mut u32,
        );
        info!("needed length: {}", buf_len);

        let mut buf = Vec::with_capacity(buf_len as usize);
        buf.resize(buf_len as usize, 0);
        let result = iphlpapi::GetAdaptersAddresses(
            ws2def::AF_INET as u32,
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut iptypes::IP_ADAPTER_ADDRESSES,
            &mut buf_len as *mut u32,
        );
        if result != winerror::NO_ERROR {
            error!(
                "Failed to get adapter info: {}, needed size: {}",
                get_error_message(result),
                buf_len
            );
            return;
        }
        let mut adapter = (buf.as_mut_ptr() as *mut iptypes::IP_ADAPTER_ADDRESSES)
            .as_ref()
            .unwrap();
        while adapter.Next != ptr::null_mut() {
            if adapter.OperStatus == ifdef::IfOperStatusUp {
                info!(
                    "Up Friendly name: {}",
                    U16CStr::from_ptr_str(adapter.FriendlyName).to_string_lossy()
                );
                match adapter.FirstGatewayAddress.as_ref() {
                    Some(mut g) => loop {
                        let addr = g.Address;
                        match addr.lpSockaddr.as_ref() {
                            Some(sock_addr) => {
                                if sock_addr.sa_family == ws2def::AF_INET as u16 {
                                    info!("  Found ipv4 addr, {:?}", sock_addr.sa_data);
                                    let parts: [u8; 4] = std::mem::transmute((addr.lpSockaddr as *mut ws2def::SOCKADDR_IN).as_ref().unwrap().sin_addr);
                                    info!("  {:?}", parts);
                                }
                            }
                            None => {}
                        }
                        if g.Next == ptr::null_mut() {
                            break;
                        }
                        g = g.Next.as_ref().unwrap();
                    },
                    None => {}
                }
            }

            //Unwrap is safe - we already checked that next is non null
            adapter = adapter.Next.as_ref().unwrap();
        }
    };

    let mut routes = Vec::new();

    unsafe {
        let mut row: netioapi::MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        netioapi::InitializeIpForwardEntry(&mut row as *mut netioapi::MIB_IPFORWARD_ROW2);
        row.InterfaceLuid = std::mem::transmute(luid);
        //row.NextHop.
        let result = netioapi::CreateIpForwardEntry2(&row as *const netioapi::MIB_IPFORWARD_ROW2);
        if result != winerror::NO_ERROR {
            error!("Failed to add route: {}", get_error_message(result));
            return;
        }
        routes.push(row);
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
    let reader_session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .expect("Failed to create session"),
    );

    let writer_session = reader_session.clone();

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
                .destination("10.6.7.7".parse().unwrap())
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

    /*for route in routes {
        let result = unsafe {
            netioapi::DeleteIpForwardEntry2(&route as *const netioapi::MIB_IPFORWARD_ROW2)
        };
        if result != winerror::NO_ERROR {
            warn!("Failed to delete ip route: {}", get_error_message(result));
        }
    }*/

    reader.join().unwrap();
    writer.join().unwrap();

    info!("Finished session successfully!");

    adapter.delete(false).unwrap();
}
