//! This example demonstrates how to use Wintun to create a simple UDP echo server.
//!
//! You can see packets being received by wintun by runnig: `nc -u 10.28.13.100 4321`
//! and sending lines of text.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::channel,
        Arc,
    },
};
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{CryptAcquireContextW, CryptGenRandom, CryptReleaseContext, PROV_RSA_FULL},
};
mod misc;

#[derive(Debug)]
struct NaiveUdpPacket {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    data: Vec<u8>,
}

impl NaiveUdpPacket {
    fn new(src_addr: SocketAddr, dst_addr: SocketAddr, data: &[u8]) -> Self {
        Self {
            src_addr,
            dst_addr,
            data: data.to_vec(),
        }
    }
}

impl std::fmt::Display for NaiveUdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "src=\"{}\", dst=\"{}\", data length {}",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // Loading wintun
    let dll_path = misc::get_wintun_bin_relative_path()?;
    let wintun = unsafe { wintun::load_from_path(dll_path)? };

    let version = wintun::get_running_driver_version(&wintun);
    println!("Wintun version: {:?}", version);

    let adapter_name = "Demo";
    let guid = 2131231231231231231_u128;

    // Open or create a new adapter
    let adapter = match wintun::Adapter::open(&wintun, adapter_name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, adapter_name, "MyTunnelType", Some(guid))?,
    };

    let version = wintun::get_running_driver_version(&wintun)?;
    println!("Wintun version: {}", version);

    // set metric command: `netsh interface ipv4 set interface adapter_name metric=255`
    let args = &["interface", "ipv4", "set", "interface", adapter_name, "metric=255"];
    wintun::run_command("netsh", args)?;
    println!("netsh {}", args.join(" "));

    // Execute the network card initialization command, setting virtual network card information
    // ip = 10.28.13.2 mask = 255.255.255.0 gateway = 10.28.13.1
    // command: `netsh interface ipv4 set address adapter_name static 10.28.13.2/24 gateway=10.28.13.1`
    let args = &[
        "interface",
        "ipv4",
        "set",
        "address",
        adapter_name,
        "static",
        "10.28.13.2/24",
        "gateway=10.28.13.1",
    ];
    wintun::run_command("netsh", args)?;
    println!("netsh {}", args.join(" "));

    let dns = "8.8.8.8".parse::<IpAddr>().unwrap();
    let dns2 = "8.8.4.4".parse::<IpAddr>().unwrap();
    adapter.set_dns_servers(&[dns, dns2])?;

    let v = adapter.get_addresses()?;
    for addr in &v {
        let mask = adapter.get_netmask_of_address(addr)?;
        println!("address {} netmask: {}", addr, mask);
    }

    let gateways = adapter.get_gateways()?;
    println!("adapter gateways: {gateways:?}");

    // adapter.set_name("MyNewName")?;
    // println!("adapter name: {}", adapter.get_name()?);

    // adapter.set_address("10.28.13.2".parse()?)?;

    println!("adapter mtu: {}", adapter.get_mtu()?);

    println!(
        "active adapter gateways: {:?}",
        wintun::get_active_network_interface_gateways()?
    );

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    let reader_session = session.clone();
    let writer_session = session.clone();

    let (tx, rx) = channel::<NaiveUdpPacket>();

    // Global flag to stop the session
    static RUNNING: AtomicBool = AtomicBool::new(true);

    let reader = std::thread::spawn(move || {
        let block = || {
            while RUNNING.load(Ordering::Relaxed) {
                let packet = reader_session.receive_blocking()?;
                // recieved IP packet
                let bytes = packet.bytes();

                let udp_packet = extract_udp_packet(bytes);
                if let Err(err) = udp_packet {
                    println!("{}", err);
                    continue;
                }

                // swap src and dst
                let mut udp_packet = udp_packet?;
                let src_addr = udp_packet.src_addr;
                let dst_addr = udp_packet.dst_addr;
                udp_packet.src_addr = dst_addr;
                udp_packet.dst_addr = src_addr;

                // send to writer
                tx.send(udp_packet)?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        if let Err(err) = block() {
            println!("Reader {}", err);
        }
    });

    let writer = std::thread::spawn(move || {
        let block = || {
            while RUNNING.load(Ordering::Relaxed) {
                let resp = rx.recv()?;

                let src_addr = match resp.src_addr.ip() {
                    IpAddr::V4(addr) => addr,
                    IpAddr::V6(_) => return Err("IPv6 addresses are not supported".into()),
                };

                let dst_addr = match resp.dst_addr.ip() {
                    IpAddr::V4(addr) => addr,
                    IpAddr::V6(_) => return Err("IPv6 addresses are not supported".into()),
                };

                let v = generate_random_bytes(2)?;
                let id = u16::from_ne_bytes([v[0], v[1]]);

                // build response IP packet
                use packet::Builder;
                let ip_packet = packet::ip::v4::Builder::default()
                    .id(id)?
                    .ttl(64)?
                    .source(src_addr)?
                    .destination(dst_addr)?
                    .udp()?
                    .source(resp.src_addr.port())?
                    .destination(resp.dst_addr.port())?
                    .payload(&resp.data)?
                    .build()?;

                // // The following code will be better than above, the `ipv4_udp_build` function link is
                // //
                // // https://github.com/pysrc/study-udp/blob/59d7ba210a022d207c60ad5370de37110fefaefb/src/protocol.rs#L157-L252
                // //
                // let mut ip_packet = vec![0u8; 28 + resp.data.len()];
                // protocol::ipv4_udp_build(
                //     &mut ip_packet,
                //     &src_addr.octets(),
                //     resp.src_addr.port(),
                //     &dst_addr.octets(),
                //     resp.dst_addr.port(),
                //     &resp.data,
                // );

                let mut write_pack = writer_session.allocate_send_packet(ip_packet.len() as u16)?;
                write_pack.bytes_mut().copy_from_slice(ip_packet.as_ref());

                // Send the response packet
                writer_session.send_packet(write_pack);
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        if let Err(err) = block() {
            println!("Writer {}", err);
        }
    });

    println!("Press enter to stop session");

    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    println!("Shutting down session");
    RUNNING.store(false, Ordering::Relaxed);
    session.shutdown()?;
    let _ = reader.join();
    let _ = writer.join();
    Ok(())
}

fn extract_udp_packet(packet: &[u8]) -> Result<NaiveUdpPacket, wintun::Error> {
    use packet::{ip, udp, AsPacket, Packet};
    let packet: ip::Packet<_> = packet.as_packet().map_err(|err| format!("{}", err))?;
    let info: String;
    match packet {
        ip::Packet::V4(a) => {
            let src_addr = a.source();
            let dst_addr = a.destination();
            let protocol = a.protocol();
            let payload = a.payload();
            match protocol {
                ip::Protocol::Udp => {
                    let udp = udp::Packet::new(payload).map_err(|err| format!("{}", err))?;
                    let src_port = udp.source();
                    let dst_port = udp.destination();
                    let src_addr = SocketAddr::new(src_addr.into(), src_port);
                    let dst_addr = SocketAddr::new(dst_addr.into(), dst_port);
                    let data = udp.payload();
                    let udp_packet = NaiveUdpPacket::new(src_addr, dst_addr, data);
                    log::trace!("{protocol:?} {}", udp_packet);
                    return Ok(udp_packet);
                }
                _ => {
                    info = format!("{:?} src={}, dst={}", protocol, src_addr, dst_addr);
                }
            }
        }
        ip::Packet::V6(a) => {
            info = format!("{:?}", a);
        }
    }
    Err(info.into())
}

fn generate_random_bytes(len: usize) -> Result<Vec<u8>, windows::core::Error> {
    let mut buf = vec![0u8; len];
    unsafe {
        let mut h_prov = 0_usize;
        let null = PCWSTR::null();
        CryptAcquireContextW(&mut h_prov, null, null, PROV_RSA_FULL, 0)?;
        CryptGenRandom(h_prov, &mut buf)?;
        CryptReleaseContext(h_prov, 0)?;
    };
    Ok(buf)
}
