//! Safe rust idiomatic bindings for the Wintun C library: <https://wintun.net>
//!
//! All features of the Wintun library are wrapped using pure rust types and functions to make
//! usage feel ergonomic.  
//!
//! # Usage
//!
//! Inside your code load the wintun.dll signed driver file, downloaded from <https://wintun.net>,
//! using [`load`], [`load_from_path`] or [`load_from_library`].
//!
//! Then either call [`Adapter::create`] or [`Adapter::open`] to obtain a wintun
//! adapter. Start a session with [`Adapter::start_session`].
//!
//! # Example
//! ```no_run
//! use std::sync::Arc;
//!
//! //Must be run as Administrator because we create network adapters
//! //Load the wintun dll file so that we can call the underlying C functions
//! //Unsafe because we are loading an arbitrary dll file
//! let wintun = unsafe { wintun::load_from_path("path/to/wintun.dll") }
//!     .expect("Failed to load wintun dll");
//!
//! //Try to open an adapter with the name "Demo"
//! let adapter = match wintun::Adapter::open(&wintun, "Demo") {
//!     Ok(a) => a,
//!     Err(_) => {
//!         //If loading failed (most likely it didn't exist), create a new one
//!         wintun::Adapter::create(&wintun, "Demo", "Example", None)
//!             .expect("Failed to create wintun adapter!")
//!     }
//! };
//! //Specify the size of the ring buffer the wintun driver should use.
//! let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
//!
//! //Get a 20 byte packet from the ring buffer
//! let mut packet = session.allocate_send_packet(20).unwrap();
//! let bytes: &mut [u8] = packet.bytes_mut();
//! //Write IPV4 version and header length
//! bytes[0] = 0x40;
//!
//! //Finish writing IP header
//! bytes[9] = 0x69;
//! bytes[10] = 0x04;
//! bytes[11] = 0x20;
//! //...
//!
//! //Send the packet to wintun virtual adapter for processing by the system
//! session.send_packet(packet);
//!
//! //Stop any readers blocking for data on other threads
//! //Only needed when a blocking reader is preventing shutdown Ie. it holds an Arc to the
//! //session, blocking it from being dropped
//! session.shutdown();
//!
//! //the session is stopped on drop
//! //drop(session);
//!
//! //drop(adapter)
//! //And the adapter closes its resources when dropped
//! ```
//!    
//! See `examples/wireshark.rs` for a more complete example that writes received packets to a pcap
//! file.
//!
//! # Features
//!
//! - `panic_on_unsent_packets`: Panics if a send packet is dropped without being sent. Useful for
//! debugging packet issues because unsent packets that are dropped without being sent hold up
//! wintun's internal ring buffer.
//!
//! # TODO:
//! - Add async support
//! Requires hooking into a windows specific reactor and registering read interest on wintun's read
//! handle. Asyncify other slow operations via tokio::spawn_blocking. As always, PR's are welcome!
//!

mod adapter;
mod error;
mod log;
mod packet;
mod session;
mod util;

//Generated by bingen
#[allow(
    non_snake_case,
    dead_code,
    unused_variables,
    non_camel_case_types,
    deref_nullptr,
    clippy::all
)]
mod wintun_raw;

pub use crate::{
    adapter::Adapter,
    error::{Error, OutOfRangeData, Result},
    log::{default_logger, reset_logger, set_logger},
    packet::Packet,
    session::Session,
    util::{format_message, get_active_network_interface_gateways, run_command},
};
pub use windows_sys::Win32::{Foundation::HANDLE, NetworkManagement::Ndis::NET_LUID_LH};

// TODO: Get bindgen to scrape these from the `wintun.h`
// We need to make sure these stay up to date
/// The maximum size of wintun's internal ring buffer (in bytes)
pub const MAX_RING_CAPACITY: u32 = 0x400_0000;

/// The minimum size of wintun's internal ring buffer (in bytes)
pub const MIN_RING_CAPACITY: u32 = 0x2_0000;

/// Maximum pool name length including zero terminator
pub const MAX_POOL: usize = 256;

pub type Wintun = Arc<wintun_raw::wintun>;

use std::sync::Arc;

/// Attempts to load the Wintun library from the current directory using the default name "wintun.dll".
///
/// Use [`load_from_path`] with an absolute path when more control is needed as to where wintun.dll is
///
///
/// # Safety
/// This function loads a dll file with the name wintun.dll using the default system search paths.
/// This is inherently unsafe as a user could simply rename undefined_behavior.dll to wintun.dll
/// and do nefarious things inside of its DllMain function. In most cases, a regular wintun.dll
/// file which exports all of the required functions for these bindings to work is loaded. Because
/// WinTun is a well-written and well-tested library, loading a _normal_ wintun.dll file should be safe.
/// Hoverer one can never be too cautious when loading a dll file.
///
/// For more information see [`libloading`]'s dynamic library safety guarantees: [`libloading`][`libloading::Library::new`]
pub unsafe fn load() -> Result<Wintun, Error> {
    load_from_path("wintun")
}

/// Attempts to load the Wintun library as a dynamic library from the given path.
///
///
/// # Safety
/// This function loads a dll file with the path provided.
/// This is inherently unsafe as a user could simply rename undefined_behavior.dll to wintun.dll
/// and do nefarious things inside of its DllMain function. In most cases, a regular wintun.dll
/// file which exports all of the required functions for these bindings to work is loaded. Because
/// WinTun is a well-written and well-tested library, loading a _normal_ wintun.dll file should be safe.
/// Hoverer one can never be too cautious when loading a dll file.
///
/// For more information see [`libloading`]'s dynamic library safety guarantees: [`libloading`][`libloading::Library::new`]
pub unsafe fn load_from_path<P>(path: P) -> Result<Wintun, Error>
where
    P: AsRef<::std::ffi::OsStr>,
{
    unsafe { Ok(Arc::new(wintun_raw::wintun::new(path)?)) }
}

/// Attempts to load the Wintun library from an existing [`libloading::Library`].
///
///
/// # Safety
/// This function loads the required WinTun functions using the provided library. Reading a symbol table
/// of a dynamic library and transmuting the function pointers inside to have the parameters and return
/// values expected by the functions documented at: <https://git.zx2c4.com/wintun/about/#reference>
/// is inherently unsafe.
///
/// For more information see [`libloading`]'s dynamic library safety guarantees: [`libloading::Library::new`]
pub unsafe fn load_from_library<L>(library: L) -> Result<Wintun, Error>
where
    L: Into<libloading::Library>,
{
    unsafe { Ok(Arc::new(wintun_raw::wintun::from_library(library)?)) }
}

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
pub fn get_running_driver_version(wintun: &Wintun) -> Result<Version> {
    let version = unsafe { wintun.WintunGetRunningDriverVersion() };
    if version == 0 {
        Err(util::get_last_error()?.into())
    } else {
        let v = version.to_be_bytes();
        Ok(Version {
            major: u16::from_be_bytes([v[0], v[1]]),
            minor: u16::from_be_bytes([v[2], v[3]]),
        })
    }
}
