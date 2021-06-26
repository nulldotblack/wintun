extern crate winapi;

use crate::packet;
use crate::wintun_raw;

use once_cell::sync::OnceCell;

use winapi::shared::winerror;
use winapi::shared::winerror::ERROR_NO_MORE_ITEMS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase;
use winapi::um::winnt;

use log::*;

use std::sync::Arc;
use std::{ptr, slice};

pub(crate) struct UnsafeHandle<T>(pub T);

/// We never read from the pointer. It only serves as a handle we pass to the kernel or C code that
/// doesn't have the same mutable aliasing restrictions we have in Rust
unsafe impl<T> Send for UnsafeHandle<T> {}
unsafe impl<T> Sync for UnsafeHandle<T> {}

pub struct Session {
    pub(crate) session: UnsafeHandle<wintun_raw::WINTUN_SESSION_HANDLE>,
    pub(crate) wintun: Arc<wintun_raw::wintun>,
    pub(crate) read_event: OnceCell<UnsafeHandle<winnt::HANDLE>>,
}

impl Session {
    pub fn allocate_send_packet<'a>(&'a self, size: u16) -> Result<packet::Packet, ()> {
        let ptr = unsafe {
            self.wintun
                .WintunAllocateSendPacket(self.session.0, size as u32)
        };
        if ptr == ptr::null_mut() {
            Err(())
        } else {
            Ok(packet::Packet {
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts_mut(ptr, size as usize) },
                session: self,
                kind: packet::Kind::SendPacketPending,
            })
        }
    }

    pub fn send_packet(&self, mut packet: packet::Packet) {
        assert!(matches!(packet.kind, packet::Kind::SendPacketPending));

        unsafe {
            self.wintun
                .WintunSendPacket(self.session.0, packet.bytes.as_ptr())
        };
        //Mark the packet at sent
        packet.kind = packet::Kind::SendPacketSent;
    }

    /// Attempts to receive a packet from the virtual interface.
    /// If there are no queued packets to receive then this function returns Ok(None)
    pub fn try_receive<'a>(&'a self) -> Result<Option<packet::Packet>, ()> {
        let mut size = 0u32;

        let ptr = unsafe {
            self.wintun
                .WintunReceivePacket(self.session.0, &mut size as *mut u32)
        };

        debug_assert!(size <= u16::MAX as u32);
        if ptr == ptr::null_mut() {
            //Wintun returns ERROR_NO_MORE_ITEMS instead of blocking if packets are not available
            let last_error = unsafe { GetLastError() };
            if last_error == ERROR_NO_MORE_ITEMS {
                trace!("Got no more items");
                Ok(None)
            } else {
                trace!("Got error: {}", last_error);
                Err(())
            }
        } else {
            info!("Got packet length {}", size);
            Ok(Some(packet::Packet {
                kind: packet::Kind::ReceivePacket,
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts_mut(ptr, size as usize) },
                session: self,
            }))
        }
    }

    pub fn get_read_wait_event(&self) -> Result<winnt::HANDLE, ()> {
        Ok(self
            .read_event
            .get_or_init(|| unsafe {
                info!("Getting read wait event!");
                UnsafeHandle(self.wintun.WintunGetReadWaitEvent(self.session.0) as winnt::HANDLE)
            })
            .0)
    }

    pub fn receive_blocking<'a>(&'a self) -> Result<packet::Packet, ()> {
        //Try 5 times to receive without blocking
        for _ in 0..5 {
            match self.try_receive() {
                Err(err) => return Err(err),
                Ok(Some(packet)) => return Ok(packet),
                Ok(None) => {}
            }
        }
        let result = unsafe { WaitForSingleObject(self.get_read_wait_event()?, winbase::INFINITE) };
        match result {
            winbase::WAIT_ABANDONED => Err(()),
            winerror::WAIT_TIMEOUT => Err(()),
            winbase::WAIT_FAILED => Err(()),
            winbase::WAIT_OBJECT_0 => {
                info!("Wait for single object completed successfully");
                match self.try_receive() {
                    Err(err) => Err(err),
                    Ok(Some(packet)) => Ok(packet),
                    //We still couldn't read a packet after the event was signaled
                    Ok(None) => Err(()),
                }
            }
            _ => panic!("WaitForSingleObject returned unknown result: {}", result),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        trace!("dropping");
        unsafe { self.wintun.WintunEndSession(self.session.0) };
        self.session.0 = ptr::null_mut();
    }
}
