extern crate winapi;

use crate::packet;
use crate::wintun_raw;

use winapi::um::synchapi::WaitForSingleObject;

use std::sync::Arc;
use std::{ptr, slice};

pub struct Session {
    pub(crate) session: wintun_raw::WINTUN_SESSION_HANDLE,
    pub(crate) wintun: Arc<wintun_raw::wintun>,
}

impl Session {
    pub fn allocate_send_packet<'a>(&'a self, size: u16) -> Result<packet::Packet, ()> {
        let ptr = unsafe {
            self.wintun
                .WintunAllocateSendPacket(self.session, size as u32)
        };
        if ptr == ptr::null_mut() {
            Err(())
        } else {
            Ok(packet::Packet {
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts(ptr, size as usize) },
                session: self,
                kind: packet::Kind::SendPacketPending,
            })
        }
    }

    pub fn send_packet(&self, mut packet: packet::Packet) {
        assert!(matches!(packet.kind, packet::Kind::SendPacketPending));

        unsafe {
            self.wintun
                .WintunSendPacket(self.session, packet.bytes.as_ptr())
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
                .WintunReceivePacket(self.session, &mut size as *mut u32)
        };

        debug_assert!(size <= u16::MAX as u32);
        if ptr == ptr::null_mut() {
            //Check for ERROR_NO_MORE_ITEMS and return Ok(None)
            Err(())
        } else {
            Ok(Some(packet::Packet {
                kind: packet::Kind::ReceivePacket,
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts(ptr, size as usize) },
                session: self,
            }))
        }
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
        //WaitForSingleObject
        match self.try_receive() {
            Err(err) => Err(err),
            Ok(Some(packet)) => Ok(packet),
            //We still couldn't read a packet after the event was signaled
            Ok(None) => Err(()),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { self.wintun.WintunEndSession(self.session) };
        self.session = ptr::null_mut();
    }
}
