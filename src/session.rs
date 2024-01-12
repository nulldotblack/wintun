use crate::{
    packet,
    util::{self, UnsafeHandle},
    wintun_raw, Adapter, Error, Wintun,
};
use std::{ptr, slice, sync::Arc, sync::OnceLock};
use windows::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_NO_MORE_ITEMS, FALSE, HANDLE, WAIT_EVENT, WAIT_FAILED, WAIT_OBJECT_0,
    },
    System::Threading::{SetEvent, WaitForMultipleObjects, INFINITE},
};

/// Wrapper around a <https://git.zx2c4.com/wintun/about/#wintun_session_handle>
pub struct Session {
    /// The session handle given to us by WintunStartSession
    pub(crate) session: UnsafeHandle<wintun_raw::WINTUN_SESSION_HANDLE>,

    /// Shared dll for required wintun driver functions
    pub(crate) wintun: Wintun,

    /// Windows event handle that is signaled by the wintun driver when data becomes available to
    /// read
    pub(crate) read_event: OnceLock<HANDLE>,

    /// Windows event handle that is signaled when [`Session::shutdown`] is called force blocking
    /// readers to exit
    pub(crate) shutdown_event: HANDLE,

    /// The adapter that owns this session
    pub(crate) adapter: Arc<Adapter>,
}

impl Session {
    pub fn get_adapter(&self) -> Arc<Adapter> {
        self.adapter.clone()
    }

    /// Allocates a send packet of the specified size. Wraps WintunAllocateSendPacket
    ///
    /// All packets returned from this function must be sent using [`Session::send_packet`] because
    /// wintun establishes the send packet order based on the invocation order of this function.
    /// Therefore if a packet is allocated using this function, and then never sent, it will hold
    /// up the send queue for all other packets allocated in the future. It is okay for the session
    /// to shutdown with allocated packets that have not yet been sent
    pub fn allocate_send_packet(self: &Arc<Self>, size: u16) -> Result<packet::Packet, Error> {
        let ptr = unsafe { self.wintun.WintunAllocateSendPacket(self.session.0, size as u32) };
        if ptr.is_null() {
            Err(Error::from(util::get_last_error()))
        } else {
            Ok(packet::Packet {
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts_mut(ptr, size as usize) },
                session: self.clone(),
                kind: packet::Kind::SendPacketPending,
            })
        }
    }

    /// Sends a packet previously allocated with [`Session::allocate_send_packet`]
    pub fn send_packet(&self, mut packet: packet::Packet) {
        assert!(matches!(packet.kind, packet::Kind::SendPacketPending));

        unsafe { self.wintun.WintunSendPacket(self.session.0, packet.bytes.as_ptr()) };
        //Mark the packet at sent
        packet.kind = packet::Kind::SendPacketSent;
    }

    /// Attempts to receive a packet from the virtual interface without blocking.
    /// If there are no packets currently in the receive queue, this function returns Ok(None)
    /// without blocking. If blocking until a packet is desirable, use [`Session::receive_blocking`]
    pub fn try_receive(self: &Arc<Self>) -> Result<Option<packet::Packet>, Error> {
        let mut size = 0u32;

        let ptr = unsafe { self.wintun.WintunReceivePacket(self.session.0, &mut size as *mut u32) };

        debug_assert!(size <= u16::MAX as u32);
        if ptr.is_null() {
            //Wintun returns ERROR_NO_MORE_ITEMS instead of blocking if packets are not available
            if let Err(last_error) = unsafe { GetLastError() } {
                if last_error.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                    Ok(None)
                } else {
                    Err(last_error.into())
                }
            } else {
                Err("Unknow error".into())
            }
        } else {
            Ok(Some(packet::Packet {
                kind: packet::Kind::ReceivePacket,
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts_mut(ptr, size as usize) },
                session: self.clone(),
            }))
        }
    }

    /// Returns the low level read event handle that is signaled when more data becomes available
    /// to read
    pub fn get_read_wait_event(&self) -> Result<HANDLE, Error> {
        Ok(*self
            .read_event
            .get_or_init(|| unsafe { HANDLE(self.wintun.WintunGetReadWaitEvent(self.session.0) as _) }))
    }

    /// Blocks until a packet is available, returning the next packet in the receive queue once this happens.
    /// If the session is closed via [`Session::shutdown`] all threads currently blocking inside this function
    /// will return Err(())
    pub fn receive_blocking(self: &Arc<Self>) -> Result<packet::Packet, Error> {
        loop {
            //Try 5 times to receive without blocking so we don't have to issue a syscall to wait
            //for the event if packets are being received at a rapid rate
            for _ in 0..5 {
                match self.try_receive() {
                    Err(err) => return Err(err),
                    Ok(Some(packet)) => return Ok(packet),
                    Ok(None) => {
                        //Try again
                        continue;
                    }
                }
            }
            //Wait on both the read handle and the shutdown handle so that we stop when requested
            let handles = [self.get_read_wait_event()?, self.shutdown_event];
            let result = unsafe {
                //SAFETY: We abide by the requirements of WaitForMultipleObjects, handles is a
                //pointer to valid, aligned, stack memory
                WaitForMultipleObjects(&handles, FALSE, INFINITE)
            };
            const WAIT_OBJECT_1: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);
            match result {
                WAIT_FAILED => return Err(Error::from(util::get_last_error())),
                WAIT_OBJECT_0 => {
                    //We have data!
                    continue;
                }
                WAIT_OBJECT_1 => {
                    //Shutdown event triggered
                    return Err(Error::ShuttingDown);
                }
                _ => {
                    //This should never happen
                    panic!("WaitForMultipleObjects returned unexpected value {:?}", result);
                }
            }
        }
    }

    /// Cancels any active calls to [`Session::receive_blocking`] making them instantly return Err(_) so that session can be shutdown cleanly
    pub fn shutdown(&self) -> Result<(), Error> {
        unsafe { SetEvent(self.shutdown_event)? };
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(err) = unsafe { CloseHandle(self.shutdown_event) } {
            log::error!("Failed to close handle of shutdown event: {:?}", err);
        }

        unsafe { self.wintun.WintunEndSession(self.session.0) };
        self.session.0 = ptr::null_mut();
    }
}
