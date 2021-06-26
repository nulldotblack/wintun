use crate::session;
use log::*;

pub(crate) enum Kind {
    SendPacketPending, //Send packet type, but not sent yet
    SendPacketSent,    //Send packet type - sent
    ReceivePacket,
}

pub struct Packet<'a> {
    pub(crate) kind: Kind,
    pub(crate) bytes: &'a mut [u8],
    pub(crate) session: &'a session::Session,
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'a> AsMut<[u8]> for Packet<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<'a> Drop for Packet<'a> {
    fn drop(&mut self) {
        trace!("dropping");
        match self.kind {
            Kind::ReceivePacket => {
                unsafe {
                    self.session
                        .wintun
                        .WintunReleaseReceivePacket(self.session.session.0, self.bytes.as_ptr())
                };
            }
            Kind::SendPacketPending => {
                //If someone allocates a packet with session.allocate_send_packet() and then it is
                //dropped without being sent, this will hold up the send queue because wintun expects
                //that every allocated packet is sent
                panic!("Packet was never sent!");
            }
            Kind::SendPacketSent => {
                //Nop
            }
        }
    }
}
