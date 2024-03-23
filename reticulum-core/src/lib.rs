use hex::DisplayHex;
use std::io::Write;
use std::net::TcpStream;

pub use ed25519_dalek;
pub use rmp;
pub use x25519_dalek;

pub mod announce;
pub mod context;
pub mod destination;
pub mod encode;
mod fernet;
pub mod hdlc;
pub mod identity;
pub mod interface;
pub mod link;
pub mod packet;
pub mod parse;
pub mod path_request;
pub mod sign;

use announce::Announce;
use context::{Context, RnsContext};
use encode::Encode;
use hdlc::Hdlc;
use interface::Interface;
use link::Link;
use packet::Packet;
use path_request::PathRequest;

pub trait OnPacket<I: Interface, C: Context> {
    fn on_packet(&self, packet: &Packet<I, C>) {
        let _ = packet;
    }

    fn on_announce(&self, announce: &Announce) {
        let _ = announce;
    }

    fn on_path_request(&self, path_request: &PathRequest) {
        let _ = path_request;
    }

    fn on_link_established(&self, link: &Link) {
        let _ = link;
    }

    fn on_link_message(&self, link: &Link, message: &[u8]) {
        let _ = message;
        let _ = link;
    }
}

pub trait OnSend<I: Interface, C: Context> {
    fn send(&mut self, packet: &Packet<I, C>);
}

#[derive(Debug)]
pub struct TestInf;
impl Interface for TestInf {
    const LENGTH: usize = 2;
}

pub struct TcpSend(pub Hdlc<TcpStream>);

impl OnSend<TestInf, RnsContext> for TcpSend {
    fn send(&mut self, packet: &Packet<TestInf, RnsContext>) {
        let mut out = Vec::new();
        let _ = &packet.encode(&mut out);

        log::trace!("OUT: {}", out.as_hex());

        let _ = self.0.write(&out).expect("successfully written bytes");
        self.0.flush().expect("successfully flushed");
    }
}

pub struct PrintPackets;

impl OnPacket<TestInf, RnsContext> for PrintPackets {
    fn on_packet(&self, packet: &Packet<TestInf, RnsContext>) {
        log::debug!(
            "Packet: {:?}/{:?}/{:?}/{:?}/{:?}/{} {} {:?}",
            packet.header().ifac_flag,
            packet.header().header_type,
            packet.header().propagation_type,
            packet.header().destination_type,
            packet.header().packet_type,
            packet.header().hops,
            packet.destination.as_hex(),
            packet.transport_id.map(|x| x.as_hex().to_string())
        );
    }

    fn on_announce(&self, ann: &Announce) {
        log::info!(
            "Announce: name:{} rnd:{} data:[{}]",
            ann.name_hash.as_hex(),
            ann.random_hash.as_hex(),
            ann.app_data
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or("N/A".to_string())
        );
    }

    fn on_path_request(&self, req: &PathRequest) {
        log::info!(
            "Path request: dest:{} trans:{} tag:{}",
            req.query.as_hex(),
            req.transport
                .map(|x| x.as_hex().to_string())
                .unwrap_or("N/A".to_string()),
            req.tag
                .map(|x| x.as_hex().to_string())
                .unwrap_or("N/A".to_string())
        );
    }

    fn on_link_established(&self, link: &Link) {
        log::info!("Link established: id={}", link.link_id());
    }

    fn on_link_message(&self, link: &Link, message: &[u8]) {
        log::info!(
            "Message from link id={}: {:?}",
            link.link_id(),
            core::str::from_utf8(message)
        );
    }
}
