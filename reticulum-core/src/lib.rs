use std::io::Write;
use std::net::TcpStream;

use announce::Announce;
pub use ed25519_dalek;
use encode::Encode;
use hdlc::Hdlc;
use path_request::PathRequest;
pub use x25519_dalek;

pub mod announce;
pub mod context;
pub mod destination;
pub mod encode;
pub mod hdlc;
pub mod identity;
pub mod interface;
pub mod link_request;
pub mod packet;
pub mod parse;
pub mod path_request;
pub mod sign;

use context::{Context, RnsContext};
use interface::Interface;
use packet::Packet;

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
            hex::encode(packet.destination),
            packet.transport_id.map(hex::encode)
        );
    }

    fn on_announce(&self, ann: &Announce) {
        log::info!(
            "Announce: name:{} rnd:{} data:[{}]",
            hex::encode(ann.name_hash),
            hex::encode(ann.random_hash),
            ann.app_data
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or("N/A".to_string())
        );
    }

    fn on_path_request(&self, req: &PathRequest) {
        log::info!(
            "Path request: dest:{} trans:{} tag:{}",
            hex::encode(req.query),
            req.transport.map(hex::encode).unwrap_or("N/A".to_string()),
            req.tag.map(hex::encode).unwrap_or("N/A".to_string())
        );
    }
}
