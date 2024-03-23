use std::io::Write;
use std::net::TcpStream;

pub use ed25519_dalek;
pub use x25519_dalek;

pub mod announce;
pub mod context;
pub mod destination;
pub mod encode;
mod fernet;
pub mod hdlc;
pub mod identity;
pub mod interface;
pub mod link_request;
pub mod packet;
pub mod parse;
pub mod path_request;
pub mod sign;

use announce::Announce;
use context::{Context, RnsContext};
use encode::Encode;
use hdlc::Hdlc;
use identity::Identity;
use interface::Interface;
use link_request::LinkRequest;
use packet::Packet;
use path_request::PathRequest;
use sign::{Dh, Sign};

pub trait OnPacket<I: Interface, C: Context> {
    fn identity(&self) -> &Identity;

    fn on_packet(&self, packet: &Packet<I, C>) {
        let _ = packet;
    }

    fn on_announce(&self, announce: &Announce) {
        let _ = announce;
    }

    fn on_path_request(&self, path_request: &PathRequest) {
        let _ = path_request;
    }

    fn on_link_request(&self, link_request: &LinkRequest) -> Option<Vec<u8>> {
        let _ = link_request;
        None
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

        log::trace!("OUT: {}", hex::encode(&out));

        let _ = self.0.write(&out).expect("successfully written bytes");
        self.0.flush().expect("successfully flushed");
    }
}

pub struct PrintPackets<S>(pub Identity, pub S);

impl<S: Sign + Dh> OnPacket<TestInf, RnsContext> for PrintPackets<S> {
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

    fn on_link_request(&self, link_request: &LinkRequest) -> Option<Vec<u8>> {
        log::info!("Link request: id:{}", hex::encode(link_request.id));

        link_request.derive_keys(&self.1);

        let message = [
            link_request.id.as_slice(),
            self.identity().public_key().as_bytes(),
            self.identity().verifying_key().as_bytes(),
        ]
        .concat();

        let mut proof = self.1.sign(&message).to_vec();
        proof.append(&mut self.identity().public_key().to_bytes().to_vec());

        Some(proof)
    }

    fn identity(&self) -> &Identity {
        &self.0
    }
}
