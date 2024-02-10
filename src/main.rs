use std::io::prelude::*;
use std::net::TcpStream;

use env_logger::Env;
use log::{debug, info, trace, warn};

use reticulum::destination::Destination;
use reticulum::interface::Interface;
use reticulum::packet::Payload;

#[derive(Debug)]
struct TestInf;
impl Interface for TestInf {
    const LENGTH: usize = 2;
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    info!("Starting rusty Reticulum.");

    // let mut stream = TcpStream::connect("amsterdam.connect.reticulum.network:4965").unwrap();
    // let stream = TcpStream::connect("betweentheborders.com:4242").unwrap();
    let stream = TcpStream::connect("localhost:4998").unwrap();

    let mut stream = reticulum::hdlc::Hdlc::new(stream);

    let mut buf = [0u8; 512];

    while let Ok(x) = stream.read(&mut buf) {
        trace!("{}", hex::encode(buf.get(0..x).unwrap()));
        match reticulum::parse::packet::<TestInf>(buf.get(0..x).unwrap()) {
            Ok((_, packet)) => {
                debug!(
                    "Packet: {:?}/{:?}/{:?}/{:?}/{:?}/{} {}",
                    packet.header().ifac_flag,
                    packet.header().header_type,
                    packet.header().propagation_type,
                    packet.header().destination_type,
                    packet.header().packet_type,
                    packet.header().hops,
                    match packet.destination {
                        Destination::Type1(h) => hex::encode(h).to_string(),
                        Destination::Type2(h1, h2) =>
                            format!("{} → {}", hex::encode(h1), hex::encode(h2)),
                    }
                );

                match packet.data {
                    Payload::Announce(ann) => {
                        info!(
                            "Announce: name:{} rnd:{} data:[{}]",
                            hex::encode(ann.name_hash),
                            hex::encode(ann.random_hash),
                            ann.app_data
                                .map(|b| String::from_utf8_lossy(b).to_string())
                                .unwrap_or("N/A".to_string())
                        );
                        ann.validate();
                    }
                    Payload::PathRequest(req) => {
                        info!(
                            "Path request: dest:{} trans:{} tag:{}",
                            hex::encode(req.destination_hash),
                            req.transport.map(hex::encode).unwrap_or("N/A".to_string()),
                            req.tag.map(hex::encode).unwrap_or("N/A".to_string())
                        );
                    }
                    _ => {
                        println!("Other: {packet:?}");
                    }
                }
            }
            Err(nom::Err::Error(e)) => {
                warn!("Problem: {:?} {}", e.code, hex::encode(e.input));
            }
            Err(e) => {
                warn!("Problem: {e:?}");
            }
        }
        // println!("{:?}", String::from_utf8_lossy(a.unwrap().1.data));
    }
}
