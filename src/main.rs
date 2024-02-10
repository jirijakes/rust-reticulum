use std::fs::File;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use env_logger::Env;
use log::{debug, info, trace, warn};

use rand_core::OsRng;
use reticulum::destination::Destination;
use reticulum::identity::Identity;
use reticulum::interface::Interface;
use reticulum::packet::Payload;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
struct TestInf;
impl Interface for TestInf {
    const LENGTH: usize = 2;
}

fn load_identity() -> (Identity, StaticSecret, SigningKey) {
    let path = Path::new("reticulum_identity");
    if path.exists() {
        let mut file = File::open(path).expect("open file");
        let mut sign_key = [0u8; 32];
        let mut static_key = [0u8; 32];
        let _ = file.read(&mut sign_key).expect("read public key");
        let _ = file.read(&mut static_key).expect("read verifying key");
        let sign_key = SigningKey::from(sign_key);
        let static_key = StaticSecret::from(static_key);
        (
            Identity::load(sign_key.clone(), static_key.clone()),
            static_key,
            sign_key,
        )
    } else {
        let mut file = File::create(path).expect("create file");
        let (identity, static_key, sign_key) = Identity::generate(OsRng);
        let _ = file.write(sign_key.as_bytes());
        let _ = file.write(static_key.as_bytes());
        (identity, static_key, sign_key)
    }
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    let (identity, _static_key, _sign_key) = load_identity();

    info!("Starting rusty Reticulum with {identity:?}.");

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
