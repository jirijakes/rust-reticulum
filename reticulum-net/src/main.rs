pub mod tcp;

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::thread;

use core::time;
use env_logger::Env;
use log::info;
use rand_core::OsRng;

use reticulum_core::context::RnsContext;
use reticulum_core::destination::Destination;
use reticulum_core::ed25519_dalek::SigningKey;
use reticulum_core::identity::Identity;
use reticulum_core::packet::Packet;
use reticulum_core::sign::FixedKey;
use reticulum_core::x25519_dalek::StaticSecret;
use reticulum_core::{PrintPackets, TestInf};

use crate::tcp::Reticulum;

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

    let (identity, _static_key, sign_key) = load_identity();
    let sign = FixedKey::new(sign_key);

    info!("Starting rusty Reticulum with {identity:?}.");

    let mut reticulum = Reticulum::tcp_std(PrintPackets);

    thread::sleep(time::Duration::from_secs(20));

    let destination = Destination::single_in(&identity, "hello", "hello");
    let announce = destination.announce_rnd(&mut OsRng, Some(b"rust-reticulum"), &sign);
    let packet = Packet::<TestInf, RnsContext>::from_announce(announce);
    reticulum.broadcast(&packet);

    // let path_request = PathRequest::new_rns(
    //     &[
    //         0x02, 0x9f, 0x61, 0x43, 0xa3, 0x4b, 0xd3, 0x44, 0x93, 0x95, 0x86, 0xa4, 0x79, 0x17,
    //         0x5c, 0x58,
    //     ],
    //     None,
    //     Some(&[1, 2, 3]),
    // );
    // let packet = Packet::<TestInf, RnsContext>::from_path_request(path_request);
    // sendem.send(&packet);
    // });

    let _ = reticulum.handle.join();

    println!("Bye.");
}
