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
use reticulum_core::sign::FixedKeys;
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

    let (identity, static_key, sign_key) = load_identity();
    let secrets = FixedKeys::new(static_key, sign_key);

    info!("Starting rusty Reticulum with {identity:?}.");

    let destination = Destination::single_in(&identity, "hello", "hello");
    let announce = destination.announce_rnd(&mut OsRng, Some(b"rust-reticulum"), &secrets);
    let announce = Packet::<TestInf, RnsContext>::from_announce(announce);

    let mut reticulum = Reticulum::tcp_std(PrintPackets(identity, secrets));

    thread::sleep(time::Duration::from_secs(2));
    reticulum.broadcast(&announce);

    let _ = reticulum.handle.join();

    println!("Bye.");
}
