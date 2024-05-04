use std::collections::HashMap;
use std::env::args;
use std::sync::{Arc, RwLock};

use env_logger::Env;
use rand_core::OsRng;

use reticulum::announce::Announce;
use reticulum::context::RnsContext;
use reticulum::destination::Destination;
use reticulum::identity::Identity;
use reticulum::link::{LinkKeys, Lynx};
use reticulum::packet::Packet;
use reticulum::sign::FixedKeys;
use reticulum::{OnPacket, TestInf};
use reticulum_net::tcp::Reticulum;

struct LinkClient(Arc<RwLock<HashMap<[u8; 16], Identity>>>);

impl OnPacket<TestInf, RnsContext> for LinkClient {
    fn on_announce(&self, announce: &Announce) {
        let mut guard = self.0.write().expect("write to announces");
        guard.insert(announce.destination, announce.identity);
        println!("{:02x?}", guard);
    }
}

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    let (identity, static_key, sign_key) = Identity::generate(OsRng);

    let secrets = FixedKeys::new(static_key, sign_key);

    let argument = args().nth(1).expect("one argument");
    let mut destination: [u8; 16] = [0; 16];
    hex::decode_to_slice(argument, &mut destination).expect("valid destination");

    let client = LinkClient(Default::default());

    let announces = client.0.clone();

    let mut reticulum = Reticulum::tcp_std(identity, client, secrets);

    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).expect("read line");

    {
        let announces = announces.read().expect("read announces");
        let linkee_id = announces.get(&destination).expect("announced destination");
        let linkee_dest = Destination::new(linkee_id, "example_utilities", "linkexample");

        let (link_keys, _ephemeral) = LinkKeys::generate(&mut OsRng);

        let lynx = Lynx::new(*link_keys.public_key(), link_keys.verifying_key());
        let packet = Packet::<TestInf, RnsContext>::link_request(linkee_dest, &lynx);

        let mut buf = [0; 512];
        let (data, _hash) = packet.encode_get_hash(&mut buf);

        reticulum.broadcast_raw(data);
    }

    let _ = reticulum.handle.join();

    println!("Bye.");
}
