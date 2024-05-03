use rand_core::OsRng;

use reticulum_core::context::RnsContext;
use reticulum_core::destination::Destination;
use reticulum_core::identity::Identity;
use reticulum_core::link::Link;
use reticulum_core::packet::Packet;
use reticulum_core::sign::FixedKeys;
use reticulum_core::{OnPacket, TestInf};
use reticulum_net::tcp::Reticulum;

pub fn main() {
    let (identity, static_key, sign_key) = Identity::generate(OsRng);

    let secrets = FixedKeys::new(static_key, sign_key);

    struct PrintMessage;

    impl OnPacket<TestInf, RnsContext> for PrintMessage {
        fn on_link_established(&self, link: &Link) {
            println!(".. {}: connected", link.link_id());
        }

        fn on_link_message(&self, link: &Link, message: &[u8]) {
            println!("{}: {}", link.link_id(), String::from_utf8_lossy(message));
        }
    }

    let myself = Destination::single_in(&identity, "example_utilities", "linkexample");
    let announce = myself.announce_rnd(&mut OsRng, None, &secrets);
    let announce = Packet::from_announce(announce);

    let mut reticulum = Reticulum::tcp_std(identity, PrintMessage, secrets);

    reticulum.broadcast(&announce);

    let _ = reticulum.handle.join();

    println!("Bye.");
}
