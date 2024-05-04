use env_logger::Env;
use rand_core::OsRng;

use reticulum::context::RnsContext;
use reticulum::destination::Destination;
use reticulum::identity::Identity;
use reticulum::link::Link;
use reticulum::packet::Packet;
use reticulum::sign::FixedKeys;
use reticulum::{OnPacket, TestInf};
use reticulum_net::tcp::Reticulum;

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

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

        fn on_link_closed(&self, link: &Link) {
            println!(".. {}: closed", link.link_id());
        }
    }

    let myself = Destination::single_in(&identity, "example_utilities", "linkexample");

    println!("Hello, this is {myself}, waiting for a link request.");

    let announce = myself.announce_rnd(&mut OsRng, None, &secrets);
    let announce = Packet::from_announce(announce);

    let mut reticulum = Reticulum::tcp_std(identity, PrintMessage, secrets);

    reticulum.broadcast(&announce);

    let _ = reticulum.handle.join();

    println!("Bye.");
}
