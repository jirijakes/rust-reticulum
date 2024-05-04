use rand::seq::SliceRandom;
use rand_core::OsRng;

use reticulum::announce::Announce;
use reticulum::context::RnsContext;
use reticulum::destination::Destination;
use reticulum::identity::Identity;
use reticulum::packet::Packet;
use reticulum::sign::FixedKeys;
use reticulum::{OnPacket, TestInf};
use reticulum_net::tcp::Reticulum;

pub fn main() {
    let (identity, static_key, sign_key) = Identity::generate(OsRng);

    let secrets = FixedKeys::new(static_key, sign_key);

    let destination1 =
        Destination::single_in(&identity, "example_utilities", "announcesample.fruits");
    let destination2 =
        Destination::single_in(&identity, "example_utilities", "announcesample.noble_gases");

    let fruits = [
        "Peach",
        "Quince",
        "Date",
        "Tangerine",
        "Pomelo",
        "Carambola",
        "Grape",
    ];

    let noble_gases = [
        "Helium",
        "Neon",
        "Argon",
        "Krypton",
        "Xenon",
        "Radon",
        "Oganesson",
    ];

    let mut rng = OsRng;

    struct ShowAnnouncement {
        destination: [u8; 16],
    }

    impl OnPacket<TestInf, RnsContext> for ShowAnnouncement {
        fn on_announce(&self, announce: &Announce) {
            if announce.destination == self.destination {
                println!(
                    "Received fruity announce: name:{} rnd:{} data:[{}]",
                    hex::encode(announce.name_hash),
                    hex::encode(announce.random_hash),
                    announce
                        .app_data
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .unwrap_or("N/A".to_string())
                );
            }
        }
    }

    let mut reticulum = Reticulum::tcp_std(
        identity,
        ShowAnnouncement {
            destination: destination1.hash(),
        },
        secrets.clone(),
    );

    loop {
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).expect("read line");

        let noble_gas = noble_gases.choose(&mut rng).expect("non empty");
        let announce2 = destination2.announce_rnd(&mut rng, Some(noble_gas.as_bytes()), &secrets);
        reticulum.broadcast(&Packet::from_announce(announce2));
        println!("Sent gassy announce.");

        std::thread::sleep(std::time::Duration::from_secs(2));

        let fruit = fruits.choose(&mut rng).expect("non empty");
        let announce1 = destination1.announce_rnd(&mut rng, Some(fruit.as_bytes()), &secrets);
        reticulum.broadcast(&Packet::from_announce(announce1));
        println!("Sent fruity announce.");
    }
}
