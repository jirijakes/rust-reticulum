use rand::seq::SliceRandom;
use rand_core::OsRng;

use reticulum_core::destination::Destination;
use reticulum_core::identity::Identity;
use reticulum_core::sign::FixedKey;

pub fn main() {
    let (identity, _, sign_key) = Identity::generate(OsRng);

    let sign = FixedKey::new(sign_key);

    let destination1 = Destination::single_in(&identity, "announcesample", "fruits");
    let destination2 = Destination::single_in(&identity, "announcesample", "noble_gases");

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

    let fruit = fruits.choose(&mut rng).expect("non empty");
    let noble_gas = noble_gases.choose(&mut rng).expect("non empty");

    let announce1 = destination1.announce_rnd(&mut rng, Some(fruit.as_bytes()), &sign);
    let announce2 = destination2.announce_rnd(&mut rng, Some(noble_gas.as_bytes()), &sign);

    println!("{:?}", announce1);
    announce1.validate();
    println!("{:?}", announce2);
    announce2.validate();
}
