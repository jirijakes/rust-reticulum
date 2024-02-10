use rand_core::OsRng;

use reticulum::destination::Destination;
use reticulum::identity::Identity;
use reticulum::sign::FixedKey;

pub fn main() {
    let (identity, _, sign_key) = Identity::generate(OsRng);

    let sign = FixedKey::new(sign_key);

    let destination = Destination::single_in(&identity, "testing_app", "fruits");

    println!("{}", destination.name());

    let announce = destination.announce(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], None, sign);

    println!("{:?}", announce);
    println!("{:?}", announce.validate());
}
