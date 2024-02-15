use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use reticulum::{interface::Interface, packet::Payload, parse};

#[derive(Debug)]
struct TestInf;
impl Interface for TestInf {
    const LENGTH: usize = 2;
}

#[test]
fn path_requests() {
    let path = Path::new("tests/data/path_requests.txt");
    let f = File::open(path).expect("load file with path requests");
    let f = BufReader::new(f);

    f.lines().for_each(|line| {
        if let Ok(hex) = line {
            let msg = hex::decode(&hex).expect("decode hex string");
            let packet = parse::packet::<TestInf>(&msg);
            assert!(packet.is_ok());
            if let Ok((rest, packet)) = packet {
                assert!(
                    matches!(packet.data, Payload::PathRequest(_)),
                    "is not path request: {}",
                    hex
                );
                assert!(rest.is_empty());
            }
        } else {
            panic!("Could not read {path:?}");
        }
    });
}
