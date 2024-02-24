use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use reticulum_core::interface::Interface;
use reticulum_core::packet::{Packet, Payload};
use reticulum_core::parse;

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
            let packet: Result<(&[u8], Packet<TestInf>), _> = parse::packet(&msg);
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
