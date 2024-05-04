use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use reticulum::interface::Interface;
use reticulum::packet::{Packet, Payload};
use reticulum::parse;

#[derive(Debug)]
struct TestInf;
impl Interface for TestInf {
    const LENGTH: usize = 2;
}

#[test]
fn path_requests() {
    use hex::prelude::*;

    let path = Path::new("tests/data/path_requests.txt");
    let f = File::open(path).expect("load file with path requests");
    let f = BufReader::new(f);

    f.lines().for_each(|line| {
        if let Ok(hex) = line {
            let msg = Vec::from_hex(&hex).expect("decode hex string");
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

#[test]
fn link_proofs() {
    use hex::prelude::*;

    let path = Path::new("tests/data/link_proofs.txt");
    let f = File::open(path).expect("load file with link proofs");
    let f = BufReader::new(f);

    f.lines().for_each(|line| {
        if let Ok(hex) = line {
            let msg = Vec::from_hex(&hex).expect("decode hex string");
            let packet: Result<(&[u8], Packet<TestInf>), _> = parse::packet(&msg);
            assert!(packet.is_ok());
            if let Ok((rest, packet)) = packet {
                assert!(
                    matches!(packet.data, Payload::LinkProof(_)),
                    "is not link proof: {}",
                    hex
                );
                assert!(rest.is_empty());
            }
        } else {
            panic!("Could not read {path:?}");
        }
    });
}
