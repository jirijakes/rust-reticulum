use std::io::prelude::*;
use std::net::TcpStream;

use reticulum::{hdlc, packet, Interface, Payload};

#[derive(Debug)]
struct TestInf;
impl Interface for TestInf {
    const LENGTH: usize = 2;
}

fn main() {
    println!("Ahoj");

    // let mut stream = TcpStream::connect("amsterdam.connect.reticulum.network:4965").unwrap();
    // let mut stream = TcpStream::connect("betweentheborders.com:4242").unwrap();
    let mut stream = TcpStream::connect("localhost:4998").unwrap();

    let mut buf = [0u8; 512];

    while let Ok(x) = stream.read(&mut buf) {
        let a = hdlc(packet::<TestInf>)(buf.get(0..x).unwrap());
        println!("{x} : {:?}", a);

        if let Ok((_, packet)) = a {
            if let Payload::Announce(ann) = packet.data {
                ann.validate();
            }
        }
        // println!("{:?}", String::from_utf8_lossy(a.unwrap().1.data));
    }
}
