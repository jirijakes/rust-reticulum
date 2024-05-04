use std::io::Read;
use std::marker::PhantomData;
use std::net::TcpStream;
use std::thread::{self, JoinHandle};

use rand_core::OsRng;
use reticulum_core::context::{Context, RnsContext};
use reticulum_core::hdlc::Hdlc;
use reticulum_core::identity::Identity;
use reticulum_core::interface::Interface;
use reticulum_core::link::{Link, LinkKeys};
use reticulum_core::packet::{Packet, Payload};
use reticulum_core::rmp;
use reticulum_core::sign::{Dh, Sign};
use reticulum_core::{OnPacket, OnSend, TcpSend, TestInf};

pub struct Reticulum<R, S, I, C, X>
where
    I: Interface,
    C: Context,
    R: OnPacket<I, C>,
    S: OnSend<I, C>,
    X: Sign + Dh,
{
    send: S,
    pub handle: JoinHandle<()>,
    _r: PhantomData<R>,
    _i: PhantomData<I>,
    _c: PhantomData<C>,
    _x: PhantomData<X>,
}

impl<R, X> Reticulum<R, TcpSend, TestInf, RnsContext, X>
where
    R: OnPacket<TestInf, RnsContext> + Send + 'static,
    X: Sign + Dh + Send + 'static,
{
    pub fn tcp_std(_identity: Identity, receive: R, secrets: X) -> Self {
        let receive = receive;
        let stream = TcpStream::connect("localhost:4242").unwrap();
        let mut stream = Hdlc::new(stream);

        let mut out = TcpSend(stream.try_clone().unwrap());

        let send = TcpSend(stream.try_clone().unwrap());

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let mut established_link: Option<Link> = None;

            while let Ok(x) = stream.read(&mut buf) {
                log::trace!("IN: {}", hex::encode(buf.get(0..x).unwrap()));
                match reticulum_core::parse::packet::<TestInf, RnsContext>(buf.get(0..x).unwrap()) {
                    Ok((_, packet)) => {
                        receive.on_packet(&packet);

                        match packet.data {
                            Payload::Announce(ann) => {
                                receive.on_announce(&ann);
                                ann.validate();
                            }
                            Payload::PathRequest(req) => {
                                receive.on_path_request(&req);
                            }
                            Payload::LinkRequest(link_request) => {
                                let (keys, ephemeral) = LinkKeys::generate(&mut OsRng);

                                let link = link_request.establish_link(ephemeral);
                                let link = established_link.insert(link);
                                receive.on_link_established(link);

                                let proof = link_request.prove(&keys, &secrets);

                                out.send_packet(&Packet::link_proof(
                                    &link_request.link_id(),
                                    &proof,
                                ));
                            }
                            Payload::LinkData(context, link_data) => {
                                if let Some(link) = established_link.as_ref() {
                                    let mut buf = [0u8; 500];
                                    let message = link.decrypt(link_data, &mut buf);
                                    if context == 0 {
                                        receive.on_link_message(link, message);
                                    } else if context == 254 {
                                        log::debug!(
                                            "RTT: {:?}",
                                            rmp::decode::read_f64(&mut &message[..])
                                        );
                                    } else if context == 252 {
                                        receive.on_link_closed(link);
                                        log::debug!("Link closed: id={}", hex::encode(message));
                                    }
                                }
                            }
                            Payload::LinkProof(proof) => {
                                println!("{:02x?}", proof);
                            }
                            _ => {
                                println!("Other: {packet:?}");
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Problem: {e:?}");
                    }
                }
            }
        });

        Reticulum {
            send,
            handle,
            _r: PhantomData,
            _i: PhantomData,
            _c: PhantomData,
            _x: PhantomData,
        }
    }

    pub fn broadcast(&mut self, packet: &Packet<TestInf, RnsContext>) {
        self.send.send_packet(packet);
    }
}
