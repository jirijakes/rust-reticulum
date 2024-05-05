use std::io::{Read, Write};
use std::marker::PhantomData;
use std::net::TcpStream;
use std::thread::{self, JoinHandle};

use hex::DisplayHex;
use rand_core::OsRng;

use reticulum::context::{Context, RnsContext};
use reticulum::identity::Identity;
use reticulum::interface::Interface;
use reticulum::link::{Link, LinkKeys};
use reticulum::packet::{Packet, PacketContext, Payload};
use reticulum::rmp;
use reticulum::sign::{Dh, Sign};
use reticulum::{OnPacket, OnSend, TestInf};

use crate::hdlc::Hdlc;

pub struct TcpSend(pub Hdlc<TcpStream>);

impl OnSend<TestInf, RnsContext> for TcpSend {
    fn send(&mut self, bytes: &[u8]) {
        log::trace!("OUT: {}", bytes.as_hex());

        let _ = self.0.write(bytes).expect("successfully written bytes");
        self.0.flush().expect("successfully flushed");
    }
}

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
                log::trace!("IN: {}", buf.get(0..x).unwrap().as_hex());
                match reticulum::parse::packet::<TestInf, RnsContext>(buf.get(0..x).unwrap()) {
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
                                    match context {
                                        PacketContext::None => {
                                            receive.on_link_message(link, message);
                                        }
                                        PacketContext::LinkRequestRoundTripTime => {
                                            log::debug!(
                                                "RTT: {:?}",
                                                rmp::decode::read_f64(&mut &message[..])
                                            );
                                        }
                                        PacketContext::LinkClose => {
                                            receive.on_link_closed(link);
                                            log::debug!("Link closed: id={}", message.as_hex());
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Payload::LinkProof(proof) => {
                                println!("Proof: {}", proof.as_bytes().as_hex());
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

    pub fn broadcast_raw(&mut self, data: &[u8]) {
        self.send.send(data);
    }
}
