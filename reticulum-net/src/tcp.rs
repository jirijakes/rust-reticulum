use std::io::Read;
use std::marker::PhantomData;
use std::net::TcpStream;
use std::thread::{self, JoinHandle};

use reticulum_core::context::{Context, RnsContext};
use reticulum_core::hdlc::Hdlc;
use reticulum_core::interface::Interface;
use reticulum_core::packet::{Packet, Payload};
use reticulum_core::{OnPacket, OnSend, TcpSend, TestInf};

pub struct Reticulum<R, S, I, C>
where
    I: Interface,
    C: Context,
    R: OnPacket<I, C>,
    S: OnSend<I, C>,
{
    send: S,
    pub handle: JoinHandle<()>,
    _r: PhantomData<R>,
    _i: PhantomData<I>,
    _c: PhantomData<C>,
}

impl<R> Reticulum<R, TcpSend, TestInf, RnsContext>
where
    R: OnPacket<TestInf, RnsContext> + Send + 'static,
{
    pub fn tcp_std(receive: R) -> Self {
        let stream = TcpStream::connect("localhost:4242").unwrap();
        let mut stream = Hdlc::new(stream);

        let mut out = TcpSend(stream.try_clone().unwrap());

        let send = TcpSend(stream.try_clone().unwrap());

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];

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
                            Payload::LinkRequest(req) => {
                                if let Some(r) = receive.on_link_request(&req) {
                                    out.send(&Packet::link_proof(req.id, &r));
                                }
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
        }
    }

    pub fn broadcast(&mut self, packet: &Packet<TestInf, RnsContext>) {
        self.send.send(packet);
    }
}
