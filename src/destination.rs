use std::fmt::Debug;

use crate::encode::{Encode, Write};

#[derive(Clone, Copy)]
pub enum Destination<'a> {
    Type1(&'a [u8; 16]),
    Type2(&'a [u8; 16], &'a [u8; 16]),
}

impl<'a> Debug for Destination<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut tuple = f.debug_tuple("Destination");
        match self {
            Destination::Type1(h) => tuple.field(&hex::encode(h)).finish(),
            Destination::Type2(h1, h2) => tuple
                .field(&hex::encode(h1))
                .field(&hex::encode(h2))
                .finish(),
        }
    }
}

impl<'a> Encode for Destination<'a> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        match self {
            Destination::Type1(h) => h.encode(writer),
            Destination::Type2(h1, h2) => h1.encode(writer) + h2.encode(writer),
        }
    }
}
