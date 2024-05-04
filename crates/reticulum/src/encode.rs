use alloc::vec::Vec;

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> usize;
}

impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> usize {
        self.extend_from_slice(buf);
        buf.len()
    }
}

impl<'a> Write for &'a mut [u8] {
    fn write(&mut self, buf: &[u8]) -> usize {
        let available = self.len().min(buf.len());
        self[..available].copy_from_slice(&buf[..available]);
        *self = &mut core::mem::take(self)[available..];
        available
    }
}

pub trait Encode {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize;
}

impl<const N: usize> Encode for &[u8; N] {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        writer.write(self.as_slice())
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        writer.write(self.as_slice())
    }
}

impl<'a> Encode for &'a [u8] {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        writer.write(self)
    }
}

impl Encode for u8 {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        writer.write(&[*self])
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> usize {
        if let Some(s) = self {
            s.encode(writer)
        } else {
            0
        }
    }
}
