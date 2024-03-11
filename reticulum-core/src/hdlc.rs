use std::io::{Read, Result, Write};
use std::net::TcpStream;

const FRAME_BOUNDARY: u8 = 0x7e;
const ESCAPE_BYTE: u8 = 0x7d;
const FLIP_MASK: u8 = 0b00100000;

#[derive(Clone)]
pub struct Hdlc<I> {
    inner: I,
    escaping: bool,
    started: bool,
    finished: bool,
}

impl<I> Hdlc<I> {
    pub const fn new(inner: I) -> Self {
        Self {
            inner,
            escaping: false,
            started: false,
            finished: false,
        }
    }
}

impl Hdlc<TcpStream> {
    pub fn try_clone(&self) -> std::io::Result<Hdlc<TcpStream>> {
        Ok(Hdlc {
            inner: self.inner.try_clone()?,
            escaping: self.escaping,
            started: self.started,
            finished: self.finished,
        })
    }
}

impl<W: Write> Write for Hdlc<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let _ = self.inner.write(&[FRAME_BOUNDARY])?;

        for b in buf {
            if *b == FRAME_BOUNDARY || *b == ESCAPE_BYTE {
                let _ = self.inner.write(&[ESCAPE_BYTE, *b ^ FLIP_MASK])?;
            } else {
                let _ = self.inner.write(&[*b])?;
            }
        }
        let _ = self.inner.write(&[FRAME_BOUNDARY])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

impl<R: Read> Read for Hdlc<R> {
    // TODO: Does not work for buffer of size 1
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut eff_len = self.inner.read(buf)?;

        let mut i = 0;

        while i <= eff_len {
            if i < eff_len && buf[i] == FRAME_BOUNDARY {
                eff_len -= 1;
                if !self.started {
                    self.started = true;
                    buf[..].rotate_left(1);
                } else {
                    self.finished = true;
                }
            }

            if self.escaping {
                self.escaping = false;
                if i == 0 {
                    buf[0] ^= FLIP_MASK;
                } else {
                    buf[i - 1] ^= FLIP_MASK;
                }
            }

            if self.finished {
                self.started = false;
                self.finished = false;
                self.escaping = false;
                return Ok(eff_len);
            }

            if i < eff_len && buf[i] == ESCAPE_BYTE {
                self.escaping = true;
                buf[i..].rotate_left(1);
                eff_len -= 1;
            }

            i += 1;
        }

        Ok(eff_len)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use crate::hdlc::Hdlc;

    #[test]
    fn write_escape() {
        let unescaped = vec![0x00, 0x7e, 0x03, 0x7e, 0x7e];
        let mut buf: Vec<u8> = Vec::new();
        let mut writer = Hdlc::new(&mut buf);
        writer.write_all(&unescaped).expect("write");
        println!(">>> {buf:02x?}");
    }

    #[test]
    fn read_preserves_unescaped() {
        let escaped = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let mut reader = Hdlc::new(escaped.as_slice());

        let mut buf = Vec::new();

        let _ = reader.read_to_end(&mut buf);

        assert_eq!(buf, escaped);
    }
    #[test]
    fn read_unescapes_accross_buffer_boundaries() {
        let escaped = vec![0x00, 0x7d, 0x5e, 0x03, 0x7d, 0x5e, 0x7d, 0x5e];
        let mut reader = Hdlc::new(escaped.as_slice());

        let mut buf = [0u8; 2];
        let mut unescaped = Vec::new();

        let mut total_len = 0;

        loop {
            if let Ok(len) = reader.read(&mut buf) {
                if len == 0 {
                    break;
                } else {
                    total_len += len;
                    unescaped.extend_from_slice(&buf[..len]);
                }
            }
        }

        assert_eq!(total_len, 5);
        assert_eq!(unescaped, vec![0x00, 0x7e, 0x03, 0x7e, 0x7e]);
    }

    #[test]
    fn read_unescapes_all() {
        let escaped = vec![0x7e, 0x00, 0x7d, 0x5e, 0x03, 0x7d, 0x5e, 0x7d, 0x5e, 0x7e];
        let mut reader = Hdlc::new(escaped.as_slice());

        let mut unescaped = Vec::new();
        let len = reader.read_to_end(&mut unescaped);

        assert_eq!(len.ok(), Some(5));
        assert_eq!(unescaped, vec![0x00, 0x7e, 0x03, 0x7e, 0x7e]);
    }
}
