use std::io;

use simplicity::encode;

pub struct Encoder<W: io::Write> {
    bits: simplicity::BitWriter<W>,
}

impl<W: io::Write> Encoder<W> {
    pub fn new(w: W) -> Self {
        Self {
            bits: simplicity::BitWriter::new(w),
        }
    }

    pub fn n_total_written(&self) -> usize {
        self.bits.n_total_written()
    }

    pub fn bits_be(&mut self, bits: u64, bit_len: usize) -> io::Result<()> {
        self.bits.write_bits_be(bits, bit_len).map(|_| ())
    }

    pub fn program_preamble(&mut self, len: usize) -> io::Result<()> {
        encode::encode_natural(len, &mut self.bits).map(|_| ())
    }

    pub fn unit(&mut self) -> io::Result<()> {
        self.bits.write_bits_be(0b01001, 5).map(|_| ())
    }

    pub fn iden(&mut self) -> io::Result<()> {
        self.bits.write_bits_be(0b01000, 5).map(|_| ())
    }

    pub fn comp(&mut self, left_offset: usize, right_offset: usize) -> io::Result<()> {
        self.bits.write_bits_be(0x00000, 5)?;
        encode::encode_natural(left_offset, &mut self.bits)?;
        encode::encode_natural(right_offset, &mut self.bits).map(|_| ())
    }

    pub fn case(&mut self, left_offset: usize, right_offset: usize) -> io::Result<()> {
        self.bits.write_bits_be(0b00001, 5)?;
        encode::encode_natural(left_offset, &mut self.bits)?;
        encode::encode_natural(right_offset, &mut self.bits).map(|_| ())
    }

    pub fn hidden(&mut self, payload: &[u8]) -> io::Result<()> {
        self.bits.write_bits_be(0b0110, 4)?;
        // 2023-11-16: We can use this method because it does not check the length of `payload`
        encode::encode_hash(payload, &mut self.bits).map(|_| ())
    }

    pub fn fail(&mut self, entropy: &[u8]) -> io::Result<()> {
        self.bits.write_bits_be(0b01010, 5)?;
        // 2023-11-16: We can use this method because it does not check the length of `entropy`
        encode::encode_hash(entropy, &mut self.bits).map(|_| ())
    }

    pub fn stop(&mut self) -> io::Result<()> {
        self.bits.write_bits_be(0b01011, 5).map(|_| ())
    }

    pub fn jet(&mut self, bits: u64, bit_len: usize) -> io::Result<()> {
        self.bits.write_bit(true)?;
        self.bits.write_bit(true)?;
        self.bits.write_bits_be(bits, bit_len).map(|_| ())
    }

    pub fn word(&mut self, depth: usize, value: &simplicity::Value) -> io::Result<()> {
        self.bits.write_bit(true)?;
        self.bits.write_bit(false)?;
        encode::encode_natural(depth, &mut self.bits)?;
        encode::encode_value(value, &mut self.bits).map(|_| ())
    }

    pub fn witness_preamble(&mut self, len: Option<usize>) -> io::Result<()> {
        match len {
            None => self.bits.write_bit(false),
            Some(len) => {
                self.bits.write_bit(true)?;
                encode::encode_natural(len, &mut self.bits).map(|_| ())
            }
        }
    }

    pub fn finalize(mut self) -> io::Result<()> {
        self.bits.flush_all()
    }
}
