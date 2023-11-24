use std::collections::VecDeque;
use std::marker::PhantomData;

use simplicity::{encode, BitWriter, Value};

pub trait Stage {}
pub struct Program;
pub struct Witness;
pub struct IllegalPadding;
impl Stage for Program {}
impl Stage for Witness {}
impl Stage for IllegalPadding {}

#[derive(Debug)]
pub struct BitBuilder<S: Stage> {
    queue: VecDeque<(u64, u8)>,
    stage: PhantomData<S>,
}

impl<S: Stage> BitBuilder<S> {
    fn n_total_written(&self) -> usize {
        self.queue.iter().map(|x| usize::from(x.1)).sum()
    }

    pub fn assert_n_total_written(self, bit_len: usize) -> Self {
        let n_total_written = self.n_total_written();
        if n_total_written != bit_len {
            panic!("{} bits written, not {}", n_total_written, bit_len);
        }
        self
    }

    pub fn bits_be(mut self, bits: u64, bit_len: u8) -> Self {
        self.queue.push_back((bits, bit_len));
        self
    }

    pub fn bytes_be<A: AsRef<[u8]>>(mut self, bytes: A) -> Self {
        for byte in bytes.as_ref() {
            self = self.bits_be(u64::from(*byte), 8);
        }
        self
    }

    pub fn positive_integer(mut self, n: usize) -> Self {
        let mut bytes = Vec::new();
        let mut writer = BitWriter::new(&mut bytes);
        let bit_len = encode::encode_natural(n, &mut writer).expect("I/O to vector never fails");
        writer.flush_all().expect("I/O to vector never fails");

        let words = bytes_to_words(&bytes, bit_len);
        self.queue.extend(words);
        self
    }

    pub fn value(mut self, value: &Value) -> Self {
        let mut bytes = Vec::new();
        let mut writer = BitWriter::new(&mut bytes);
        let bit_len = encode::encode_value(value, &mut writer).expect("I/O to vector never fails");
        writer.flush_all().expect("I/O to vector never fails");

        let words = bytes_to_words(&bytes, bit_len);
        self.queue.extend(words);
        self
    }

    pub fn delete_bits(mut self, mut bit_len: usize) -> Self {
        while bit_len > 0 {
            if let Some((word, word_len)) = self.queue.pop_back() {
                if usize::from(word_len) <= bit_len {
                    // Delete entire word
                    bit_len = bit_len.saturating_sub(usize::from(word_len));
                } else {
                    // Truncate word and put it back
                    let truncated_word = word >> bit_len;
                    let truncated_word_len = word_len - bit_len as u8; // cast safety: bit_len < word_len <= u8::MAX
                    self.queue.push_back((truncated_word, truncated_word_len));
                    break;
                }
            }
        }
        self
    }

    fn get_bytes(mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut writer = BitWriter::new(&mut bytes);

        while let Some((bits, len)) = self.queue.pop_front() {
            writer
                .write_bits_be(bits, usize::from(len))
                .expect("I/O to vector never fails");
        }

        writer.flush_all().expect("I/O to vector never fails");
        bytes
    }

    pub fn parser_stops_here(self) -> Vec<u8> {
        self.get_bytes()
    }
}

impl BitBuilder<Program> {
    pub fn program_preamble(len: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            stage: PhantomData,
        }
        .positive_integer(len)
    }

    pub fn unit(self) -> Self {
        self.bits_be(0b01001, 5)
    }

    pub fn iden(self) -> Self {
        self.bits_be(0b01000, 5)
    }

    pub fn injl(self, left_offset: usize) -> Self {
        self.bits_be(0b00100, 5).positive_integer(left_offset)
    }

    pub fn injr(self, left_offset: usize) -> Self {
        self.bits_be(0b00101, 5).positive_integer(left_offset)
    }

    pub fn take(self, left_offset: usize) -> Self {
        self.bits_be(0b00110, 5).positive_integer(left_offset)
    }

    pub fn drop(self, left_offset: usize) -> Self {
        self.bits_be(0b00111, 5).positive_integer(left_offset)
    }

    pub fn comp(self, left_offset: usize, right_offset: usize) -> Self {
        self.bits_be(0b00000, 5)
            .positive_integer(left_offset)
            .positive_integer(right_offset)
    }

    pub fn pair(self, left_offset: usize, right_offset: usize) -> Self {
        self.bits_be(0b00010, 5)
            .positive_integer(left_offset)
            .positive_integer(right_offset)
    }

    pub fn case(self, left_offset: usize, right_offset: usize) -> Self {
        self.bits_be(0b00001, 5)
            .positive_integer(left_offset)
            .positive_integer(right_offset)
    }

    pub fn disconnect(self, left_offset: usize, right_offset: usize) -> Self {
        self.bits_be(0b00011, 5)
            .positive_integer(left_offset)
            .positive_integer(right_offset)
    }

    pub fn hidden<A: AsRef<[u8]>>(self, payload: A) -> Self {
        self.bits_be(0b0110, 4).bytes_be(payload)
    }

    pub fn fail<A: AsRef<[u8]>>(self, entropy: A) -> Self {
        self.bits_be(0b01010, 5).bytes_be(entropy)
    }

    pub fn stop(self) -> Self {
        self.bits_be(0b01011, 5)
    }

    pub fn jet(self, bits: u64, bit_len: u8) -> Self {
        self.bits_be(0b11, 2).bits_be(bits, bit_len)
    }

    pub fn word(self, depth: usize, value: &Value) -> Self {
        self.bits_be(0b10, 2).positive_integer(depth).value(value)
    }

    pub fn witness(self) -> Self {
        self.bits_be(0b0111, 4)
    }

    pub fn witness_preamble(mut self, len: usize) -> BitBuilder<Witness> {
        self = match len {
            0 => self.bits_be(0b0, 1),
            _ => self.bits_be(0b1, 1).positive_integer(len),
        };

        BitBuilder {
            queue: self.queue,
            stage: PhantomData,
        }
    }
}

impl BitBuilder<Witness> {
    pub fn program_finished(self) -> Vec<u8> {
        self.parser_stops_here()
    }

    pub fn illegal_padding(self) -> BitBuilder<IllegalPadding> {
        BitBuilder {
            queue: self.queue,
            stage: PhantomData,
        }
    }
}

/// Takes a byte slice with padding at the least significant bits of the final byte.
/// Returns a vector of words with padding at the most significant bits of the final word.
///
/// Each word in front of the final word is 64 bits long.
/// The final word is between 1 and 64 bits long.
fn bytes_to_words(bytes: &[u8], mut bit_len: usize) -> Vec<(u64, u8)> {
    assert!(
        bit_len <= bytes.len() * 8,
        "Bit length points past end of byte string"
    );

    if bytes.is_empty() || bit_len == 0 {
        return Vec::new();
    }

    let mut words: Vec<(u64, u8)> = Vec::new();
    let mut word = 0u64;
    let mut bits_in_word = 0u8;

    for byte in bytes {
        word += u64::from(*byte);

        if bit_len <= 8 {
            if bit_len < 8 {
                // Final bits are less than one byte
                // Shift word to the right and pad zeroes from front
                // This even works if bit_len = 0, in which case the most recent byte is erased
                word >>= 8 - bit_len;
            }

            bits_in_word += bit_len as u8; // cast safety: bit_len <= 8
            debug_assert!(bits_in_word <= 64);
            words.push((word, bits_in_word));
            break;
        }

        bits_in_word += 8;
        bit_len -= 8;
        debug_assert!(bit_len > 0);

        if bits_in_word == 64 {
            words.push((word, 64));
            word = 0u64;
            bits_in_word = 0;
        } else {
            // Make space for next byte
            word <<= 8;
        }
    }

    for (_, bit_len) in &words[0..words.len().saturating_sub(2)] {
        debug_assert!(bit_len == &64);
    }
    debug_assert!(1 <= words.last().unwrap().1 && words.last().unwrap().1 <= 64);

    words
}
