use std::collections::VecDeque;
use std::fmt;

use simplicity::hex::DisplayHex;
use simplicity::{encode, BitWriter, Value};

#[derive(Debug, Default)]
pub struct Encoder {
    queue: VecDeque<(u64, u8)>,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    pub fn bits_be(mut self, bits: u64, bit_len: u8) -> Self {
        self.queue.push_back((bits, bit_len));
        self
    }

    pub fn bytes_be(mut self, bytes: &[u8]) -> Self {
        for byte in bytes {
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

    pub fn program_preamble(mut self, len: usize) -> Self {
        self = self.positive_integer(len);
        self
    }

    pub fn unit(mut self) -> Self {
        self.queue.push_back((0b01001, 5));
        self
    }

    pub fn iden(mut self) -> Self {
        self.queue.push_back((0b01000, 5));
        self
    }

    pub fn comp(mut self, left_offset: usize, right_offset: usize) -> Self {
        self.queue.push_back((0x00000, 5));
        self = self.positive_integer(left_offset);
        self = self.positive_integer(right_offset);
        self
    }

    pub fn case(mut self, left_offset: usize, right_offset: usize) -> Self {
        self.queue.push_back((0x00001, 5));
        self = self.positive_integer(left_offset);
        self = self.positive_integer(right_offset);
        self
    }

    pub fn hidden(mut self, payload: &[u8]) -> Self {
        self.queue.push_back((0x0110, 5));
        self = self.bytes_be(payload);
        self
    }

    pub fn fail(mut self, entropy: &[u8]) -> Self {
        self.queue.push_back((0b01010, 5));
        self = self.bytes_be(entropy);
        self
    }

    pub fn stop(mut self) -> Self {
        self.queue.push_back((0b01011, 5));
        self
    }

    pub fn jet(mut self, bits: u64, bit_len: u8) -> Self {
        self.queue.push_back((0b11, 2));
        self.queue.push_back((bits, bit_len));
        self
    }

    pub fn word(mut self, depth: usize, value: &Value) -> Self {
        self.queue.push_back((0b10, 2));
        self = self.positive_integer(depth);
        self = self.value(value);
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

    pub fn witness_preamble(mut self, len: Option<usize>) -> Self {
        match len {
            None => self.queue.push_back((0b0, 1)),
            Some(len) => {
                self.queue.push_back((0b1, 1));
                self = self.positive_integer(len);
            }
        }

        self
    }

    pub fn get_bytes(mut self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        let mut writer = BitWriter::new(&mut bytes);

        while let Some((bits, len)) = self.queue.pop_front() {
            writer
                .write_bits_be(bits, usize::from(len))
                .expect("I/O to vector never fails");
        }

        writer.flush_all().expect("I/O to vector never fails");
        let bit_len_final_byte = (writer.n_total_written() % 8) as u8; // cast safety: modulo 8

        if bit_len_final_byte > 0 {
            Err(Error::Padding((bytes, 8 - bit_len_final_byte)))
        } else {
            Ok(bytes)
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Padding((Vec<u8>, u8)),
}

impl Error {
    pub fn unwrap_padding(self) -> Vec<u8> {
        match self {
            Error::Padding((bytes, _)) => bytes,
        }
    }

    pub fn expect_padding(self, bit_len: u8) -> Vec<u8> {
        match self {
            Error::Padding((bytes, padding_len)) => {
                assert_eq!(
                    padding_len, bit_len,
                    "There are actually {} padding bits",
                    padding_len
                );
                bytes
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Padding((bytes, padding_len)) => write!(
                f,
                "There are {} bits of padding in the final byte of {}",
                padding_len,
                bytes.as_hex()
            ),
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
