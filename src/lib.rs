pub mod chacha20;
pub mod salsa20;

mod size {
    pub const INT: usize = 32;
    pub const WORD: usize = 512 / INT;
    pub const SEED: usize = 256 / INT;
    pub const LONG: usize = 64 / INT;
    pub const KEY_SPACE: u64 = 1 << 63;
}

mod masks {
    pub const LOW: u64 = (1 << super::size::INT) - 1;
    pub const HIGH: u64 = LOW << super::size::INT;
}

mod ops {
    use std::{mem, ops::BitXor};

    use super::{size, masks, Word};

    pub fn rotate(n: u32, places: u32) -> u32 {
        let places = places & ((1 << 5) - 1);

        (n << places) | n.checked_shr(32 - places).unwrap_or(0)
    }

    pub fn split(n: u64) -> [u32; size::LONG] {
        [mod32(n), ((n & masks::HIGH) >> size::INT) as u32]
    }

    pub fn mod32(n: u64) -> u32 {
        (n & masks::LOW) as u32
    }

    pub fn add_mod(a: u32, b: u32) -> u32 {
        mod32(a as u64 + b as u64)
    }

    pub fn xor_words<const S: usize>(a: &[u32; S], b: &[u32; S]) -> [u32; S] {
        let mut result = [0; S];

        for i in 0..S {
            result[i] = a[i] ^ b[i];
        }

        result
    }

    pub fn add_words<const S: usize>(a: &[u32; S], b: &[u32; S]) -> [u32; S] {
        let mut result = [0; S];

        for i in 0..S {
            result[i] = add_mod(a[i], b[i]);
        }

        result
    }

    /// Transforms an AES Key from its byte array representation, to a 32 bit unsigned integer
    /// array representation. Groups of 4 bytes are made to create each integer.
    pub fn words_to_bytes<const S: usize>(words: [u32; S]) -> Vec<u8> {
        words.into_iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    /// Transforms an AES Key from its u32 array representation to an array of bytes.
    pub fn bytes_to_word<const S: usize, const W: usize>(bytes: [u8; S]) -> [u32; W] {
        let mut words = [0; W];

        for (i, chunk) in bytes.chunks(4).enumerate() {
            words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        words
    }

    pub fn bytes_to_u64(bytes: &[u8]) -> u64 {
        let mut padded = [0; mem::size_of::<u64>()];
        let len = padded.len();
        padded[len - bytes.len()..].copy_from_slice(bytes);

        u64::from_le_bytes(padded)
    }

    pub fn xor_slices<'a, 'b, T: BitXor<Output = T> + Copy>(a: &'a [T], b: &'b [T]) -> impl Iterator<Item = T> + 'a + 'b
    where
        'b: 'a,
        'a: 'b
    {
        a.into_iter()
            .copied()
            .zip(b.into_iter().copied())
            .map(|(a, b)| a ^ b)
    }

    pub fn partition(message: &[u8]) -> impl Iterator<Item = &[u8]> {
        message.chunks(64)
    }
}

pub type Seed = [u32; size::SEED];
pub type Word = [u32; size::WORD];
pub type Key = [u8; size::WORD * 4];

#[cfg(test)]
mod tests {
    use super::ops::*;

    #[test]
    fn test_add_words() {
        // Test case 1: Adding arrays of zeros should result in an array of zeros
        let a1 = [0, 0, 0, 0];
        let b1 = [0, 0, 0, 0];
        let result1 = [0, 0, 0, 0];
        assert_eq!(add_words(&a1, &b1), result1);

        // Test case 2: Adding arrays with all positive values
        let a2 = [1, 2, 3, 4];
        let b2 = [5, 6, 7, 8];
        let result2 = [6, 8, 10, 12];
        assert_eq!(add_words(&a2, &b2), result2);

        // Test case 3: Adding arrays with larger values
        let a4 = [100, 200, 300, 400];
        let b4 = [50, 50, 50, 50];
        let result4 = [150, 250, 350, 450];
        assert_eq!(add_words(&a4, &b4), result4);
    }

    #[test]
    fn test_xor_words() {
        // Test case 1: XOR of arrays of zeros should result in an array of zeros
        let a1 = [0, 0, 0, 0];
        let b1 = [0, 0, 0, 0];
        let result1 = [0, 0, 0, 0];
        assert_eq!(xor_words(&a1, &b1), result1);

        // Test case 2: XOR of arrays with all ones
        let a2 = [0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF];
        let b2 = [0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF, 0xFFFFFFF];
        let result2 = [0, 0, 0, 0];
        assert_eq!(xor_words(&a2, &b2), result2);

        // Test case 3: XOR of arrays with alternating values
        let a3 = [0b10101010, 0b01010101, 0b10101010, 0b01010101];
        let b3 = [0b01010101, 0b10101010, 0b01010101, 0b10101010];
        let result3 = [0b11111111, 0b11111111, 0b11111111, 0b11111111];
        assert_eq!(xor_words(&a3, &b3), result3);
    }

    #[test]
    fn test_rotate() {
        // Test case 1: Rotation by 0 places should result in the same number
        assert_eq!(rotate(12345678, 0), 12345678);

        // Test case 2: Rotation by the number of bits in the type should result in the same number
        assert_eq!(rotate(0xFFF0000, 32), 0xFFF0000);

        // Test case 3: Regular rotations
        assert_eq!(rotate(0b1100, 1), 0b11000);
        assert_eq!(rotate(0b10101, 2), 0b1010100);
        assert_eq!(rotate(0b111111, 4), 0b1111110000);
        assert_eq!(rotate(0b10101010, 8), 0b1010101000000000);

        // Test case 4: Rotations greater than the number of bits should wrap around
        assert_eq!(rotate(0xaa000000, 4), 0xa000000a);
        assert_eq!(rotate(0xf0000000, 5), 0x1e);
    }

    #[test]
    fn test_split() {
        // Test case 1: Splitting 0 should result in two u32 zeros
        assert_eq!(split(0), [0, 0]);

        // Test case 2: Splitting a number where the lower 32 bits are all ones
        assert_eq!(split(0xFFFFFFFF), [0, 0xFFFFFFFF]);

        // Test case 3: Splitting a number where the higher 32 bits are all ones
        assert_eq!(split(0xFFFFFFFF00000000), [0xFFFFFFFF, 0]);

        // Test case 4: Splitting a number with mixed significant bits
        assert_eq!(split(0xABCD1234DEADBEEF), [0xABCD1234, 0xDEADBEEF]);

        // Test case 5: Splitting the largest possible u64 number
        assert_eq!(split(u64::MAX), [0xFFFFFFFF, 0xFFFFFFFF]);
    }
}
