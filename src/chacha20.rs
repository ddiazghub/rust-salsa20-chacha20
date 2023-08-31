use std::collections::VecDeque;

use super::{Seed, Word, size, ops::*};

pub struct Chacha20 {
    keygen: Keygen,
    keys: VecDeque<Vec<u8>>,
}

impl Chacha20 {
    pub fn with_count(seed: [u8; size::SEED * 4], nonce: u64, current: u64) -> Self {
        Self {
            keygen: Keygen::with_count(bytes_to_word(seed), split(nonce), current),
            keys: VecDeque::new(),
        }
    }

    pub fn new(seed: [u8; size::SEED * 4], nonce: u64) -> Self {
        Self::with_count(seed, nonce, 0)
    }

    pub fn encrypt(&mut self, message: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::new();

        for word in partition(message) {
            let encrypted = self.encrypt_word(&word);
            ciphertext.extend_from_slice(&encrypted);
        }

        ciphertext
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();

        for word in partition(ciphertext) {
            let decrypted = self.decrypt_word(&word);
            message.extend_from_slice(&decrypted);
        }

        message
    }

    pub fn encrypt_word(&mut self, word: &[u8]) -> Vec<u8> {
        let key: Vec<_> = self.keygen.next().unwrap()
            .into_iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();

        let ciphertext = xor_slices(&word, &key).collect();
        self.keys.push_back(key);

        ciphertext
    }

    pub fn decrypt_word(&mut self, word: &[u8]) -> Vec<u8> {
        xor_slices(&word, &self.keys.pop_front().unwrap()).collect()
    }
}

struct Keygen {
    seed: Seed,
    nonce: [u32; size::LONG],
    current: u64
}

impl Keygen {
    pub fn with_count(seed: Seed, nonce: [u32; size::LONG], current: u64) -> Self {
        Self { seed, nonce, current }
    }

    pub fn new(seed: Seed, nonce: [u32; size::LONG]) -> Self {
        Self::with_count(seed, nonce, 0)
    }

    fn pad(&self) -> Word {
        const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
        let mut word = [0; size::WORD];

        word[..4].copy_from_slice(&CONSTANTS);
        word[4..12].copy_from_slice(&self.seed);
        word[12..14].copy_from_slice(&split(self.current));
        word[14..].copy_from_slice(&self.nonce);

        word
    }

    fn quarter_round(pad: &mut [u32], a: usize, b: usize, c: usize, d: usize) {
        pad[a] = add_mod(pad[a], pad[b]);
        pad[d] = rotate(pad[d] ^ pad[a], 16);
        pad[c] = add_mod(pad[c], pad[d]);
        pad[b] = rotate(pad[b] ^ pad[c], 12);
        pad[a] = add_mod(pad[a], pad[b]);
        pad[d] = rotate(pad[d] ^ pad[a], 8);
        pad[c] = add_mod(pad[c], pad[d]);
        pad[b] = rotate(pad[b] ^ pad[c], 7);
    }

    fn permutate(pad: &Word) -> Word {
        const ROUNDS: usize = 20;
        let mut pad = pad.clone();

        for _ in (0..ROUNDS).step_by(2) {
            Self::quarter_round(&mut pad, 0, 4, 8, 12);
            Self::quarter_round(&mut pad, 1, 5, 9, 13);
            Self::quarter_round(&mut pad, 2, 6, 10, 14);
            Self::quarter_round(&mut pad, 3, 7, 11, 15);

            Self::quarter_round(&mut pad, 0, 5, 10, 15);
            Self::quarter_round(&mut pad, 1, 6, 11, 12);
            Self::quarter_round(&mut pad, 2, 7, 8, 13);
            Self::quarter_round(&mut pad, 3, 4, 9, 14);
        }

        pad
    }
}

impl Iterator for Keygen {
    type Item = Word;

    fn next(&mut self) -> Option<Self::Item> {
        let padded = self.pad();
        let permutated = Self::permutate(&padded);
        let ciphertext = add_words(&padded, &permutated);

        self.current = match self.current == u64::MAX {
            true => 0,
            _ => self.current + 1
        };

        Some(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_qr(mut values: [u32; 4], expected: [u32; 4]) {
        Keygen::quarter_round(&mut values, 0, 1, 2, 3);
        assert_eq!(expected, values);
    }

    #[test]
    fn test_pad() {
        let seed = [0x11111111; size::SEED];

        let nonce = 0x2222222222222222;
        let mut generator = Keygen::new(seed, split(nonce));
        generator.current = 0x3333333333333333;

        let expected = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x11111111, 0x11111111, 0x11111111, 0x11111111,
            0x11111111, 0x11111111, 0x11111111, 0x11111111,
            0x33333333, 0x33333333, 0x22222222, 0x22222222,
        ];

        assert_eq!(generator.pad(), expected);
    }

    #[test]
    fn test_quarter_round() {
        let mut initial = [
			0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
			0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
			0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
			0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
		];

		let expected = [
			0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
			0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
			0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
			0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
		];

        Keygen::quarter_round(&mut initial, 2, 7, 8, 13);
        assert_eq!(initial, expected);
    }

    fn test_generator(seed: Seed, expected: Word, nonce: u64) {
        let mut generator = Keygen::new(seed, split(nonce));

        let buffer = generator.next().unwrap();
        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_keygen() {
        let seed = [0; size::SEED];

        let expected = [
            0x76b8e0ad, 0xa0f13d90, 0x405d6ae5, 0x5386bd28,
            0xbdd219b8, 0xa08ded1a, 0xa836efcc, 0x8b770dc7,
            0xda41597c, 0x5157488d, 0x7724e03f, 0xb8d84a37,
            0x6a43b8f4, 0x1518a11c, 0xc387b669, 0xb2ee6586,
        ];

        test_generator(seed, expected, 0x02000000);
    }

    #[test]
    fn encrypt_test() {
        test(
            0x00000000,
            vec![
                42, 129, 33, 161, 137, 35, 27, 149, 115, 154, 192, 232, 160, 76,
                105, 227, 191, 104, 48, 89, 162, 249, 242, 123, 10, 123, 90, 68,
                27, 16, 219, 59, 219, 128, 111, 75, 245, 26, 231, 52, 107, 67, 13,
                79, 81, 158, 1, 86, 11, 50, 35, 238, 166, 23, 112, 201, 114, 197,
                52, 38, 201, 77, 251, 219, 14, 173, 179, 196, 215, 54, 65, 125,
                181, 65, 162, 116, 44, 201, 92, 43, 79, 101, 68, 64, 95, 30, 97,
                108, 254, 161, 159, 254, 10, 59, 177, 76, 76, 79, 41, 89, 234, 74,
                4, 36, 224, 209, 83, 138, 51, 66, 234, 157, 74, 181, 53, 104, 19,
                218, 204, 171, 233, 151, 205, 236, 61, 141, 76, 209, 103, 246, 230,
                85, 129, 125, 34, 84, 68, 39, 240, 59, 9, 244, 168, 11, 134, 89,
                74, 182, 63, 77, 49, 247, 62, 19, 175, 123, 83, 170, 160, 78, 218,
                196, 145, 7, 47, 80, 196, 212, 154, 165, 193, 230, 247, 247, 56,
                132, 231, 146, 154, 132, 177, 83, 67, 251, 90, 71, 4, 52, 246, 25,
                1, 212, 80, 138, 143, 91, 91, 93, 86, 169
            ]
        );

        test(
            0xffffffff,
            vec![
                203, 77, 83, 178, 103, 107, 194, 132, 26, 81, 220, 133, 193, 160,
                108, 82, 236, 56, 88, 206, 169, 188, 55, 39, 180, 2, 107, 47, 246,
                166, 247, 46, 129, 157, 123, 227, 229, 195, 18, 157, 190, 174, 115,
                4, 219, 51, 119, 183, 70, 207, 163, 18, 83, 184, 81, 137, 253, 39,
                215, 80, 15, 19, 106, 144, 188, 107, 158, 236, 61, 112, 250, 187,
                171, 209, 187, 61, 28, 206, 237, 0, 205, 63, 210, 115, 58, 109, 1,
                9, 187, 19, 112, 100, 57, 104, 8, 199, 255, 106, 186, 201, 103, 87,
                26, 28, 12, 87, 232, 39, 103, 193, 215, 58, 147, 20, 31, 86, 210,
                148, 73, 121, 62, 30, 177, 76, 65, 98, 81, 215, 137, 155, 89, 96,
                58, 8, 226, 97, 225, 101, 10, 107, 103, 129, 160, 120, 69, 38, 55,
                168, 23, 111, 143, 209, 52, 58, 168, 181, 101, 146, 102, 181, 137,
                51, 130, 186, 145, 179, 15, 242, 226, 176, 192, 37, 33, 242, 102,
                46, 247, 164, 143, 76, 135, 97, 236, 209, 128, 113, 8, 146, 10,
                167, 139, 179, 44, 123, 60, 56, 133, 88, 133, 116
            ]
        );

        fn test(counter: u64, expected_data: Vec<u8>) {
            let key = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
            ];

            let nonce = u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
            let mut salsa = Chacha20::with_count(key, nonce, counter);
            let message = [7; 200];
            let encrypted = salsa.encrypt(&message);
            assert_eq!(encrypted, expected_data);
            let decrypted = salsa.decrypt(&encrypted);
            assert_eq!(decrypted, message);
        }
    }
}
