use flow_cipher::{*, salsa20::Salsa20, chacha20::Chacha20};

pub fn main() {
    exercise3();
}

fn exercise1() {
    let seed: [u8; 32] = [
        0x47, 0xf5, 0x15, 0xb1,
        0xdd, 0x45, 0xf8, 0xd5,
        0xac, 0xee, 0xa7, 0x3b,
        0x52, 0x97, 0x1b, 0xe2,
        0x1f, 0x7b, 0x4b, 0x33,
        0x55, 0xa3, 0x5f, 0xd6,
        0xa2, 0x79, 0x98, 0x98,
        0xed, 0x2f, 0x8c, 0x9,
    ];

    let counter = u64::from_be_bytes([
        0x72, 0x2d, 0x9d, 0x57,
        0x0a, 0xc2, 0x32, 0x01,
    ]);

    let nonce = u64::from_be_bytes([
        0xed, 0x53, 0x9c, 0xd9,
        0x9e, 0x1d, 0x2f, 0x20,
    ]);

    let seed = ops::bytes_to_word(seed);
    let nonce = ops::split(nonce);
    let salsa = salsa20::Keygen::with_count(seed, nonce, counter);
    println!("Salsa pad: {:x?}", salsa.pad());
    let chacha = chacha20::Keygen::with_count(seed, nonce, counter);
    println!("Chacha pad: {:x?}", chacha.pad());
}

fn exercise2() {
    let a = u32::from_be_bytes(hex::decode("c2619378").unwrap().try_into().unwrap());
    let b = u32::from_be_bytes(hex::decode("ecdaec96").unwrap().try_into().unwrap());
    let c = u32::from_be_bytes(hex::decode("e62bd0c8").unwrap().try_into().unwrap());
    let d = u32::from_be_bytes(hex::decode("2b61be56").unwrap().try_into().unwrap());
    let mut values = [a, b, c, d];
    let mut values2 = values.clone();

    println!("Before = {values:x?}");
    salsa20::Keygen::quarter_round(&mut values, 0, 1, 2, 3);
    chacha20::Keygen::quarter_round(&mut values2, 0, 1, 2, 3);
    println!("After Salsa = {values:x?}");
    println!("After Chacha = {values2:x?}");
}

fn exercise3() {
    let seed: [u8; 32] = [
        0x47, 0xf5, 0x15, 0xb1,
        0xdd, 0x45, 0xf8, 0xd5,
        0xac, 0xee, 0xa7, 0x3b,
        0x52, 0x97, 0x1b, 0xe2,
        0x1f, 0x7b, 0x4b, 0x33,
        0x55, 0xa3, 0x5f, 0xd6,
        0xa2, 0x79, 0x98, 0x98,
        0xed, 0x2f, 0x8c, 0x9,
    ];

    let counter = u64::from_be_bytes([
        0x72, 0x2d, 0x9d, 0x57,
        0x0a, 0xc2, 0x32, 0x01,
    ]);

    let nonce = u64::from_be_bytes([
        0xed, 0x53, 0x9c, 0xd9,
        0x9e, 0x1d, 0x2f, 0x20,
    ]);

    let seed = ops::bytes_to_word(seed);
    let nonce = ops::split(nonce);
    let salsa = salsa20::Keygen::with_count(seed, nonce, counter);
    let chacha = chacha20::Keygen::with_count(seed, nonce, counter);
    println!("Salsa permutation:");
    let perm = salsa20::Keygen::permutate(&salsa.pad());
    println!("permutation: {perm:x?}");

    println!("Chacha permutation:");
    let perm = chacha20::Keygen::permutate(&chacha.pad());
    println!("permutation: {perm:x?}");
}
