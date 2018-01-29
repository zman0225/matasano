#[allow(unused_imports)]
use conversions::{base64_to_hex, hex_to_base64, string_to_hex, hex_to_string, pad_hex};
#[allow(unused_imports)]
use combine::{xor_byte, xor_each};
#[allow(unused_imports)]
use crack::{find_xor_key, guess_key_size, find_repeated_xor_key, aes_cbc};
#[allow(unused_imports)]
use text::CharFreq;
#[allow(unused_imports)]
use measure::hamming;
#[allow(unused_imports)]
use std::f32;
#[allow(unused_imports)]
use openssl::symm::{Crypter, Cipher, Mode};


#[test]
fn challenge_9() {
    // we have to take care of padding here
    // 'YELLOW SUBMARINE' -> HEX -> add 20 bytes
    let mut hex_rep = String::from("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE").into_bytes();
    pad_hex(&mut hex_rep, 20);
    assert_eq!(hex_rep.len() % 20, 0);
}

#[test]
fn challenge_10() {
	let cipher_lines: Vec<&str> = include_str!("data/10.txt").lines().collect();
	let original_cipher = base64_to_hex(cipher_lines.join(""));
	let block_size = Cipher::aes_128_ecb().block_size();

    let mut decrypted = vec!();
	aes_cbc(&"YELLOW SUBMARINE", &original_cipher, &[0 as u8; 16], &mut decrypted, Mode::Decrypt, block_size);
	assert!(String::from_utf8(decrypted.clone()).unwrap().starts_with("I\'m back and I\'m ringin\'"));

    let mut encrypted = vec!();
	aes_cbc(&"YELLOW SUBMARINE", &decrypted, &[0 as u8; 16], &mut encrypted, Mode::Encrypt, block_size);

	assert_eq!(encrypted, original_cipher);
}