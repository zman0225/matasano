#[allow(unused_imports)]
use conversions::{base64_to_hex, hex_to_base64, string_to_hex, hex_to_string, pad_pkcs7, unpad_pkcs7, pkcs7_validate};
#[allow(unused_imports)]
use combine::{xor_byte, xor_each};
#[allow(unused_imports)]
use crack::{find_xor_key, guess_key_size, find_repeated_xor_key};
#[allow(unused_imports)]
use crypter::{aes_ecb, aes_cbc, encryption_oracle, consistent_ecb, random_aes_key, random_bytes, ecb_oracle};
#[allow(unused_imports)]
use text::{CharFreq, profile_for};
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
    pad_pkcs7(&mut hex_rep, 20);
    assert_eq!(hex_rep.len() % 20, 0);
}

#[test]
fn challenge_10() {
    let cipher_lines: Vec<&str> = include_str!("data/10.txt").lines().collect();
    let original_cipher = base64_to_hex(cipher_lines.join(""));

    let mut decrypted = vec!();
    aes_cbc(&"YELLOW SUBMARINE".as_bytes(), &original_cipher, Some(&[0 as u8; 16]), &mut decrypted, Mode::Decrypt);
    assert!(String::from_utf8(decrypted.clone()).unwrap().starts_with("I\'m back and I\'m ringin\'"));

    let mut encrypted = vec!();
    aes_cbc(&"YELLOW SUBMARINE".as_bytes(), &decrypted, Some(&[0 as u8; 16]), &mut encrypted, Mode::Encrypt);

    assert_eq!(encrypted, original_cipher);
}


#[test]
fn challenge_11() {
    use rand::{thread_rng, Rng};

    // We just check for block duplicates 
    let plaintext = "00000000000000000000000000000000000000000000000";

    // lets first add some random prefix and suffix to it
    let mut rng = thread_rng();
    let (prefix_len, suffix_len) = (rng.gen_range(5,10), rng.gen_range(5,10));
    let mut final_plaintext = rng.gen_iter::<u8>().take(prefix_len).collect::<Vec<u8>>();
    let suffix = rng.gen_iter::<u8>().take(suffix_len).collect::<Vec<u8>>();

    final_plaintext.extend_from_slice(plaintext.as_bytes());
    final_plaintext.extend(suffix);

    // then we need to pad it up
    let mut encrypted = vec!(); 
    let mode = encryption_oracle(&final_plaintext, &mut encrypted);

    // the gist here is that we can dictate the input, so we need to use some like 00...00
    // to detect ECB
    let guessed_mode = if encrypted[16..32] == encrypted[32..48] {
        "ECB"
    } else { "CBC" };
    assert_eq!(guessed_mode, mode);
}

#[test]
fn challenge_12() {
    let result = ecb_oracle(&mut vec!(), vec!());
    println!("answer is {:?}", result);
}

#[test]
fn challenge_13() {
    use conversions::pad_pkcs7;

    let plaintext = profile_for("foo@bar.com");
    let generated_key = random_aes_key();

    let mut padded_plaintext = plaintext.as_bytes().to_owned().to_vec();
    pad_pkcs7(&mut padded_plaintext, generated_key.len());
    let mut encrypted = vec![0; generated_key.len() + padded_plaintext.len()];
    aes_ecb(&generated_key, &padded_plaintext, None, &mut encrypted, Mode::Encrypt);

    let mut decrypted = vec![0; generated_key.len() + padded_plaintext.len()];
    aes_ecb(&generated_key, &encrypted, None, &mut decrypted, Mode::Decrypt);

    unpad_pkcs7(&mut decrypted);
    assert_eq!(plaintext.as_bytes(), &decrypted[..]);
}

#[test]
fn challenge_14() {
    let prefix = random_bytes().to_vec();
    let result = ecb_oracle(&mut vec!(), prefix);
    println!("answer is {:?}", result);
}

#[test]
fn challenge_15() {
    let valid_bytes = "ICE ICE BABY\x04\x04\x04\x04".as_bytes();
    let invalid_bytes1 = "ICE ICE BABY\x05\x05\x05\x05".as_bytes();
    let invalid_bytes2 = "ICE ICE BABY\x01\x02\x03\x04".as_bytes();
    
    assert_eq!(pkcs7_validate(&valid_bytes), true);
    assert_eq!(pkcs7_validate(&invalid_bytes1), false);
    assert_eq!(pkcs7_validate(&invalid_bytes2), false);
}