#[allow(unused_imports)]
use conversions::{base64_to_hex, hex_to_base64, string_to_hex, hex_to_string, pad_pkcs7, unpad_pkcs7};
#[allow(unused_imports)]
use combine::{xor_byte, xor_each};
#[allow(unused_imports)]
use crack::{find_xor_key, guess_key_size, find_repeated_xor_key};
#[allow(unused_imports)]
use crypter::{aes_ecb, aes_cbc, encryption_oracle, consistent_ecb, random_aes_key};
#[allow(unused_imports)]
use text::CharFreq;
#[allow(unused_imports)]
use measure::hamming;
#[allow(unused_imports)]
use std::f32;
#[allow(unused_imports)]
use openssl::symm::{Crypter, Cipher, Mode};
use std::collections::HashMap;

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

fn find_block_size(key: &Vec<u8>, plain_text: &mut Vec<u8>) -> usize {
    let block_size;
    let mut cipher_text = vec!();
    consistent_ecb(&key, &plain_text, &mut cipher_text);
    loop {
        plain_text.push(0);
        let cipher_size = cipher_text.len();
        let count = consistent_ecb(&key, &plain_text, &mut cipher_text);
        if count != cipher_size{
            block_size = count - cipher_size; 
            break;
        }
    }
    block_size
}

fn confirm_ecb(block_size: usize, key: &Vec<u8>, plain_text: &mut Vec<u8>) {
    plain_text.clear();
    plain_text.extend(vec![0; 3*block_size]);

    let mut cipher_text = vec!();
    consistent_ecb(&key, &plain_text, &mut cipher_text);
    assert_eq!(cipher_text[0..16], cipher_text[16..32]);
}

#[test]
fn challenge_12() {
    let generated_key = random_aes_key();
    let mut plain_text: Vec<u8> = vec!();
    let mut cipher_text: Vec<u8> = vec!();

    // 1. find block size
    let block_size = find_block_size(&generated_key, &mut plain_text);
    assert_eq!(block_size, 16);

    // 2. confirm that it is ECB
    confirm_ecb(block_size, &generated_key, &mut plain_text);

    let mut decrypted: Vec<u8> = vec!(); 

    // solve, we can systemically replace a single value of known spot in the plaintext
    loop {
        let mut dict: HashMap<Vec<u8>, u8> = HashMap::new();

        // we need to prepad the prefix so that we always know the last character
        plain_text.clear();
        plain_text.extend(vec![0; block_size - (decrypted.len()%block_size) - 1]);
        for last_byte in 0x00..0xFF {
            cipher_text.clear();
            let try_plain_text = [&plain_text[..], &decrypted[..], &[last_byte]].concat();
            consistent_ecb(&generated_key, &try_plain_text, &mut cipher_text);
            dict.insert(cipher_text[..try_plain_text.len()].to_owned(), last_byte);
        }

        cipher_text.clear();
        consistent_ecb(&generated_key, &plain_text, &mut cipher_text);
        if decrypted.len()+plain_text.len()+1 >= cipher_text.len() {
            break;
        }   
        let query = cipher_text[..decrypted.len()+plain_text.len()+1].to_vec();
        if let Some(next_byte) = dict.get(&query) {
            decrypted.push(*next_byte);
            
        } else {
            break;
        }
    }
    let result = String::from_utf8(decrypted);
    println!("answer is {:?}", result.unwrap());
}


fn profile_for(email: &str) -> String {
    use text::kv_encode;
    let sanitized_email = email.replace('@', "").replace('=',"");
    let obj: HashMap<String, String> = [
        ("email".to_string(), sanitized_email),
        ("uid".to_string(), "10".to_string()),
        ("role".to_string(), "user".to_string())
    ].iter().cloned().collect();

    kv_encode(obj)
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

