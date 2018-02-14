

#[cfg(test)]
mod test_set2 {
    use conversions::{hex_to_base64, base64_to_hex, pad_pkcs7, pkcs7_validate};
    use crypter::{aes_cbc, random_aes_key, aes_ctr};
    use openssl::symm::Mode;
    
    const CH_17_STRS: &'static [&'static str] = &[
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ];
    
    fn is_cbc_padding_valid(key: &[u8], cipher_text: &[u8]) -> bool {
        let mut decrypted = vec!();
        aes_cbc(&key, &cipher_text, Some(&[0 as u8; 16]), &mut decrypted, Mode::Decrypt);
        let retval = pkcs7_validate(&decrypted);
        retval
    }

    // cipher is the cipher block, known_p is our currently solved plain text, known c is our
    // current C'
    fn solve_block(key: &[u8], cipher_1: &[u8], cipher_2: &[u8], known_p: &mut Vec<u8>) {
        let block_size = cipher_2.len();
        let mut known_c = vec!();

        for idx in (0..16).rev() {
            // we need to solve each byte now
            for _c in 0..256 {
                let c_prime = _c as u8;
                let padding = (block_size - idx) as u8;

                let zero_prefix = vec![0; block_size - known_c.len() - 1];
                let suffix: Vec<u8> = known_c.iter().map(|k| k ^ padding).collect();
                let test_cipher = [&zero_prefix, &vec![c_prime], &suffix, cipher_2].concat();
                if is_cbc_padding_valid(&key, &test_cipher) {
                    let c1 = cipher_1[idx];
                    let new_c_prime = padding ^ c_prime;
                    let last_byte =  new_c_prime ^ c1;

                    known_c.insert(0, new_c_prime);
                    known_p.insert(0, last_byte);
                    break;
                }
            }           
        }
    }

    fn cbc_padding_attack(key: &[u8], iv: &[u8], encrypted: &[u8]) -> Vec<u8>{
        let combined = &[iv, encrypted].concat();
        let mut chunks = combined.chunks(16).rev();
        let mut retval: Vec<u8> = vec!();

        let mut last = chunks.next().unwrap();
        while let Some(iv) = chunks.next() {
            let mut known_p = vec!();
            solve_block(key, &iv, &last, &mut known_p);

            known_p.extend(retval);
            retval = known_p;
            last = iv;
        }
        retval
    }

    #[test]
    fn challenge_17() {
        // 1. randomly pick
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();

        let iv = random_aes_key();

        let rand_idx = rng.gen_range(0, CH_17_STRS.len()); 
        let rand_str = base64_to_hex(String::from(CH_17_STRS[rand_idx]));
        let generated_key = random_aes_key();

        let mut padded_plaintext = rand_str.clone();
        pad_pkcs7(&mut padded_plaintext, generated_key.len());

        let mut encrypted = vec!();
        aes_cbc(&generated_key, &padded_plaintext, Some(&iv), &mut encrypted, Mode::Encrypt);
        assert_eq!(cbc_padding_attack(&generated_key, &iv, &encrypted), padded_plaintext);
    }

    #[test]
    fn challenge_18() {
        let encrypted = base64_to_hex("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".to_string());
        let key = "YELLOW SUBMARINE";

        let mut decrypted = vec!();
        aes_ctr(key.as_bytes(), &encrypted, 0u64, &mut decrypted);

        let mut reencrypted = vec!();
        aes_ctr(key.as_bytes(), &decrypted, 0u64, &mut reencrypted);

        assert_eq!(encrypted, reencrypted);
    }
}




















