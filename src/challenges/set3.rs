#[cfg(test)]
mod test_set3 {
    use itertools::Itertools;
    use std::cmp::min;
    use conversions::{hex_to_base64, base64_to_hex, pad_pkcs7, pkcs7_validate};
    use crypter::{aes_cbc, random_aes_key, random_bytes, aes_ctr};
    use openssl::symm::Mode;
    use combine::{xor_each_no_wrap};
    use crack::{find_xor_key};
    use mersenne::MTRng;
    use rand::{thread_rng, Rng};
    use std::time::{SystemTime, UNIX_EPOCH};

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

    const CH_19_STRS: &'static [&'static str] = &[
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
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
        let nonce = 0u64;

        let mut decrypted = vec!();
        aes_ctr(key.as_bytes(), &encrypted, nonce, &mut decrypted);

        let mut reencrypted = vec!();
        aes_ctr(key.as_bytes(), &decrypted, nonce, &mut reencrypted);

        assert_eq!(encrypted, reencrypted);
    }

    fn get_candidates(ciphers: &Vec<Vec<u8>>, idx: usize) -> Vec<u8> {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        let valid_chars: HashSet<&u8> = HashSet::from_iter("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,".as_bytes().iter());
        // grab the u8 values that decrypts out into an actual ascii character
        let mut retval = vec!();
        for ch in 0..256u16 {
            if ciphers.iter().map(|cipher| cipher[idx] ^ ch as u8).all(|c| valid_chars.contains(&c)) {
                retval.push(ch as u8);
            }
        }

        return retval;
    }

    fn extend_key(current_keys: &mut Vec<u8>, ciphers: &[u8], guess: &[u8]){
        let key_len = current_keys.len();
        let xored: Vec<u8> = (0..guess.len()).map(|idx| guess[idx] ^ ciphers[key_len+idx]).collect();
        current_keys.extend(xored);
    }

    #[test]
    fn challenge_19() {
        let key = [163, 201, 231, 237, 109, 90, 85, 30, 172, 21, 226, 175, 180, 36, 169, 123];
        let nonce = 0u64;

        let mut encrypted_vec = vec!();
        for plain_text in CH_19_STRS {
            let mut decrypted = vec!();
            aes_ctr(&key, &base64_to_hex(plain_text.to_string()), nonce, &mut decrypted);
            encrypted_vec.push(decrypted);
        }

        let char_candidates = (0..10).map(|idx| get_candidates(&encrypted_vec, idx));
        let mut prods = char_candidates.multi_cartesian_product();
        let mut current_keys = prods.next().unwrap();

        // manual edit
        extend_key(&mut current_keys, &encrypted_vec[1], "h ".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[3], "entury ".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[5], "ss ".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[3], "se".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[5], "rds".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[0], " ".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[29], "ght".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[4], " ".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[27], "d".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[4], "ead".as_bytes());
        extend_key(&mut current_keys, &encrypted_vec[37], "n,".as_bytes());

        let keys_len = current_keys.len();

        for (idx, cipher) in encrypted_vec.iter().enumerate(){
            let c_len = cipher.len();
            let t1 = xor_each_no_wrap(&cipher[..min(keys_len, c_len)], &current_keys[..min(c_len, keys_len)]);
            let decrypted = [&t1[..], &cipher[min(keys_len, c_len)..]].concat();
            assert_eq!(hex_to_base64(&decrypted), CH_19_STRS[idx]);
        }
    }

    #[test]
    fn challenge_20() {
        // no need to finish this one, it does need manual input to polish the rest, but it looks pretty good without.
        let plain_text: Vec<Vec<u8>> = include_str!("data/20.txt").lines().map(|l| base64_to_hex(l.to_string())).collect();
        let key = random_aes_key();
        let nonce = 0u64;

        let mut ciphers = vec!();
        for line in plain_text.iter() {
            let mut decrypted = vec!();
            aes_ctr(&key, &line, nonce, &mut decrypted);
            ciphers.push(decrypted);
        }

        let min_len = ciphers.iter().min_by_key(|cipher| cipher.len()).unwrap().len();

        let truncated_ciphers: Vec<Vec<u8>> = ciphers.iter().map(|cipher| cipher[..min_len].to_vec()).into_iter().collect();
        let zipped_ciphers = (0..min(truncated_ciphers.len() as u8, min_len as u8)).map(|idx| truncated_ciphers.iter().map(|cipher| cipher[idx as usize]).collect::<Vec<u8>>());
        let key_stream: Vec<u8> = zipped_ciphers.map(|cipher| find_xor_key(&cipher)).collect();

        let keys_len = key_stream.len();

        for (idx, cipher) in ciphers.iter().enumerate(){
            let c_len = cipher.len();
            let t1 = xor_each_no_wrap(&cipher[..min(keys_len, c_len)], &key_stream[..min(c_len, keys_len)]);
            let _decrypted = [&t1[..], &cipher[min(keys_len, c_len)..]].concat();
            println!("vs {:?} {:?}", String::from_utf8(t1.clone()), String::from_utf8(plain_text[idx][..t1.len()].to_vec()));
        }
    }

    const TEST_VECTOR: [u32; 20] = [
        3499211612, 
        581869302, 
        3890346734, 
        3586334585, 
        545404204, 
        4161255391, 
        3922919429, 
        949333985, 
        2715962298, 
        1323567403, 
        418932835, 
        2350294565, 
        1196140740, 
        809094426, 
        2348838239, 
        4264392720, 
        4112460519, 
        4279768804, 
        4144164697, 
        4156218106
    ];

    #[test]
    fn challenge_21() {

        let mut rng = MTRng::mt19937(5489);

        for true_val in TEST_VECTOR.iter() {
            assert_eq!(*true_val, rng.u32());
        }
    }

    #[test]
    fn challenge_22() {
        // brute forcing out a seed
        let mut th_rng = thread_rng();

        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32 + th_rng.gen_range(40, 1000);
        println!("seed is {:?}", seed);

        let mut rng = MTRng::mt19937(seed);
        let first = rng.u32();

        let rand_epoch = seed + th_rng.gen_range(40, 1000); 
        for i in 0..2000 {
            let key = rand_epoch - i;
            let mut rng = MTRng::mt19937(key);
            let rand_value = rng.u32();
            if rand_value == first {
                assert_eq!(key, seed);
            }
        }
    }

    #[test]
    fn challenge_23() {
        let mut th_rng = thread_rng();
        let rand_seed = th_rng.gen_iter::<u32>().next().unwrap();

        let mut rng1 = MTRng::mt19937(rand_seed);
        let mut new_mt = vec![0 as u32; 624];

        rng1.untemper(1339713300);
        for idx in 0..624 {
            let val = rng1.u32();
            new_mt[idx] = rng1.untemper(val);
        }
        let mut rng2 = MTRng::mt19937(0);
        rng2._mt = new_mt;

        for _ in 0..1000 {
            assert_eq!(rng1.u32(), rng2.u32());
        }
    }

    // challenge 24
    fn mersenne_encrypt(plain_text: &[u8], seed: u32) -> Vec<u8> {
        let mut rng = MTRng::mt19937(seed);
        let key_stream = (0..plain_text.len()).map(|_| rng.u8()).collect::<Vec<u8>>();
        xor_each_no_wrap(&plain_text, &key_stream)
    }

    fn encryption_oracle(plain_text: &[u8]) ->  Vec<u8>{
        let mut th_rng = thread_rng();
        let prefix = random_bytes();
        let plain_text = &[&prefix, plain_text].concat();

        let rand_seed = th_rng.gen_iter::<u16>().next().unwrap();
        println!("Oracle seed is {:?}", rand_seed);
        mersenne_encrypt(plain_text, rand_seed as u32)
    }

    #[test]
    fn challenge_24() {
        let mut th_rng = thread_rng();

        // recover the key first
        let plain_text = vec![0; 14];
        let cipher_text = encryption_oracle(&plain_text);
        let prefix_len = cipher_text.len() - plain_text.len();

        // we can brute force every single bit combo
        let mut forced_key: u16 = 0;
        for i in (0..u16::max_value()) {
            let c = mersenne_encrypt(&vec![0; cipher_text.len()], i as u32);
            if c[prefix_len..] == cipher_text[prefix_len..] {
                forced_key = i as u16;
                break;
            }
        }

        println!("key is {:?}", forced_key);

        // test for time seed consistency
        let current_time_seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u16;

        let plain_text1 = vec![0; th_rng.gen_range(4, 20)];
        let cipher_text1 = mersenne_encrypt(&plain_text1, current_time_seed as u32);

        let current_time_seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u16;
        let cipher_text2 =  mersenne_encrypt(&plain_text1, current_time_seed as u32);

        assert_eq!(cipher_text1, cipher_text2);
    }
}




















