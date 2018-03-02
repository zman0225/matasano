#[cfg(test)]
mod test_set4 {
    use conversions::{base64_to_hex, pad_pkcs7, unpad_pkcs7};
    use crypter::{aes_cbc, random_aes_key, random_bytes, aes_ctr};
    use openssl::symm::Mode;
    use combine::{xor_each_no_wrap};
    use text::{profile_for, sanitize_for_url};
    use sha1::{SHA1, generate_sha1_padding};
    use md4::{MD4, generate_md4_padding};

    fn edit(ciphertext: &[u8], new_text: &[u8], key: &[u8], nonce: u64, offset: u8) -> Vec<u8> {
        let mut output = vec!();
        let offset_input = &[&vec![0; offset as usize], new_text].concat();
        aes_ctr(key, offset_input, nonce, &mut output);
        [&ciphertext[..offset as usize], &output[offset as usize..]].concat()
    }

    #[test]
    fn challenge_25() {
        // this question was poorly designed, I assumed it required some kind of brute force
        // however since ctr is super symmetric, we can crack the plaintext just by giving it back the ciphertext
        let plain_text: Vec<Vec<u8>> = include_str!("data/25.txt").lines().map(|l| base64_to_hex(l.to_string())).collect();
        let key = random_aes_key();
        let nonce = 0u64;

        let mut ciphers = vec!();
        for line in plain_text.iter() {
            let mut decrypted = vec!();
            aes_ctr(&key, &line, nonce, &mut decrypted);
            ciphers.push(decrypted);
        }

        let plain_text1 = plain_text.first().unwrap();
        let cipher1 = ciphers.first().unwrap();
        let cracked = edit(cipher1, cipher1, &key, nonce, 0);
        assert_eq!(cracked, *plain_text1);
    }

    // challenge 26
    fn encrypt_ctr_profile(profile_data: &str, key: &[u8], encrypted: &mut Vec<u8>) -> usize {
        let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

        let plain_text = [&prefix[..], &profile_data.as_bytes()[..], &suffix[..]].concat();
        let mut padded_input = plain_text.to_owned().to_vec();
        pad_pkcs7(&mut padded_input, key.len());

        aes_ctr(key, &padded_input, 0u64, encrypted)
    }

    fn is_profile_admin(key: &[u8], cipher_text: &[u8]) -> bool {
        let mut decrypted = vec!();
        aes_ctr(key, &cipher_text, 0u64, &mut decrypted);

        let mut unpadded = decrypted.clone();
        unpad_pkcs7(&mut unpadded);

        let utf_str =  unsafe {
            String::from_utf8_unchecked(unpadded)
        }.replace("%3D", "=").replace("%3B", ";");
        match utf_str.find("role=admin") {
            Some(_) => true,
            None => false,
        }
    }

    #[test]
    fn challenge_26() {
        let plain_text1 = sanitize_for_url(&profile_for("foo@bar.com", "user"));
        let generated_key = random_aes_key();

        let mut encrypted = vec!();
        encrypt_ctr_profile(&plain_text1, &generated_key, &mut encrypted);
        assert_eq!(is_profile_admin(&generated_key, &encrypted), false);


        let plain_text2 = sanitize_for_url(&profile_for("foo@bar.com", "admin"));

        let mut encrypted = vec!();
        encrypt_ctr_profile(&plain_text2, &generated_key, &mut encrypted);

        // lets flip some bit
        encrypted[0] ^= 1;
        encrypted[1] ^= 1;
        encrypted[2] ^= 1;
        assert_eq!(is_profile_admin(&generated_key, &encrypted), true);
    }

    // challenge 27
    fn encrypt_cbc_profile(profile_data: &str, key: &[u8], encrypted: &mut Vec<u8>) -> usize {
        let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

        let plain_text = [&prefix[..], &profile_data.as_bytes()[..], &suffix[..]].concat();
        let mut padded_input = plain_text.to_owned().to_vec();
        pad_pkcs7(&mut padded_input, key.len());

        aes_cbc(key, &padded_input, Some(key), encrypted, Mode::Encrypt)
    }

    #[test]
    fn challenge_27() {
        let plain_text = sanitize_for_url(&profile_for("foo@ab.com", "usernameishigh"));
        let generated_key = random_aes_key();

        let mut encrypted = vec!();
        encrypt_cbc_profile(&plain_text, &generated_key, &mut encrypted);

        // attacker: zero out the second block and replace the third with the first
        let attacked_cipher = [&encrypted[..16], &[0; 16], &encrypted[..16]].concat();

        // now the receiver attempts to decrypt, then raise an error if an ascii is too high in value
        let mut decrypted = vec!();
        aes_cbc(&generated_key, &attacked_cipher, Some(&generated_key), &mut decrypted, Mode::Decrypt);
        let contains_error = decrypted.iter().any(|&c| c >= 127);

        assert!(contains_error);

        // now the attacker, posing as the system receives the plaintext as the invalidated error
        let key = xor_each_no_wrap(&decrypted[..16], &decrypted[32..]);
        assert_eq!(key, generated_key);

        // because it takes c2 to get p3 in the decryption process, when we zero out c2, AND
        // since we replace c3 with c1, p1 is c1 is decrypted with the IV, and c3 is decrypted with zero bytes
        // meaning p'1 ^ p'3 yields the IV, or the key!!!
    }

    // challenge 28+
    fn key_message_digest(key: &[u8], message: &[u8]) -> Vec<u32> {
        let sha1 = SHA1::new();
        sha1.u32_digest(&[key, message].concat()).to_vec()
    }

    #[test]
    fn challenge_28() {
        let key = b"YELLOW SUBMARINE";
        let msg1 = b"LSD";
        let msg2 = b"THC";

        assert!(key_message_digest(&key[..], &msg1[..]) != key_message_digest(&key[..], &msg2[..]));
    }

    #[test]
    fn challenge_29() {
        // we're given the original message and that's it
        // attack relies on the fact we can take the output of sha1 and use it as a new starting point for sha1
        // the output digest is just the h values reassembled
        // sha1 is progressive in the way that it progressively mutates the h values on more data, and that will be
        // the reason we can we extend the input further as such:
        // SHA1(key || original-message || glue-padding || new-message)

        // the key and its length isn't known to us.
        let key = random_bytes();
        let key_length = key.len();
        
        // the original message and thus length is known to us.
        let original_msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
        let message_digest = key_message_digest(&key, &original_msg);
        
        let suffix = ";admin=true".as_bytes();

        let mut sh = SHA1::new();
        sh.disable_padding();

        let mut tmp_reg = [0u32; 5];
        tmp_reg.clone_from_slice(&message_digest[..]);
        sh.update_registers(tmp_reg);

        for guess_key_len in 0..65 {
            let old_padding = generate_sha1_padding((original_msg.len() + guess_key_len) as u64);
            let new_padding = generate_sha1_padding((original_msg.len() + old_padding.len() + suffix.len() + guess_key_len) as u64);

            let new_data = [&suffix[..], &new_padding[..]].concat();
            let new_digest = sh.u32_digest(&new_data);
            if key_message_digest(&key[..], &[&original_msg[..], &old_padding[..], &suffix[..]].concat()) == new_digest {
                assert_eq!(key_length, guess_key_len);
                return;
            }
        }

        panic!("should reach here");
    }

    // challenge 30

    fn key_message_md4(key: &[u8], message: &[u8]) -> Vec<u32> {
        let md4 = MD4::new();
        md4.u32_digest(&[key, message].concat()).to_vec()
    }

    #[test]
    fn challenge_30() {
        // the key and its length isn't known to us.
        let key = random_bytes();
        let key_length = key.len();
        
        // the original message and thus length is known to us.
        let original_msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
        let message_digest = key_message_md4(&key, &original_msg);
        
        let suffix = ";admin=true".as_bytes();

        let mut sh = MD4::new();
        sh.disable_padding();

        let mut tmp_reg = [0u32; 4];
        tmp_reg.clone_from_slice(&message_digest[..]);
        sh.update_registers(tmp_reg);

        for guess_key_len in 0..65 {
            let old_padding = generate_md4_padding((original_msg.len() + guess_key_len) as u64);
            let new_padding = generate_md4_padding((original_msg.len() + old_padding.len() + suffix.len() + guess_key_len) as u64);

            let new_data = [&suffix[..], &new_padding[..]].concat();
            let new_digest = sh.u32_digest(&new_data);

            if key_message_md4(&key[..], &[&original_msg[..], &old_padding[..], &suffix[..]].concat()) == new_digest {
                assert_eq!(key_length, guess_key_len);
                return;
            }
        }

        panic!("should reach here");
    }
}




















