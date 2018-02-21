#[cfg(test)]
mod test_set4 {
    use itertools::Itertools;
    use std::cmp::min;
    use conversions::{hex_to_base64, base64_to_hex, unpad_pkcs7, pad_pkcs7, pkcs7_validate};
    use crypter::{aes_cbc, random_aes_key, random_bytes, aes_ctr};
    use openssl::symm::Mode;
    use combine::{xor_each_no_wrap};
    use crack::{find_xor_key};
    use mersenne::MTRng;
    use rand::{thread_rng, Rng};
    use std::time::{SystemTime, UNIX_EPOCH};
    use text::{profile_for, sanitize_for_url};

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
    fn encrypt_cbc_profile(profile_data: &str, key: &[u8], encrypted: &mut Vec<u8>) -> usize {
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
        encrypt_cbc_profile(&plain_text1, &generated_key, &mut encrypted);
        assert_eq!(is_profile_admin(&generated_key, &encrypted), false);


        let plain_text2 = sanitize_for_url(&profile_for("foo@bar.com", "admin"));

        let mut encrypted = vec!();
        encrypt_cbc_profile(&plain_text2, &generated_key, &mut encrypted);

        // lets flip some bit
        encrypted[0] ^= 1;
        encrypted[1] ^= 1;
        encrypted[2] ^= 1;
        assert_eq!(is_profile_admin(&generated_key, &encrypted), true);
    }
}




















