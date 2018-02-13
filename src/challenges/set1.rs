#[cfg(test)]
mod test_set1 {
    use conversions::{base64_to_hex, hex_to_base64, string_to_hex, hex_to_string};
    use combine::{xor_byte, xor_each};
    use crack::{find_xor_key, guess_key_size, find_repeated_xor_key};
    use crypter::aes_ecb;
    use text::CharFreq;
    use std::f32;
    use openssl::symm::{Cipher, Mode};


    #[test]
    fn challenge_1() {
        let input_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let true_str_val = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
        let hex_rep = string_to_hex(input_str);

        assert_eq!(hex_to_base64(&hex_rep), true_str_val);
        assert_eq!(base64_to_hex(true_str_val), hex_rep);
    }

    #[test]
    fn challenge_2() {
        let x1 = string_to_hex("1c0111001f010100061a024b53535009181c");
        let x2 = string_to_hex("686974207468652062756c6c277320657965");

        let xor_hex = xor_each(&x1, &x2);
        assert_eq!(hex_to_string(&xor_hex), "746865206b696420646f6e277420706c6179");
    }

    #[test]
    fn challenge_3() {
        let bytes = string_to_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let key = find_xor_key(&bytes);
        println!("[challenge_3] {}", String::from_utf8(xor_byte(&bytes, key)).unwrap());

        assert_eq!(key, 'X' as u8);
    }

    #[test]
    fn challenge_4() {
        let content = include_str!("data/4.txt");

        let en = CharFreq::for_english();
        let mut found = None;
        for line in content.lines() {
            let mut best = 1000.0;
            for b in 0x00..0xFF {
                let bytes = string_to_hex(line);
                let s = String::from_utf8(xor_byte(&bytes, b)).unwrap_or("".to_string());
                if s.len() > 0 {
                    let mut c = CharFreq::new();
                    c.count_all(&s);
                    let d = c.dist(&en);
                    if d < 1.0 && d < best {
                        found = Some(s);
                        best = d;
                    }
                }
            }

            if found.is_some(){
                break;
            }
        }
        assert_eq!(found, Some("Now that the party is jumping\n".to_string()));
    }

    #[test]
    fn challenge_5() {
        let content = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";

        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
        a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        let encrypted = xor_each(content.as_bytes(), key.as_bytes());
        assert_eq!(expected, hex_to_string(&encrypted));
    }


    #[test]
    fn challenge_6() {
        let en = CharFreq::for_english();
        let cipher_lines: Vec<&str> = include_str!("data/6.txt").lines().collect();
        let cipher_text: String = cipher_lines.join("");
        let cipher = base64_to_hex(cipher_text);

        let mut best_message = (f32::MAX, "".to_string());

        for key_size in guess_key_size(&cipher) {
            let key = find_repeated_xor_key(&cipher, key_size);
            let message = xor_each(&cipher, &key);

            // lower score is better for histogram
            let msg_string = String::from_utf8(message).unwrap();
            let score = en.dist_from_string(&msg_string);
            if score < best_message.0 {
                best_message = (score, msg_string);
            }
        }
        assert!(best_message.1.starts_with("I'm back and I'm ringin' the bell"));
    }


    #[test]
    fn challenge_7() {
        const KEY: &'static str = "YELLOW SUBMARINE";
        let cipher_lines: Vec<&str> = include_str!("data/7.txt").lines().collect();
        let cipher_text: String = cipher_lines.join("");
        let cipher = base64_to_hex(cipher_text);
        println!("Decoding {} char cipher", cipher.len());

        let block_size = Cipher::aes_128_ecb().block_size();
        let mut msg = vec![0; cipher.len() + block_size];
        let count = aes_ecb(KEY.as_bytes(), &cipher, None, &mut msg, Mode::Decrypt);
        msg.truncate(count);

        assert!(msg.len() > 0);
        let msg_string = String::from_utf8(msg).unwrap();
        assert!(msg_string.starts_with("I'm back and I'm ringin' the bell"));
    }


    #[test]
    fn challenge_8() {
        use std::collections::HashMap;

        // load the cipher from file
        let ciphers: Vec<Vec<u8>> = include_str!("data/8.txt").lines().map(|l| string_to_hex(l)).collect();
        let mut dupeidx = vec!();

        // iterate through each line of the cipher
        for cipher in ciphers.iter() {

            // initialize a hashmap
            let mut block_counts: HashMap<Vec<u8>, usize> = HashMap::new();
            
            // chunk each into a 128 bit context
            for block in cipher.chunks(16) {
                // have we seen this before?
                let count = block_counts.entry(block.to_owned()).or_insert(0);
                *count += 1;
            }
            // sum up all the duplicate cipher blocks and insert into vec
            let dupes = block_counts.iter().fold(0, |acc, (_, count)| acc + count - 1);
            dupeidx.push(dupes)
        }

        let mut found_idx = (0, 0); // idx, dupes
        for (idx, dupes) in dupeidx.iter().enumerate() {
            if *dupes > found_idx.1 {
                found_idx = (idx, *dupes);
            }
        }
        assert!(found_idx.1 > 0);
        println!("win? {:?}", found_idx);
    }
}