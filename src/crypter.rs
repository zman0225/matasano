use openssl::symm::{Crypter, Cipher, Mode};
use rand::{thread_rng, Rng};
use conversions::{base64_to_hex, pad_pkcs7};
use std::collections::HashMap;
use std::mem::transmute;
use combine::xor_each;


pub fn aes_ecb(key: &[u8], input: &[u8], iv: Option<&[u8]>, msg: &mut Vec<u8>, mode: Mode) -> usize{
    let mut c = Crypter::new(
        Cipher::aes_128_ecb(),
        mode,
        key,
        iv
    ).unwrap();
    c.pad(false);

    let mut count = c.update(&input, &mut *msg).unwrap();
    count += c.finalize(&mut msg[count..]).unwrap();
    msg.truncate(count);
    count
}

pub fn aes_cbc(key: &[u8], input: &[u8], iv: Option<&[u8]>, msg: &mut Vec<u8>, mode: Mode) -> usize {

    let block_size = Cipher::aes_128_ecb().block_size();

	let mut count = 0;
	let mut prev = iv.unwrap().to_vec();

    for block in input.chunks(block_size){
    	let mut tmp = vec![0 as u8; block.len() + block_size].to_owned();
    	count += match mode {
    	    Mode::Encrypt => {
    	    	let c = aes_ecb(key, &xor_each(&block, &prev), None, &mut tmp, mode);
    	    	tmp.truncate(c);
    	    	prev = tmp.to_owned();
    	    	c
    	    },
    	    Mode::Decrypt => {
    	    	let c = aes_ecb(key, &block, None, &mut tmp, mode);
    	    	tmp.truncate(c);
    	    	tmp = xor_each(&tmp, &prev);
    	    	prev = block.to_owned();
    	    	c
    	    },
    	};
    	msg.extend(&tmp);
    }
    msg.truncate(count);
    count
}

pub fn aes_ctr(key: &[u8], input: &[u8], nonce: u64, msg: &mut Vec<u8>) -> usize {
    for (idx, chunk) in input.chunks(key.len()).enumerate() {
        let mut nonce_bytes: [u8; 8] = unsafe { transmute(nonce as u64) };
        let mut block_count: [u8; 8] = unsafe { transmute((idx as u64).to_be()) };

        nonce_bytes.reverse();
        block_count.reverse();

        let key_stream = &[nonce_bytes, block_count].concat();
        let mut output = vec![0 as u8; key_stream.len() + key.len()].to_owned();

        // it's actually irrelevant what the mode is, as long as encryption and decryption is the same
        aes_ecb(key, key_stream, None, &mut output, Mode::Encrypt);
        let xored = xor_each(chunk, &output);
        msg.extend(xored);
    }
    msg.len()
}

pub fn random_aes_key() -> Vec<u8> {
    let mut rng = thread_rng();
    rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>()
}

pub fn random_bytes(min: usize, max: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let len = if min == max { max } else { rng.gen_range(min, max) as usize };
    rng.gen_iter::<u8>().take(len).collect::<Vec<u8>>()
}

pub fn encryption_oracle(plaintext: &[u8], msg: &mut Vec<u8>) -> String {
    let mut rng = thread_rng();

    let key = random_aes_key();
    let iv = random_aes_key();
    let key_size = key.len();

    // pad the plaintext
    let mut padded_plaintext = plaintext.to_owned().to_vec();
    pad_pkcs7(&mut padded_plaintext, key_size);

    // allocate for msg
    msg.extend(vec![0; padded_plaintext.len() + key_size]);

    let mode: &str;
    let fnc = if rng.gen::<bool>() {
        mode = "ECB";
        aes_ecb
    } else {
        msg.clear();
        mode = "CBC";
        aes_cbc
    };
    fnc(&key, &padded_plaintext, Some(&iv), &mut *msg, Mode::Encrypt);
    String::from(mode)
}

pub fn consistent_ecb(key: &Vec<u8>, prefix: &Vec<u8>, plaintext: &[u8], msg: &mut Vec<u8>) -> usize {
    let suffix = String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    
    let mut mod_plaintext: Vec<u8> = vec!();
    mod_plaintext.extend(prefix);
    mod_plaintext.extend(plaintext);

    mod_plaintext.extend(base64_to_hex(suffix));
    pad_pkcs7(&mut mod_plaintext, key.len());
    msg.extend(vec![0; mod_plaintext.len() + key.len()]);
    aes_ecb(&key, &mod_plaintext, None, &mut *msg, Mode::Encrypt)
}

// challenge 12
fn find_block_size(key: &Vec<u8>, plain_text: &mut Vec<u8>) -> usize {
    let block_size;
    let mut cipher_text = vec!();
    consistent_ecb(&key, &vec!(), &plain_text, &mut cipher_text);
    loop {
        plain_text.push(0);
        let cipher_size = cipher_text.len();
        let count = consistent_ecb(&key, &vec!(), &plain_text, &mut cipher_text);
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
    consistent_ecb(&key, &vec!(), &plain_text, &mut cipher_text);
    assert_eq!(cipher_text[0..16], cipher_text[16..32]);
}

fn generate_next_byte(generated_key: &Vec<u8>, block_size: usize, prefix: &Vec<u8>, prefix_size: usize) -> String {
    let mut decrypted: Vec<u8> = vec!(); 
    let mut cipher_text: Vec<u8> = vec!();
    let mut plain_text: Vec<u8> = vec!();

    // the prefix padding at the end
    let prefix_pad_size = if prefix_size > 0 { block_size - (prefix_size % block_size) } else { 0 };
    let prefix_len_round_down = prefix_size - (prefix_size % block_size);

    // will always be a multiple of 16
    let encrypted_prefix_len = prefix_pad_size + prefix_len_round_down;
    
    // solve, we can systemically replace a single value of known spot in the plaintext
    loop {
        let mut dict: HashMap<Vec<u8>, u8> = HashMap::new();
        let decrypted_pad_size = block_size - (decrypted.len() % block_size);

        // we need to prepad the prefix so that we always know the last character
        plain_text.clear();
        plain_text.extend(vec![0; prefix_pad_size + decrypted_pad_size - 1]);
        for last_byte in 0x00..0xFF {
            cipher_text.clear();
            let try_plain_text = [&plain_text[..], &decrypted[..], &[last_byte]].concat();
            consistent_ecb(&generated_key, prefix, &try_plain_text, &mut cipher_text);
            dict.insert(cipher_text[encrypted_prefix_len..encrypted_prefix_len+try_plain_text.len()].to_owned(), last_byte);
        }

        cipher_text.clear();
        consistent_ecb(&generated_key, prefix, &plain_text, &mut cipher_text);
        if prefix_size + decrypted.len() + plain_text.len()+1 >= cipher_text.len() {
            break;
        }   
        let query = cipher_text[encrypted_prefix_len..encrypted_prefix_len+decrypted.len()+plain_text.len()+1].to_vec();
        
        if let Some(next_byte) = dict.get(&query) {
            decrypted.push(*next_byte);
        } else {
            break;
        }
    }
    String::from_utf8(decrypted).unwrap()
}

// challenge 14
fn ecb_match_blocks(key: &Vec<u8>, prefix: &[u8], block_size: usize) -> usize {
    let mut plain_text = vec!();
    
    plain_text.extend(prefix);

    let mut digest1 = vec!();
    let mut digest2 = vec!();

    consistent_ecb(key, &vec!(), &plain_text, &mut digest1);    
    plain_text.push(0);
    consistent_ecb(key, &vec!(), &plain_text, &mut digest2);

    let (mut c1, mut c2) = (digest1.chunks(block_size), digest2.chunks(block_size));
    for i in 0..c1.len(){
        if c1.next().unwrap() != c2.next().unwrap() {
            return i;
        }
    }
    0
}

fn find_prefix_size(key: &Vec<u8>, prefix: &[u8], block_size: usize) -> usize {
    // so we know that ECB is the same for blocks only
    // 1. find all the same blocks first, then find left over blocks
    
    let blocks_matched = ecb_match_blocks(key, prefix, block_size);

    let mut mod_prefix = prefix.to_vec();

    for i in 0..16 {
        mod_prefix.insert(0,0);

        let new_matched = ecb_match_blocks(key, &mod_prefix, block_size);
        if new_matched != blocks_matched {
            return blocks_matched * block_size + block_size - i - 1;
        }
    }
    blocks_matched * block_size
}

pub fn ecb_oracle(plain_text: &mut Vec<u8>, prefix: Vec<u8>) -> String {
    let generated_key = random_aes_key();
    
    // 1. find block size
    let block_size = find_block_size(&generated_key, plain_text);
    assert_eq!(block_size, 16);

    // 2. confirm that it is ECB
    confirm_ecb(block_size, &generated_key, plain_text);

    // 3. find the length of the prefix
    let prefix_size = if prefix.len() > 0 { find_prefix_size(&generated_key, &prefix, block_size) } else { 0 };
    assert_eq!(prefix_size, prefix.len());

    generate_next_byte(&generated_key, block_size, &prefix, prefix_size)
}

