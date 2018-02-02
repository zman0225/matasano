use openssl::symm::{Crypter, Cipher, Mode};
use rand::{thread_rng, Rng};
use conversions::{base64_to_hex, pad_pkcs7};

pub fn aes_ecb(key: &[u8], cipher: &[u8], iv: Option<&[u8]>, msg: &mut Vec<u8>, mode: Mode) -> usize{
    let mut c = Crypter::new(
        Cipher::aes_128_ecb(),
        mode,
        key,
        iv
    ).unwrap();
    c.pad(false);

    let mut count = c.update(&cipher, &mut *msg).unwrap();
    count += c.finalize(&mut msg[count..]).unwrap();
    msg.truncate(count);
    count
}

pub fn aes_cbc(key: &[u8], cipher: &[u8], iv: Option<&[u8]>, msg: &mut Vec<u8>, mode: Mode) -> usize {
	use combine::xor_each;

    let block_size = Cipher::aes_128_ecb().block_size();

	let mut count = 0;
	let mut prev = iv.unwrap().to_vec();

    for block in cipher.chunks(block_size){
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

pub fn random_aes_key() -> Vec<u8> {
    let mut rng = thread_rng();
    rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>()
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

pub fn consistent_ecb(key: &Vec<u8>, plaintext: &[u8], msg: &mut Vec<u8>, ) -> usize {
    let suffix = String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    
    let mut mod_plaintext: Vec<u8> = vec!();
    mod_plaintext.extend(plaintext);
    mod_plaintext.extend(base64_to_hex(suffix));
    pad_pkcs7(&mut mod_plaintext, key.len());
    msg.extend(vec![0; mod_plaintext.len() + key.len()]);
    aes_ecb(&key, &mod_plaintext, None, &mut *msg, Mode::Encrypt)
}

