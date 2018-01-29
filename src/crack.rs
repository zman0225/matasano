use openssl::symm::{Crypter, Cipher, Mode};

pub fn find_xor_key(m: &[u8]) -> u8 {
	use combine::xor_byte;
	use std::f32;
	use text::CharFreq;

	let en = CharFreq::for_english();

	// xor, distance from en, string
	let mut best = (0x0, f32::MAX);

	for b in 0x00..0xff {
	    let s = String::from_utf8(xor_byte(m, b)).unwrap_or("".to_string());
	    if s.len() > 0 {
	        let mut c = CharFreq::new();
	        c.count_all(&s);

	        let d = c.dist(&en);
	        if d < best.1 {
	            best = (b, d);
	        }
	    }
	}
	best.0
}

pub fn guess_key_size(cipher: &[u8]) -> Vec<usize>{
	use measure::hamming;
	let mut best = (vec!(8.0 as f32), vec!(cipher.len() as usize));
	let threshold = 0.10;

	for ks in 2..40 {
	    let mut chunks = cipher.chunks(ks);
	    let mut total_diff = 0.0;
	    let mut pairs = 0;
	    while let (Some(a), Some(b)) = (chunks.next(), chunks.next()) {
	        pairs += 1;
	        total_diff += hamming(a, b) as f32;
	    }

	    let diff = (total_diff / pairs as f32) / ks as f32;
	    let best_avg = best.0.iter().fold(0.0, |acc, &x| acc + x) / best.0.len() as f32;
	    let per_diff = ((best_avg - diff) / best_avg).abs();

	    // if the percentage diff is less than 0.1
	    if per_diff < threshold {
	    	best.0.push(diff);
	    	best.1.push(ks);
	    // if the best average is greater than diff, (diff is good)
	    } else if diff < best_avg{
	    	best = (vec!(diff), vec!(ks));
	    }
	}
	best.1
}

pub fn find_repeated_xor_key(cipher: &[u8], key_size: usize) -> Vec<u8> {
    let mut blocks: Vec<Vec<u8>> = vec!();
    let chunks = cipher.chunks(key_size);
    for chunk in chunks {
    	for (idx, block) in chunk.iter().enumerate() {
    	    if blocks.len() <= idx {
    	    	blocks.push(vec!(*block));
    	    } else if let Some(b) = blocks.get_mut(idx) {
    	    	b.push(*block);
    	    }
    	}
    }
    blocks.iter().map(|v| find_xor_key(v)).collect()
}


pub fn aes_ecb(key: &str, cipher: &[u8], msg: &mut [u8], mode: Mode) -> usize{
    let mut c = Crypter::new(
        Cipher::aes_128_ecb(),
        mode,
        key.as_bytes(),
        None
    ).unwrap();
    c.pad(false);

    let mut count = c.update(&cipher, &mut *msg).unwrap();
    count += c.finalize(&mut msg[count..]).unwrap();
    count
}

pub fn aes_cbc(key: &str, cipher: &[u8], iv: &[u8], msg: &mut Vec<u8>, mode: Mode, block_size: usize) -> usize {
	use combine::xor_each;

	let mut count = 0;
	let mut prev = iv.to_vec();

    for block in cipher.chunks(block_size){
    	let mut tmp = vec![0 as u8; block.len() + block_size].to_owned();
    	count += match mode {
    	    Mode::Encrypt => {
    	    	let c = aes_ecb(key, &xor_each(&block, &prev), &mut tmp, mode);
    	    	tmp.truncate(c);
    	    	prev = tmp.to_owned();
    	    	c
    	    },
    	    Mode::Decrypt => {
    	    	let c = aes_ecb(key, &block, &mut tmp, mode);
    	    	tmp.truncate(c);
    	    	tmp = xor_each(&tmp, &prev);
    	    	prev = block.to_owned();
    	    	c
    	    },
    	};
    	msg.extend(&tmp);
    }
    count
}