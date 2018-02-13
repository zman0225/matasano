// reference: https://github.com/jakerr/cryptopals-rust/blob/master/src/conversions.rs

use std::iter::Iterator;

const BASE_64: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn hex_to_char(short: u8) -> char {
    match short {
        0x0...0x9 => (short + '0' as u8) as char,
        0xa...0xf => (short - 0xa + 'a' as u8) as char,
        _ => panic!("hex_to_char only converts short values between 0x0 and 0xf"),
    }
}


fn char_to_hex(c: char) -> u8 {
    match c {
        '0'...'9' => (c as u8 - '0' as u8),
        'a'...'f' => 10 + (c as u8 - 'a' as u8),
        _ => panic!("char_to_hex only converts char values between '0' and 'f'"),
    }
}


pub fn hex_to_string(hex: &[u8]) -> String {
    hex.iter().map(|x| {
    	// since each u8 contains two hex characters
    	// we need to extract the first, then second
    	let h = (x & 0xF0) >> 4;
    	let l = x & 0x0F;
    	format!("{}{}", hex_to_char(h), hex_to_char(l))
    }).collect()
}


pub fn string_to_hex(string: &str) -> Vec<u8> {
    let mut v = Vec::new();
    let mut cs = string.chars();
    loop {
        let pair = (cs.next(), cs.next());
        match pair {
            (Some(h), Some(l)) => {
            	// each char needs to be converted into hex value
            	let h = char_to_hex(h);
            	let l = char_to_hex(l);

            	// combine the two to make a byte, packed u8
            	let byte = (h << 4) | l;
            	v.push(byte);
            },
            (Some(_), None) => panic!("Strings need pairs (even numbers of characters to be \
            considered valid hex"),
            _ => break,
        }
    }
    v
}


//wrapper for bits manipulation
struct Bits<'a> {
    hex: &'a [u8],
    // idx of the byte we are on
    idx: usize,

    // idx of the bit id we are on
    bidx: usize,

    // size of the bits stride
    stride: usize,
}


impl <'a>Bits<'a> {
    fn new(hex: &'a [u8], stride: usize) -> Bits<'a> {
    	assert!(stride <= 8);
    	Bits {hex, stride, idx: 0, bidx: 0}
    }

    // bite ensures that we return the next n bits, that is less or equal to 8 bits
    // meaning that bite only processes 1 byte at a time
    fn bite(&mut self, bits: usize) -> (usize, u8) {
    	// lets figure out how many bits are left remaining in a 8 bits max context
    	let remain = 8 - self.bidx;

    	// lets calculate the number of bits to ignore here
    	// if we need 6 bits, then we have 2 bits remaining, we need 8 - 6 (2) bits to ignore
    	let ignore = if remain > bits {
    		remain - bits
    	} else {
    		0
    	};

    	// how many bits read? (8 - 2 == 6)
    	let read = remain - ignore;

    	let byte;
    	if let Some(b) = self.hex.get(self.idx) {
    		// we shift left by the bits idx (already processed those)
    		// then we shift right by (0 + 2)
    	    byte = (b << self.bidx) >> (self.bidx + ignore);
    	} else {
    		return (0, 0);
    	}

    	self.bidx += read;
    	assert!(self.bidx <= 8);

    	if self.bidx == 8 {
    		self.bidx = 0;
    		self.idx += 1;
    	}
    	(read, byte)
    }
}

impl <'a>Iterator for Bits<'a> {
	type Item = u8;

	fn next(&mut self) -> Option<u8> {
		let mut need = self.stride;
		let (high_read, high_byte) = self.bite(need);
		if high_read == 0 {
			return None;
		}

		need = need - high_read;

		let (_, low_byte) = if need > 0 {
			self.bite(need)
		} else {
			(0, 0)
		};

		Some((high_byte << need) | low_byte)
	}
}


pub fn hex_to_base64(hex: &[u8]) -> String {
	// we need to take strides of 4x6 bits 
	// each hex is 4 bits in representation, we need to compact u8 together 
	let mut b = Bits::new(hex, 6);
	let mut s = String::new();

	loop {
	    let set = (b.next(), b.next(), b.next(), b.next());
	    match set {
	        (None, _, _, _) => break,
	        (Some(h1), Some(h2), m, l) => {
	        	s.push(BASE_64[h1 as usize] as char);
	        	s.push(BASE_64[h2 as usize] as char);
	        	match m {
	        	    Some(m) => s.push(BASE_64[m as usize] as char),
	        	    _ => s.push('='),
	        	};
	        	match l {
	        	    Some(l) => s.push(BASE_64[l as usize] as char),
	        	    _ => s.push('='),
	        	};
	        },
	        _ => unreachable!(),
	    }
	}
	s
}


fn base64_inverse(c: char) -> Option<u8> {
	BASE_64.iter().position(|x| c == *x as char).map(|x| x as u8)
}


// Takes a base64 encoded string and returns the vector of bytes that it decodes to 
pub fn base64_to_hex(string: String) -> Vec<u8> {
	let mut v = Vec::new();
	let mut chars = string.chars();
	loop {
	    let set = (chars.next(), chars.next(), chars.next(), chars.next());
	    match set {
	        (None, _, _, _) => break,
	        (Some(a), Some(b), Some(c), Some(d)) => {
	        	let mut h = base64_inverse(a).unwrap() << 2;
	        	let mut m = base64_inverse(b).unwrap();
	        	h |= m >> 4;
	        	m <<= 4;
	        	v.push(h);

	        	let mut l = 0;
	        	match base64_inverse(c) {
	        	    Some(c) => {
	        	    	m |= c >> 2;
	        	    	l = c << 6;
	        	    	v.push(m)
	        	    },
	        	    _ => (),
	        	}

	        	match base64_inverse(d) {
	        	    Some(d) => {
	        	    	l |= d;
	        	    	v.push(l)
	        	    },
	        	    _ => (),
	        	}
	        },
	        _ => panic!("Invalid base64. Inproperly padded"),
	    }
	}
	v
}


// if valid returns the length to truncate, else return original length
// should not call this if we know its not padded
fn pkcs7_truncate_len(text: &[u8]) -> usize{
    let text_len = text.len();
    let last = text[text.len() - 1];

    if text_len == 0 || last > 16 { return text.len() }

    for i in text_len - last as usize .. text_len {
        if last != text[i] {
            return text_len;
        }
    }
    text_len - last as usize
}

pub fn pkcs7_validate(text: &[u8]) -> bool {
    pkcs7_truncate_len(text) != text.len()
}

pub fn unpad_pkcs7(text: &mut Vec<u8>) {
    let truncate_len = pkcs7_truncate_len(&text);
    text.truncate(truncate_len);
}

pub fn pad_pkcs7(text: &mut Vec<u8>, len: usize) {
    let mod_len = text.len() % len;
    let remaining = len - mod_len;

    if remaining > 0 && remaining != len{
         let pad = vec![remaining as u8; remaining];
         text.extend(pad);
    } 
}



















































