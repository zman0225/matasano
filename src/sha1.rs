use bits::Decomposable;

const DEFAULT_SHA1_REGISTER: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

pub struct SHA1 {
    registers: [u32; 5],
    padding_enabled: bool
}

pub fn generate_sha1_padding(message_len: u64) -> Vec<u8> {
    let zero_bytes = (56 - (message_len + 1 as u64) % 64) % 64;
    let total_bytes = (zero_bytes + 9) as usize;

    let mut retval = vec![0u8; total_bytes];
    retval[0] = 0x80;
    let decomposed: [u8; 8] = u64::decompose((message_len as u64 * 8));
    retval[total_bytes-8..total_bytes].copy_from_slice(&decomposed);
    retval
}

impl SHA1 {
    pub fn new() -> SHA1 {
        SHA1{ registers: DEFAULT_SHA1_REGISTER, padding_enabled: true }
    }

    pub fn update_registers(&mut self, new_regs: [u32; 5]) {
        self.registers = new_regs;
    }

    pub fn disable_padding(&mut self) {
        self.padding_enabled = false;
    }

    pub fn enable_padding(&mut self) {
        self.padding_enabled = true;
    }

    fn _process(&self, message: &[u8]) -> [u32; 5]{
        // source: https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
        // Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
        //         ml, the message length, which is a 64-bit quantity, and
        //         hh, the message digest, which is a 160-bit quantity.
        // Note 2: All constants in this pseudo code are in big endian.
        //         Within each word, the most significant byte is stored in the leftmost byte position

        let mut h: [u32; 5] = self.registers.clone();
        let mut modified_msg = message.clone().to_vec();

        if self.padding_enabled {
            let suffix_padding = generate_sha1_padding(message.len() as u64);
            modified_msg.extend(suffix_padding);
        }

        // Process the message in successive 512-bit chunks:
        // break message into 512-bit chunks, or 64 bytes
        for chunk in modified_msg.chunks(64) {
            // for each chunk
            //     break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            let mut words: Vec<u32> = chunk.chunks(4).map(|word| {
                ((word[0] as u32) << 24) | ((word[1] as u32) << 16) | ((word[2] as u32) << 8) | word[3] as u32
            }).collect();
            words.extend([0u32; 64].iter());

            //     Extend the sixteen 32-bit words into eighty 32-bit words:
            //     for i from 16 to 79
            //         w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
            for idx in 16..80 {
                words[idx] = (words[idx-3] ^ words[idx-8] ^ words[idx-14] ^ words[idx-16]).rotate_left(1); 
            }

            //     Initialize hash value for this chunk:
            let mut a: u32 = h[0].clone();
            let mut b: u32 = h[1].clone();
            let mut c: u32 = h[2].clone();
            let mut d: u32 = h[3].clone();
            let mut e: u32 = h[4].clone();

            for idx in 0..80 {
                let (f, k) = match idx {
                    0...19 => {
                        (d ^ (b & (c ^ d)), 0x5A827999)
                    },
                    20...39 => {
                        (b ^ c ^ d, 0x6ED9EBA1)
                    },
                    40...59 => {
                        ((b & c) | (d & (b | c)), 0x8F1BBCDC)
                    },
                    60...79 => {
                        (b ^ c ^ d, 0xCA62C1D6)
                    },
                    _ => panic!("index invalid"),
                };

                let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(words[idx]);

                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);

        }

        h
    }

    pub fn u32_digest(&self, message: &[u8]) -> [u32; 5] {
        self._process(message)
    }

    pub fn u8_digest(&self, message: &[u8]) -> [u8; 20] {
        let mut retval = [0u8; 20];
        for (idx, h_val) in self._process(message).iter().enumerate(){
            retval[idx*4] = ((h_val & 0xff000000) >> 24) as u8;
            retval[idx*4 + 1] = ((h_val & 0x00ff0000) >> 16) as u8;
            retval[idx*4 + 2] = ((h_val & 0x0000ff00) >> 8) as u8;
            retval[idx*4 + 3] = (h_val & 0x000000ff) as u8;
        }
        retval
    }
}

#[test]
fn validity() {
    use conversions::hex_to_string;
    
    let sha1 = SHA1::new();

    assert_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", hex_to_string(&sha1.u8_digest("".as_bytes())));
    assert_eq!("a9993e364706816aba3e25717850c26c9cd0d89d", hex_to_string(&sha1.u8_digest("abc".as_bytes())));
}
