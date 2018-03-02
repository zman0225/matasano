use bits::Decomposable;


const DEFAULT_MD4_REGISTER: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

pub struct MD4 {
    registers: [u32; 4],
    padding_enabled: bool
}

pub fn generate_md4_padding(message_len: u64) -> Vec<u8> {
    let zero_bytes = (56 - (message_len + 1 as u64) % 64) % 64;
    let total_bytes = (zero_bytes + 9) as usize;

    let mut retval = vec![0u8; total_bytes];
    retval[0] = 0x80;
    let mut decomposed: [u8; 8] = u64::decompose((message_len as u64 * 8));
    decomposed.reverse();
    retval[total_bytes-8..total_bytes].copy_from_slice(&decomposed);
    retval
}

impl MD4 {
    pub fn new() -> MD4 {
        MD4{ registers: DEFAULT_MD4_REGISTER, padding_enabled: true }
    }

    pub fn update_registers(&mut self, new_regs: [u32; 4]) {
        self.registers = new_regs;
    }

    pub fn disable_padding(&mut self) {
        self.padding_enabled = false;
    }

    pub fn enable_padding(&mut self) {
        self.padding_enabled = true;
    }

    fn _process(&self, message: &[u8]) -> [u32; 4]{
        let mut state: [u32; 4] = self.registers.clone();

        // Process the message in successive 512-bit chunks:
        // break message into 512-bit chunks, or 64 bytes

        let mut message = message.clone().to_vec();
        if message.len() == 0 {
            let suffix_padding = generate_md4_padding(message.len() as u64);
            message.extend(suffix_padding);
        }

        for block in message.chunks(64) {
            let mut block = block.clone().to_vec();
            if self.padding_enabled && block.len() != 64 {
                let suffix_padding = generate_md4_padding(message.len() as u64);
                block.extend(suffix_padding);
            }

            // helper funcs
            fn f(x: u32, y: u32, z: u32) -> u32 {
                (x & y) | (!x & z)
            }

            fn g(x: u32, y: u32, z: u32) -> u32 {
                (x & y) | (x & z) | (y & z)
            }

            fn h(x: u32, y: u32, z: u32) -> u32 {
                x ^ y ^ z
            }

            fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
                a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
            }

            fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
                a.wrapping_add(g(b, c, d)).wrapping_add(k)
                    .wrapping_add(0x5A82_7999).rotate_left(s)
            }

            fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
                a.wrapping_add(h(b, c, d)).wrapping_add(k)
                    .wrapping_add(0x6ED9_EBA1).rotate_left(s)
            }

            let mut registers = state.clone();

            // load block to words of 32 bits
            let mut data: Vec<u32> = block.chunks(4).map(|word| {
                ((word[3] as u32) << 24) | ((word[2] as u32) << 16) | ((word[1] as u32) << 8) | word[0] as u32
            }).collect();
            
            // round 1
            let s = [3,7,11,19];
            for r in 0..16 {
                let (i, k) = ((16-r)%4, r);
                registers[i] = op1(registers[i], registers[(i+1)%4], registers[(i+2)%4], registers[(i+3)%4], data[k], s[r%4]);
            }

            // round 2
            let s = [3,5,9,13];
            for r in 0..16 {
                let (i, k) = ((16-r)%4, 4*(r%4) + r/4);
                registers[i] = op2(registers[i], registers[(i+1)%4], registers[(i+2)%4], registers[(i+3)%4], data[k], s[r%4]);
            }
            // round 3
            let s = [3,9,11,15];
            let k = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15];
            for r in 0..16  {
                let i = (16-r)%4;
                registers[i] = op3(registers[i], registers[(i+1)%4], registers[(i+2)%4], registers[(i+3)%4], data[k[r]], s[r%4]);
            }
            for (idx, s) in state.iter_mut().enumerate() {
                *s = s.wrapping_add(registers[idx]);
            }
        }
        state
    }

    pub fn u32_digest(&self, message: &[u8]) -> [u32; 4] {
        self._process(message)
    }

    pub fn u8_digest(&self, message: &[u8]) -> [u8; 16] {
        let mut retval = [0u8; 16];
        for (idx, h_val) in self._process(message).iter().enumerate(){
            retval[idx*4 + 3] = ((h_val & 0xff000000) >> 24) as u8;
            retval[idx*4 + 2] = ((h_val & 0x00ff0000) >> 16) as u8;
            retval[idx*4 + 1] = ((h_val & 0x0000ff00) >> 8) as u8;
            retval[idx*4 + 0] = (h_val & 0x000000ff) as u8;
        }
        retval
    }
}

#[test]
fn validity() {
    use conversions::hex_to_string;
    
    let md4 = MD4::new();
    assert_eq!("31d6cfe0d16ae931b73c59d7e0c089c0", hex_to_string(&md4.u8_digest("".as_bytes())));
    assert_eq!("a448017aaf21d8525fc10ae87aa6729d", hex_to_string(&md4.u8_digest("abc".as_bytes())));
}
