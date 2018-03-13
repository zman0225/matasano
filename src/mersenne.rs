// MT19937
// (w, n, m, r) = (32, 624, 397, 31)
// a = 9908B0DF16
// (u, d) = (11, FFFFFFFF16)
// (s, b) = (7, 9D2C568016)
// (t, c) = (15, EFC6000016)
// l = 18
use std::fs::File;
use std::io::Read;

pub struct MTRng {
    _seed: u32,
    _w: u32,
    n: u32,
    m: u32,
    _r: u32,
    a: u32,
    u: u32,
    d: u32,
    s: u32,
    c: u32,
    t: u32,
    b: u32,
    l: u32,
    _index: usize,
    pub _mt: Vec<u32>,
}

fn read_urandom() -> u32 {
    let mut v = [0u8; 4];
    let mut file = File::open("/dev/urandom")
        .expect("failed to open /dev/urandom");
    file.read_exact(&mut v).expect("failed to read /dev/urandom");
    (v[0] as u32) << 24 | ((v[1] as u32) << 16) | ((v[2] as u32) << 8) | v[3] as u32
}

impl MTRng {
    pub fn mt19937(_seed: u32) -> MTRng {
    	let f: u32 = 0x6C078965;
    	let mut _mt = vec![0; 624];
    	_mt[0] = _seed;

    	for idx in 1..624 {
    		let last_val = _mt[(idx-1) as usize];
            let new_val = f.wrapping_mul(last_val ^ (last_val >> 30)).wrapping_add(idx as u32);
    		_mt[idx] = new_val;
    	}

        MTRng {
        	_w: 32,
        	n: 624,
        	m: 397,
        	_r: 31,
        	a: 0x9908B0DF,
        	u: 11,
        	d: 0xFFFFFFFF,
        	s: 7,
        	b: 0x9D2C5680,
        	t: 15,
			c: 0xEFC60000,
			l: 18,
			_index: 0,
			_mt,
        	_seed 
        }
    }

    pub fn new() -> MTRng {
        Self::mt19937(read_urandom())
    }

    pub fn generate_number(&mut self) {
        for idx in 0..624 {
        	let y = (self._mt[idx] & 0x80000000) + (self._mt[(idx + 1) % self.n as usize] & 0x7fffffff);
        	self._mt[idx] = self._mt[(idx + self.m as usize) % self.n as usize] ^ (y >> 1);
        	if y % 2 != 0 {
        		self._mt[idx] ^= self.a;
        	}
        }
    }

    pub fn u32(&mut self) -> u32 {
    	if self._index == 0 {
    		self.generate_number();
    	}

    	let mut y: u32 = self._mt[self._index as usize];
    	y ^= y >> self.u & self.d;
    	y ^= (y << self.s) & self.b;
    	y ^= (y << self.t) & self.c;
    	y ^= y >> self.l;

    	self._index = (self._index + 1) % 624;
    	y
    }

    pub fn u8(&mut self) -> u8 {
    	self.u32() as u8
    }

    pub fn undo_right_shift_xor(&self, y: u32, l: u32) -> u32 {
        // first self.l of y' is going to be same as y
    	// we need to undo y^= y >> self.l which is the same as y = y' ^ (y' >> self.l) 
    	// communicatively it is the same as y' = y ^ (y' >> self.l), which means the first self.l
    	// significant bits are the same for y' and y [y[..14]][18 bits left to find out ]
    	let s = 32 - l;
		(l..32).fold(y >> s << s, |z, x| {
	    	// lets make space for the new byte
	    	let y = 1 & (y >> (31 - x));
	    	let y_p = 1 & (z.checked_shr(31 - x + l).unwrap_or(0));
			z | (y_p ^ y) << (31 - x)
	    })
    }

    pub fn undo_left_shift_xor(&self, y: u32, l: u32, k: u32) -> u32 {
        // same with the right side
	    // y = y' ^ ((y' << self.t) & self.c) 
	    // same as: y' = y ^ ((y' << self.t) & self.c), we need to operate from least significant now
	    // so for the last (32 - self.t) bits, it is the same as y, since left shifting y' will vacate
	    // self.t trailing zeros
	    let s = 32 - l;
	    (l..32).fold(y << s >> s, |z, x| {
	    	let y = 1 & (y >> x); 
	    	let y_p = 1 & (z >> (x - l));
	    	let k = 1 & (k >> x);
	    	z | (y ^ (y_p & k)) << x
	    })
    }

    pub fn untemper(&self, y: u32) -> u32 {
    	let y1 = self.undo_right_shift_xor(y, self.l);
    	let y2 = self.undo_left_shift_xor(y1, self.t, self.c);
	    let y3 = self.undo_left_shift_xor(y2, self.s, self.b);
		self.undo_right_shift_xor(y3, self.u)
	}
}

