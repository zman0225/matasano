// referenced from: https://github.com/jakerr/cryptopals-rust/blob/master/src/combine.rs


pub fn xor_each(source: &[u8], with: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let xiter = with.iter().cycle(); // repeats an iterator endlessly

    let pairs = source.iter().zip(xiter);
    for (a, b) in pairs {
        v.push(a ^ b);
    }
    v
}

pub fn xor_each_no_wrap(source: &[u8], with: &[u8]) -> Vec<u8> {
	use std::cmp;
	let min_len = cmp::min(source.len(), with.len());
    xor_each(&source[..min_len], &with[..min_len])
}


pub fn xor_byte(source: &[u8], with: u8) -> Vec<u8> {
    xor_each(source, &[with])
}

