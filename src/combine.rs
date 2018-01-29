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


pub fn xor_byte(source: &[u8], with: u8) -> Vec<u8> {
    xor_each(source, &[with])
}

