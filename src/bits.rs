//src: https://github.com/zsck/rust-md4/blob/master/src/md4/bits.rs
/// Decomposable is a trait for types that can be broken down into multiple units
/// of a smaller type.
pub trait Decomposable<T> {
    fn decompose(Self) -> T;
}

/// u16 can be decomposed into two bytes.
impl Decomposable<[u8; 2]> for u16 {
    fn decompose(n: u16) -> [u8; 2] {
        [(n >> 8) as u8, n as u8]
    }
}

/// u32 can be decomposed into four bytes.
impl Decomposable<[u8; 4]> for u32 {
    fn decompose(n: u32) -> [u8; 4] {
        [(n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    }
}

/// u64 can be decomposed into eight bytes.
impl Decomposable<[u8; 8]> for u64 {
    fn decompose(n: u64) -> [u8; 8] {
        [(n >> 56) as u8, (n >> 48) as u8, (n >> 40) as u8, (n >> 32) as u8,
         (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    }
}

/// u64 can be decoded into four words.
impl Decomposable<[u16; 4]> for u64 {
    fn decompose(n: u64) -> [u16; 4] {
        [(n >> 48) as u16, (n >> 32) as u16, (n >> 16) as u16, n as u16]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u16_splits() {
        let parts: [u8; 2] = u16::decompose(0b0000000100000001);
        assert_eq!(parts[0], 0b00000001);
        assert_eq!(parts[1], 0b00000001);
    }

    #[test]
    fn u32_splits() {
        let parts: [u8; 4] = u32::decompose(0x0FFF00F0);
        assert_eq!(parts[0], 0x0F);
        assert_eq!(parts[1], 0xFF);
        assert_eq!(parts[2], 0x00);
        assert_eq!(parts[3], 0xF0);
    }

    #[test]
    fn u64_splits() {
        let parts: [u8; 8] = u64::decompose(0x00FFF00FAAA00ACC);
        assert_eq!(parts[0], 0x00);
        assert_eq!(parts[1], 0xFF);
        assert_eq!(parts[2], 0xF0);
        assert_eq!(parts[3], 0x0F);
        assert_eq!(parts[4], 0xAA);
        assert_eq!(parts[5], 0xA0);
        assert_eq!(parts[6], 0x0A);
        assert_eq!(parts[7], 0xCC);
    }

    #[test]
    fn u64_to_words() {
        let parts: [u16; 4] = u64::decompose(0x00FFF00FAAA00ACC);
        assert_eq!(parts[0], 0x00FF);
        assert_eq!(parts[1], 0xF00F);
        assert_eq!(parts[2], 0xAAA0);
        assert_eq!(parts[3], 0x0ACC);
    }
}