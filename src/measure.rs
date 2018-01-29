pub fn hamming(a: &[u8], b: &[u8]) -> u32{
	a.iter().zip(b.iter()).fold(0, |acc, (a, b)| (a^b).count_ones() + acc)
}

#[test]
fn test_hamming() {
    let str1 = "this is a test".as_bytes();
    let str2 = "wokka wokka!!!".as_bytes();

    assert_eq!(hamming(&str1, &str2), 37);
}
