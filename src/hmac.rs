// Wikipedia pseudocode
// Function hmac
//    Inputs:
//       key:        Bytes     array of bytes
//       message:    Bytes     array of bytes to be hashed
//       hash:       Function  the hash function to use (e.g. SHA-1)
//       blockSize:  Integer   the block size of the underlying hash function (e.g. 64 bytes for SHA-1)
//       outputSize: Integer   the output size of the underlying hash function (e.g. 20 bytes for SHA-1)
 
//    Keys longer than blockSize are shortened by hashing them
//    if (length(key) > blockSize) then
//       key ← hash(key) //Key becomes outputSize bytes long
   
//    Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
//    if (length(key) < blockSize) then
//       key ← Pad(key, blockSize)  //pad key with zeros to make it blockSize bytes long
    
//    o_key_pad = key xor [0x5c * blockSize]   //Outer padded key
//    i_key_pad = key xor [0x36 * blockSize]   //Inner padded key
    
//    return hash(o_key_pad ∥ hash(i_key_pad ∥ message)) //Where ∥ is concatenation

use sha1::SHA1;
use combine::xor_each_no_wrap;


pub fn hmac_sha1(key: &Vec<u8>, message: &[u8]) -> [u8; 20] {
   let sh = SHA1::new();

   let mut mut_key = key.clone();

   // keys longer than block size are shortened artifically
   if mut_key.len() > 64 {
      mut_key = sh.u8_digest(&key).to_vec();
   } else {
      // keys longer than block size are padded with zero
      mut_key.extend(vec![0; 64 - key.len()]);
   }

   let o_key_pad = &xor_each_no_wrap(&mut_key, &[0x5c, 64]);
   let i_key_pad = &xor_each_no_wrap(&mut_key, &[0x36, 64]);

   let inner_digest = [&i_key_pad[..], &message[..]].concat();
   sh.u8_digest(&[&o_key_pad[..], &inner_digest[..]].concat())
}
