#[cfg(test)]
mod test_set5 {
    use conversions::{pad_pkcs7, unpad_pkcs7};
    // use crypter::{aes_cbc, random_aes_key, random_bytes, aes_ctr};
    // use openssl::symm::Mode;
    // use combine::{xor_each_no_wrap};
    // use text::{profile_for, sanitize_for_url};
    // use sha1::{SHA1, generate_sha1_padding};
    // use md4::{MD4, generate_md4_padding};
    // use std::thread;
    // use std::time::{Duration, Instant};
    // use std::sync::mpsc::{Sender, Receiver};
    // use std::sync::mpsc;
    // use hmac::hmac_sha1;
    // use std::collections::BinaryHeap;
    use dh::KeyPair;
    use openssl::symm::Mode;
    use crypter::{aes_cbc, random_bytes};
    use num_bigint::BigUint;


    const NIST_P: &'static [u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff";
    const NIST_G: &'static [u8] = b"2";


    #[test]
    fn challenge_33() {
        let k1 = KeyPair::new(&NIST_P.to_vec(), &NIST_G.to_vec());
        let k2 = KeyPair::new(&NIST_P.to_vec(), &NIST_G.to_vec());

        let pub1 = &k1.public_key;
        let pub2 = &k2.public_key;
        assert_eq!(k1.generate_session_key(pub2), k2.generate_session_key(pub1));
    }

    // challenge 34
    fn cbc_encrypt(kp: &KeyPair, other_pb: &BigUint) -> (Vec<u8>, Vec<u8>) {
        let session_key = kp.generate_session_key(other_pb);
        let key = &session_key[..16];

        let iv = random_bytes(16, 16);
        let msg = random_bytes(16, 32);
        let mut padded_msg = msg.clone(); 

        let mut msg_encrypted = vec!();
        pad_pkcs7(&mut padded_msg, key.len());
        aes_cbc(key, &padded_msg, Some(&iv), &mut msg_encrypted, Mode::Encrypt);
        msg_encrypted.extend(iv);
        (msg_encrypted, msg)
    }

    fn cbc_decrypt(kp: &KeyPair, other_pb: &BigUint, encrypted: &[u8]) -> Vec<u8> {
        let session_key = kp.generate_session_key(other_pb);
        let (encrypted, iv) = (&encrypted[..encrypted.len()-16], &encrypted[encrypted.len()-16..]);

        let mut msg_decrypted = vec!();
        aes_cbc(&session_key[..16], &encrypted, Some(&iv), &mut msg_decrypted, Mode::Decrypt);
        unpad_pkcs7(&mut msg_decrypted);
        msg_decrypted
    }

    #[test]
    fn challenge_34() {
        // here we need two nodes communicating with each other, lets simulate this
        let a_keypair = KeyPair::new(&NIST_P.to_vec(), &NIST_G.to_vec());
        let b_keypair = KeyPair::new(&NIST_P.to_vec(), &NIST_G.to_vec());

        // 1 A->B send p, g, A
        let a_pubkey = &a_keypair.public_key;

        // 2 B->A send B
        let b_pubkey = &b_keypair.public_key;

        // 3 A->B send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        let (a_msg_encrypted, a_msg) = cbc_encrypt(&a_keypair, &b_pubkey);

        // B decrypts A's message
        assert_eq!(cbc_decrypt(&b_keypair, &a_pubkey, &a_msg_encrypted), a_msg);

        // 4 B->A Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
        let (b_msg_encrypted, b_msg) = cbc_encrypt(&b_keypair, &a_pubkey);

        // A decrypts B's message
        assert_eq!(cbc_decrypt(&a_keypair, &b_pubkey, &b_msg_encrypted), b_msg);

        // The man in the middle attack basically dictates that a deceiving middle man intercepts A and B's messages
        // He then replaces the public key with his own such that both A and B signs with his public key and encrypts their 
        // messages with the false public key

        // here we need two nodes communicating with each other, lets simulate this
        let a_keypair = KeyPair::new(&NIST_P.to_vec(), &NIST_G.to_vec());
        let b_keypair = KeyPair::new(&NIST_P.to_vec(), &NIST_G.to_vec());
        let m_keypair = KeyPair::new(&NIST_P.to_vec(), &NIST_G.to_vec());

        // 1. A->M send "p", "g", "A"
        let a_pubkey = &a_keypair.public_key;

        // 2. M->B send "p", "g", "p"
        let false_pubkey = BigUint::from_bytes_le(&NIST_P.to_vec());

        // 3. B->M send "B"
        let b_pubkey = &b_keypair.public_key;

        // 4. M->A send "p"
        // same as 2

        // 5. A->M send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        // 6. M->B relay that to B
        let (a_msg_encrypted, a_msg) = cbc_encrypt(&a_keypair, &false_pubkey);

        // M can decrypt it
        assert_eq!(cbc_decrypt(&m_keypair, &false_pubkey, &a_msg_encrypted), a_msg);

        // 7. B->M send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
        // 8. M->A relay that to A
        let (b_msg_encrypted, b_msg) = cbc_encrypt(&b_keypair, &false_pubkey);

        // M can decrypt it
        assert_eq!(cbc_decrypt(&m_keypair, &false_pubkey, &b_msg_encrypted), b_msg);

        // we can do all of this because when generating the session key with the p value, we get a 0 session key
    }
    
}
