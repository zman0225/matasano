use mersenne::MTRng;
use sha1::SHA1;
use num::bigint::BigUint;


pub struct KeyPair {
    private_key: BigUint,
    pub public_key: BigUint,
    _p: BigUint,
    _g: BigUint
}

impl KeyPair {
    pub fn new(p: &[u8], g: &[u8]) -> KeyPair {
        let (p, g) = (BigUint::from_bytes_le(p), BigUint::from_bytes_le(g));
        let mut rng = MTRng::new();
        let private_key = rng.u32() % &p;
        let public_key = g.modpow(&private_key, &p);
        Self{private_key, public_key, _p: p, _g: g}
    }

    pub fn generate_session_key(&self, other_public_key: &BigUint) -> Vec<u8> {
        let session_key = other_public_key.modpow(&self.private_key, &self._p);
        let sha1 = SHA1::new();
        sha1.u8_digest(&session_key.to_bytes_le()[..]).to_vec()
    }
}
