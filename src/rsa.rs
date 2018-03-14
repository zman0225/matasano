// Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a prime table. 
// Call them "p" and "q".
// Let n be p * q. Your RSA math is modulo n.
// Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
// Let e be 3.
// Compute d = invmod(e, et). invmod(17, 3120) is 2753.
// Your public key is [e, n]. Your private key is [d, n].
// To encrypt: c = m**e%n. To decrypt: m = c**d%n
// Test this out with a number, like "42".
// Repeat with bignum primes (keep e=3).

use num::traits::{Zero, One};
use openssl::bn::{BigNum, MsbOption};
use num::bigint::{ToBigUint, ToBigInt, BigUint, BigInt};


// extended Euclidean GCD algorithm
// returns k, u, and v such that ua + vb = k, where k is the gcd of a and b
pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
    // u_a, v_a, u_b, v_b = 1, 0, 0, 1
    let (mut u_a, mut v_a, mut u_b, mut v_b) = (one.clone(), zero.clone(), zero.clone(), one.clone());
    let (mut aa, mut bb) = (a.to_bigint().unwrap(), b.to_bigint().unwrap());

    while aa != zero {
    	let q = &bb / &aa;

    	let new_a = bb - &q * &aa;
    	bb = aa;
    	aa = new_a;

    	let new_u_a = u_b - &q * &u_a;
    	u_b = u_a;
    	u_a = new_u_a;

    	let new_v_a = v_b - &q * &v_a;
    	v_b = v_a;
    	v_a = new_v_a;
    }

    (bb, u_b, v_b)
}

pub fn invmod(a: &BigUint, n: &BigUint) -> Option<BigUint> {

    let (mut t, mut new_t):(BigInt,BigInt) =  (Zero::zero(), One::one());
      
    let (mut r, mut new_r) =  (n.to_bigint().unwrap(), a.to_bigint().unwrap());    
         
    while new_r != Zero::zero() {
		
		let quotient = &r / &new_r;
		
		let mut tmp  = &t - &quotient * &new_t;
		t = new_t;
		new_t = tmp;
		
		tmp  = &r - &quotient * &new_r;
		r = new_r;
		new_r = tmp;
	}	
	if r > One::one()   { return None };
	if t < Zero::zero() { t = &t + &n.to_bigint().unwrap() };
	
	Some(t.to_biguint().unwrap())
}

 
pub fn prime_gen() -> BigUint {
   let mut big = BigNum::new().unwrap();

   // Generates a 128-bit odd random number
   big.rand(128, MsbOption::MAYBE_ZERO, true).unwrap();
   BigUint::from_bytes_le(&big.to_vec())
}

pub fn rsa_keygen() -> (Vec<u8>, Vec<u8>){
    let (p, q) = (prime_gen(), prime_gen());
    let n = &p * &q;

    let one: &BigUint = &One::one();
    let et = (p - one) * (q - one);
    let e = 3.to_biguint().unwrap();
    let d = invmod(&e, &et).unwrap();

    // public key is [e, n]
    // private key is [d, n]
    let (e_vec, n_vec, d_vec) = (e.to_bytes_le(), n.to_bytes_le(), d.to_bytes_le());
    ([&e_vec[..], &n_vec[..]].concat().to_vec(), [&d_vec[..], &n_vec[..]].concat().to_vec())
}
