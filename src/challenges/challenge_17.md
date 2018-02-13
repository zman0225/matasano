### Challenge 17
#### References: [Wikipedia](https://en.wikipedia.org/wiki/Padding_oracle_attack), [Skull Security](https://blog.skullsecurity.org/2013/a-padding-oracle-example)
-----

##### Recall that CBC mode operates as such (example using blocksize of 8): 

```C2 = E(P2 ⊕ C1)```<sup>1</sup> 

where `C1` and `C2` are consecutive cipher blocks blocks and `P2` is the plain text for block 2.
Now if the attacker were to abuse the CBC padding oracle, with control over (C1, C2) and nothing else. Their decryption attempt can be described as such: ```P'2 = D(C2) ⊕ C'``` Where `P'2` (not necessarily the same as `P2` but valid nonetheless) is the resulting plain text and `C'` is the cipher block we want to manipulate. `E` and `D` are the functions to encrypt and decrypt, respectively.


Substituting the encryption function (`C2`<sup>1</sup>) into the decryption one, we get: ```P'2 = D(E(P2 ⊕ C1)) ⊕ C'```. Now the nested `D(E(...))` becomes redundant as it is only encrypting then decrypting. ```P'2 = D(E(P2 ⊕ C1)) ⊕ C'``` is mathematically the same as:

 ```P'2 = P2 ⊕ C1 ⊕ C'```<sup>2</sup>, where we are trying to find `P2`, can't see `P'2` and have the ability to change `C`.


So to start, we, as attackers, need to manipulate the cipher blocks returned to us by testing the validity of padding. Once we build a cbc padding oracle, we can start attacking it by having it telling us whether our cipherblocks are padded correctly or not. For example, let `C2` be untouched and let `C1` just be a string of zeros (0x0...000). Remember the properties of CBC encryption, if we change even one bit in `P1` to `P'`, the corresponding cipherblock, `C1` would be completely different from `C'1` due to the avalanche effect, but `C'2` would only differ from `C2` by a single bit edit. 


Inversely, since we cannot manipulate the plain text anymore, we can still manipulate the ciphertext. To start we can start by manipulating `C'`'s last byte, `C'[7]`. When decrypted (`C' + C2`), `P'2` will be tested (in the CBC oracle function) on whether the padding is valid or not. Note that ultimately, even though we don't know what `P'2` is, we can assume that it CAN be different from `P2` as long as it has valid padding. So as long as we are only manipulating the last byte in `C'`, we know that there should exist `P'2` for all possible values of `C'` that ends with `0x01`, which is a valid padding. 


Why look for `0x01` as our padding? Well, because we modify the entirety of `C'` we have to xor it before getting the final plaintext. The likihood of achieving a plain text that ends in `0x01` is 1/256 (values in a byte), where as the chance of generating something that end with `\02\02` even less likely. Now, our objective is to find `P2`, byte by byte. Using the commutative property, we get:

```P2 = P'2 ⊕ C1 ⊕ C'```, where `C'` is the ciphertext that produces a valid padding for solution to `D(C'+C2)`

in bytewise form: 
```P2[7] = P'2[7] ⊕ C1[7] ⊕ C'[7]```.

While we don't know `P'2`, we can assume that `P'2[7]` is `0x01` We have both `C1` and `C'`. We now have the last byte.


Onto the second-to-last byte. We need to find the `P'2` where it ends with `\02\02`. Recall that the general bytewise formula for finding `P'` is: 

```P′2[k] = P2[k] ⊕ C1[k] ⊕ C′[k]``` 

So we need to brute force `P'2[7]` to be `\02`, we just need to find the value of `C'[7]`. Re-arranging the formula, we get like: 

```C'[7] = P2[7] ⊕ P′2[7] ⊕ C1[7]```; `P'2[7]` is `\02`, `P2[7]` is solved, and `C1[7]` is known

Once we do that, we will have found the last byte. If it's invalid, we just need to iterate through all 256 possibility to find the second from last byte. This whole concept can be a bit confusing at first, what really helped me understand it all is the base knowledge that all of this is a machine. As long as the inputs and outputs are **VALID**, we are free to abuse it to leak new information.
