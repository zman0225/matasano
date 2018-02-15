### Challenge 17
#### References: [Cryptopal](https://github.com/akalin/cryptopals-python3/blob/master/challenge19.py)
-----

I was pretty stuck on this problem. Following the python solutions, here is my understanding. 


Once we generate a random key and a nonce, we use it for the rest of the challenge. To refresh CTR keystreams are formed from two u64 concatenated together. The first u64 is the nonce, while the second is the blocksize. We use the same nonce for the entirity of the encryption/decryption process. We AES encrypt the key and nonce digest to get the keystream. Lastly the keystream is used to xor with the plain text as such:  

```plain_text ⊕ keystream = cipher_text```

with rearranging we can also get:

```cipher_text ⊕ keystream = plain_text```


In this challenge, all 39 messages are encrypted with the same keystream. 
First we need to generate a list of candidate characters values that fit xor out to valid human readable plain texts. In the python implementation, we iterate through the ciphertexts and we pull out the ith character to xor with an valid u8. If there exists a u8 that xors out with all 39 ciphers then that u8 can be a possible candidate for the keystream at position i. As a way to generate all the possible keystreams, we perform a cartesian product on the list of results. We can view the decrypted results after that. We see that up to 10 characters, we have a pretty good result of what's going on, once we get to the 11th character, we are not able to get a candidate. 


Now we go into the extend_key function, which is used to manually extend the key. For example, when we see that up to the 10th character we can decode the second encryption to be "Coming wit", we safely assume that the possible word is `with` and after with there has to be a space, so we can extend it the guess to be `h `. What `extend_keys` does is that it xors every character of our guess with the matching position in the ciphertext getting additional keystream bytes. We can now decrypt again with the larger key and extrapolate more words logically. We can do this gradually as the key gets larger.


Now to automate all of this, I think it would be prudent to use some sort of a ngram probability lookup to complete the word. Of course, we'd ignore the current decrypted plain text if it ended with a space.
