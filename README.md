This is key mismatch attack demo for Kyber768 in NIST Round 3.
First of all the program is going to be generating the pair of public and private keys
after ciphering the message, the attack will try to figure the private key out using 
the public key in addition to the ciphered text after specifying a kernal seed.

# Structure

PQCgenKAT_kem.c: the entrance of attack, 

kem.c:  building the oracle 

indcpa.c: choosing attack parameters

test.p6: test queries  

time.p6: test  time

# Build and Run

To build it, you need to have openssl  and make on linux or Mac os.

> make

After making, then you can run 

>  ./PQCgenKAT_kem \<num\>



To build the key recovery attack

> make recovery

After making, then you can run 

> ./recovery



`<num>` is a integer used as a random seed. For example, `./PQCgenKAT_kem 1`

To run test, you need to install [rakudo](https://rakudo.org/) and run

> raku test.p6
>
> raku time.p6
>
> 
