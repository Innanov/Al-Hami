#include <stddef.h>
#include <stdint.h>
#include "kem.h"
#include "params.h"
#include "rng.h"
#include "symmetric.h"
#include "verify.h"
#include "indcpa.h"
#include <string.h>

/* modify */
#include "poly.h"
// static const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// int base64_encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_len) {
//     size_t i, j;
//     unsigned char buf[3];
//     int k;
//     char tmp[4];

//     for (i = 0, j = 0; i < src_len; i += 3) {
//         buf[0] = src[i];
//         buf[1] = (i+1 < src_len) ? src[i+1] : 0;
//         buf[2] = (i+2 < src_len) ? src[i+2] : 0;

//         tmp[0] = base64_chars[buf[0] >> 2];
//         tmp[1] = base64_chars[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
//         tmp[2] = base64_chars[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)];
//         tmp[3] = base64_chars[buf[2] & 0x3F];

//         if (j + 4 <= dst_len) {
//             dst[j++] = tmp[0];
//             dst[j++] = tmp[1];
//             dst[j++] = tmp[2];
//             dst[j++] = tmp[3];
//         } else {
//             return 0;
//         }
//     }

//     k = src_len % 3;
//     if (k > 0) {
//         dst[j-1] = '=';
//         if (k == 1) {
//             dst[j-2] = '=';
//         }
//     }

//     return j;
// }

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk, polyvec * skpoly)
{
  size_t i;
  indcpa_keypair(pk, sk, skpoly);
  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct: pointer to output cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}



/* modify for key mismatch attack*/
/*
*   input: m, pk, h, k, select
*   output: ct 
*/
int kemenc_Attack(unsigned char * ct, 
                  unsigned char * m, 
                  const unsigned char * pk, 
                  int h, int k, int select) 
{
  /* call enc to choose ct */
  enc(ct, m, h, k, select);
  
}

/* build the Oracle */
/*
*   input : ct, sk, msg_A
*   output: 0 or 1
*/
int oracle(const unsigned char * ct, 
           const unsigned char * sk, 
           unsigned char * msg_A) 
{

  unsigned char m_dec[KYBER_SYMBYTES] = { 0 };
  

  indcpa_dec(m_dec, ct, sk);    //decrypt the ct
  /* check msg_A given by adversary ==  the m_dec decrypted by oracle */
          //     char outstr1[1024] = {0};
	        // base64_encode(m_dec,strlen(m_dec),outstr1,1024);
          //   printf("m:%s\n",outstr1);
  for(int a = 0; a < KYBER_SYMBYTES; a++) {
    if(msg_A[a] != m_dec[a]){
      //printf("a:%d miss:%d %d\n", a, msg_A[a], m_dec[a]);
      return 0;
    }
  }
  
  return 1;
}