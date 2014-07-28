/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
/**
  @file nop.c
  Implementation of the Nop block cipher, Tom St Denis
*/
#include "crypt.h"

#ifdef LTC_NOP

const struct ltc_cipher_descriptor nop_desc =
{
    "nop",
    99,
    8, 8, 8, 16,
    &nop_setup,
    &nop_ecb_encrypt,
    &nop_ecb_decrypt,
    &nop_test,
    &nop_done,
    &nop_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

 /**
    Initialize the Nop block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
INT nop_setup(const UCHAR *key, INT keylen, INT num_rounds,
                   symmetric_key *skey)
{
    return CRYPT_OK;
}

/**
  Encrypts a block of text with Nop
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
INT nop_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey)
{
	XMEMCPY(ct, pt, 8);
    return CRYPT_OK;
}

/**
  Decrypts a block of text with Nop
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled 
  @return CRYPT_OK if successful
*/
INT nop_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey)
{
	XMEMCPY(pt, ct, 8);
    return CRYPT_OK;
}

/**
  Performs a self-test of the Nop block cipher
  @return CRYPT_OK if functional, CRYPT_NOP if self-test has been disabled
*/
INT nop_test(void)
{
    return CRYPT_OK;
}

/** Terminate the context 
   @param skey    The scheduled key
*/
void nop_done(symmetric_key *skey)
{

}

/**
  Gets suitable key size
  @param keysize [in/out] The length of the recommended key (in bytes).  This function will store the suitable size back in this variable.
  @return CRYPT_OK if the input key size is acceptable.
*/
INT nop_keysize(INT *keysize)
{
   LTC_ARGCHK(keysize != NULL);

   if (*keysize < 8) {
      return CRYPT_INVALID_KEYSIZE;
   } else if (*keysize > 8) {
      *keysize = 8;
   }
   return CRYPT_OK;
}
#endif
