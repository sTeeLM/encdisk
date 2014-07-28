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
#include "crypt.h"

/**
  @file f8_decrypt.c
  F8 implementation, decrypt data, Tom St Denis
*/

#ifdef LTC_F8_MODE

/**
   F8 decrypt
   @param ct      Ciphertext
   @param pt      [out] PlaINText
   @param len     Length of ciphertext (octets)
   @param f8      F8 state
   @return CRYPT_OK if successful
*/
INT f8_decrypt(const UCHAR*ct, UCHAR*pt, ULONG len, symmetric_F8 *f8)
{
   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(f8 != NULL);
   return f8_encrypt(ct, pt, len, f8);
}


#endif

 

/* $Source: /cvs/libtom/libtomcrypt/src/modes/f8/f8_decrypt.c,v $ */
/* $Revision: 1.3 $ */
/* $Date: 2006/12/28 01:27:24 $ */
