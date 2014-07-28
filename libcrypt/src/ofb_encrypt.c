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
  @file ofb_encrypt.c
  OFB implementation, encrypt data, Tom St Denis
*/

#ifdef LTC_OFB_MODE

/**
  OFB encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    Length of plaintext (octets)
  @param ofb    OFB state
  @return CRYPT_OK if successful
*/
INT ofb_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_OFB *ofb)
{
   INT err;
   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(ofb != NULL);
   if ((err = cipher_is_valid(ofb->cipher)) != CRYPT_OK) {
       return err;
   }
   
   /* is blocklen/padlen valid? */
   if (ofb->blocklen < 0 || ofb->blocklen > (INT)sizeof(ofb->IV) ||
       ofb->padlen   < 0 || ofb->padlen   > (INT)sizeof(ofb->IV)) {
      return CRYPT_INVALID_ARG;
   }
   
   while (len-- > 0) {
       if (ofb->padlen == ofb->blocklen) {
          if ((err = cipher_descriptor[ofb->cipher].ecb_encrypt(ofb->IV, ofb->IV, &ofb->key)) != CRYPT_OK) {
             return err;
          }
          ofb->padlen = 0;
       }
       *ct++ = *pt++ ^ ofb->IV[(ofb->padlen)++];
   }
   return CRYPT_OK;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/modes/ofb/ofb_encrypt.c,v $ */
/* $Revision: 1.8 $ */
/* $Date: 2006/12/28 01:27:24 $ */
