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
  @file cfb_decrypt.c
  CFB implementation, decrypt data, Tom St Denis
*/

#ifdef LTC_CFB_MODE

/**
   CFB decrypt
   @param ct      Ciphertext
   @param pt      [out] Plaintext
   @param len     Length of ciphertext (octets)
   @param cfb     CFB state
   @return CRYPT_OK if successful
*/
INT cfb_decrypt(const UCHAR *ct, UCHAR *pt, ULONG len, symmetric_CFB *cfb)
{
   INT err;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(cfb != NULL);

   if ((err = cipher_is_valid(cfb->cipher)) != CRYPT_OK) {
       return err;
   }

   /* is blocklen/padlen valid? */
   if (cfb->blocklen < 0 || cfb->blocklen > (INT)sizeof(cfb->IV) ||
       cfb->padlen   < 0 || cfb->padlen   > (INT)sizeof(cfb->pad)) {
      return CRYPT_INVALID_ARG;
   }

   while (len-- > 0) {
       if (cfb->padlen == cfb->blocklen) {
          if ((err = cipher_descriptor[cfb->cipher].ecb_encrypt(cfb->pad, cfb->IV, &cfb->key)) != CRYPT_OK) {
             return err;
          }
          cfb->padlen = 0;
       }
       cfb->pad[cfb->padlen] = *ct;
       *pt = *ct ^ cfb->IV[cfb->padlen];
       ++pt; 
       ++ct;
       ++(cfb->padlen);
   }
   return CRYPT_OK;
}

#endif


/* $Source: /cvs/libtom/libtomcrypt/src/modes/cfb/cfb_decrypt.c,v $ */
/* $Revision: 1.8 $ */
/* $Date: 2006/12/28 01:27:24 $ */
