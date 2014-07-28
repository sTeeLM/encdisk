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
  @file crypt_find_hash_any.c
  Find a hash, Tom St Denis
*/

/**
   Find a hash flexibly.  First by name then if not present by digest size 
   @param name        The name of the hash desired
   @param digestlen   The minimum length of the digest size (octets)
   @return >= 0 if found, -1 if not present
*/
INT find_hash_any(const CHAR *name, INT digestlen)
{
   INT x, y, z;
   LTC_ARGCHK(name != NULL);

   x = find_hash(name);
   if (x != -1) return x;

   LTC_MUTEX_LOCK(&ltc_hash_mutex);
   y = MAXBLOCKSIZE+1;
   z = -1;
   for (x = 0; x < TAB_SIZE; x++) {
       if (hash_descriptor[x].name == NULL) {
          continue;
       }
       if ((INT)hash_descriptor[x].hashsize >= digestlen && (INT)hash_descriptor[x].hashsize < y) {
          z = x;
          y = hash_descriptor[x].hashsize;
       }
   }
   LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
   return z;
}

/* $Source: /cvs/libtom/libtomcrypt/src/misc/crypt/crypt_find_hash_any.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2006/12/28 01:27:24 $ */
