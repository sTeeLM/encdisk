#include "crypt.h"

INT GenMd5(const void * data, SIZE_T len, UCHAR * out)
{
	hash_state md5;
	if(md5_init(&md5) != CRYPT_OK) return CRYPT_ERROR;
	if(md5_process(&md5, data, (ULONG)len) != CRYPT_OK)  return CRYPT_ERROR;
	if(md5_done(&md5, out)!= CRYPT_OK) return CRYPT_ERROR;
	return CRYPT_OK;
}


INT RngGetBytes(void *out, SIZE_T outlen)
{
   ULONG x, n, r, i;
   ULONG * p;
   UCHAR * p1;

   p = (ULONG *)out;
   n = (ULONG)(outlen / sizeof(ULONG));
   r = (ULONG)(outlen % sizeof(ULONG));


   for( i = 0 ; i < n ; i ++) {
        x = XRAND();
        *p = x;
        p ++;
   }
   p1 = (UCHAR *)p;

   for( i = 0 ; i < r; i ++) {
        x = XRAND();
        *p1 = (UCHAR)x;
        p1 ++;
   }
   return (INT)outlen;
}
