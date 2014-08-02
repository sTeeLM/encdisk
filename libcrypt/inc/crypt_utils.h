#ifndef __CRYPT_UTILS_H__
#define __CRYPT_UTILS_H__

INT GenMd5(const void * data, SIZE_T len, UCHAR * out);
INT RngGetBytes(void *out, SIZE_T outlen);

#endif
