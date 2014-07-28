#ifndef __CRYPT_BASE64_H__
#define __CRYPT_BASE64_H__
INT base64_encode(const UCHAR *in,  ULONG inlen, 
                        UCHAR *out, ULONG *outlen);
INT base64_decode(const UCHAR *in,  ULONG inlen, 
                        UCHAR *out, ULONG *outlen);
#endif