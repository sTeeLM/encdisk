#ifndef __CRYPT_SINGLE_BYTE_H__
#define __CRYPT_SINGLE_BYTE_H__

typedef struct _CYRPT_SINGLE_BYTE_KEY
{
    UCHAR  key[256];
}CYRPT_SINGLE_BYTE_KEY, *PCYRPT_SINGLE_BYTE_KEY;

INT SingleByteSetup(UCHAR * key, ULONG key_len, PCYRPT_SINGLE_BYTE_KEY skey);
INT SingleByteDone(PCYRPT_SINGLE_BYTE_KEY skey);
UCHAR SingleByteEncrypt(PCYRPT_SINGLE_BYTE_KEY skey, UCHAR p, ULONG index);
UCHAR SingleByteDecrypt(PCYRPT_SINGLE_BYTE_KEY skey, UCHAR c, ULONG index);

#endif