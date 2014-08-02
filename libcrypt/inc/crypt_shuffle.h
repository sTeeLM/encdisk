#ifndef __CRYPT_SHUFFLE_BYTE_H__
#define __CRYPT_SHUFFLE_BYTE_H__

#define SHUFFLE3_ROUND 16
#define SHUFFLE3_SHIFT 4  // (sizeof(index) / SHUFFLE3_ROUND)
#define SHUFFLE3_MASK 0x7
typedef struct _CYRPT_SHUFFLE3_CONTEXT
{
    UCHAR  iv[SHUFFLE3_ROUND]; // use last 3 bits, total 12 bits
    UCHAR  x[SHUFFLE3_ROUND];  // use last 3 bits, total 12 bits
}CYRPT_SHUFFLE3_CONTEXT, *PCYRPT_SHUFFLE3_CONTEXT;

#define SHUFFLE8_ROUND 16
#define SHUFFLE8_SHIFT 4 // (sizeof(index) / SHUFFLE8_ROUND)
#define SHUFFLE8_MASK 0x3
typedef struct _CYRPT_SHUFFLE8_CONTEXT
{
    UCHAR  iv[SHUFFLE8_ROUND]; //use all 8 bits, total 32 bits
    UCHAR  x[SHUFFLE8_ROUND];  //use all 8 bits, total 32 bits
}CYRPT_SHUFFLE8_CONTEXT, *PCYRPT_SHUFFLE8_CONTEXT;

INT shuffle3setup(UCHAR * key, ULONG key_len, PCYRPT_SHUFFLE3_CONTEXT s);
INT shuffle3done(PCYRPT_SHUFFLE3_CONTEXT s);
UCHAR shuffle3encrypt(PCYRPT_SHUFFLE3_CONTEXT s, UCHAR p, ULONGLONG index);
UCHAR shuffle3decrypt(PCYRPT_SHUFFLE3_CONTEXT s, UCHAR c, ULONGLONG index);

INT shuffle8setup(UCHAR * key, ULONG key_len, PCYRPT_SHUFFLE8_CONTEXT c);
INT shuffle8done(PCYRPT_SHUFFLE8_CONTEXT c);
UCHAR shuffle8encrypt(PCYRPT_SHUFFLE8_CONTEXT s, UCHAR p, ULONGLONG index);
UCHAR shuffle8decrypt(PCYRPT_SHUFFLE8_CONTEXT s, UCHAR c, ULONGLONG index);

#endif