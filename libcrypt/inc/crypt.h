#ifndef __CRYPT_H__
#define __CRYPT_H__

#include <windef.h>

/* use configuration data */
#include "crypt_custom.h"

#ifdef __cplusplus
extern "C" {
#endif

/* version */
#define CRYPT   0x0117
#define SCRYPT  "1.17"

/* max size of either a cipher/hash block or symmetric key [largest of the two] */
#define MAXBLOCKSIZE  128

/* descriptor table size */
#define TAB_SIZE      32

/* error codes [will be expanded in future releases] */
enum {
   CRYPT_OK=0,             /* Result OK */
   CRYPT_ERROR,            /* Generic Error */
   CRYPT_NOP,              /* Not a failure but no operation was performed */

   CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
   CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
   CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */

   CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
   CRYPT_INVALID_PACKET,   /* Invalid input packet given */

   CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
   CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */

   CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
   CRYPT_INVALID_HASH,     /* Invalid hash specified */
   CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */

   CRYPT_MEM,              /* Out of memory */

   CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
   CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */

   CRYPT_INVALID_ARG,      /* Generic invalid argument */
   CRYPT_FILE_NOTFOUND,    /* File Not Found */

   CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */
   CRYPT_PK_INVALID_SYSTEM,/* Invalid PK system specified */
   CRYPT_PK_DUP,           /* Duplicate key already in key ring */
   CRYPT_PK_NOT_FOUND,     /* Key not found in keyring */
   CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */

   CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
   CRYPT_PK_INVALID_PADDING /* Invalid padding on input */
};

#include "crypt_xfun.h"
#include "crypt_cfg.h"
#include "crypt_macros.h"
#include "crypt_cipher.h"
#include "crypt_hash.h"
#include "crypt_argchk.h"
#include "crypt_base64.h"
#include "crypt_shuffle.h"
#include "crypt_utils.h"

#define CRYPT_SECTOR_SIZE  512 /* a sector */
#define CRYPT_SECTOR_SHIFT 9
#define CRYPT_SECTOR_P_CLUSTER 256
#define CRYPT_CLUSTER_SHIFT 17
#define CRYPT_CLUSTER_SIZE (CRYPT_SECTOR_SIZE * CRYPT_SECTOR_P_CLUSTER) /* a cluster */

#define CRYPT_SLOT_NUMBER 8
#define CRYPT_KEY_SIZE 32
#define CRYPT_IV_SIZE  32

#define CRYPT_MIN_HARD 0
#define CRYPT_MAX_HARD (CRYPT_SLOT_NUMBER)

#pragma pack(push, r1, 1)
typedef struct _CRYPT_KEY {
    UCHAR signature[16];   // md5 hash
    UCHAR shu3[CRYPT_KEY_SIZE];
    UCHAR shu8[CRYPT_KEY_SIZE];
    CHAR  algo[CRYPT_SLOT_NUMBER];
    UCHAR key[CRYPT_SLOT_NUMBER][CRYPT_KEY_SIZE];
    UCHAR iv[CRYPT_SLOT_NUMBER][CRYPT_IV_SIZE];
}CRYPT_KEY, *PCRYPT_KEY;
#pragma pack(pop, r1)

typedef struct _CRYPT_CONTEXT {
    CRYPT_KEY key;
    CYRPT_SHUFFLE3_CONTEXT shuc3;
    CYRPT_SHUFFLE8_CONTEXT shuc8;
    symmetric_CBC cbc[CRYPT_SLOT_NUMBER];
}CRYPT_CONTEXT, *PCRYPT_CONTEXT;

typedef struct _CRYPT_XFUN
{
	void (__stdcall *xmemcpy)(void *dest, const void *src, SIZE_T n);
	INT   (__stdcall *xmemcmp)(const void *s1, const void *s2, SIZE_T n);
	void (__stdcall *xmemset)(void *s, INT c, SIZE_T n);
	INT   (__stdcall *xstrcmp)(const CHAR *s1, const CHAR *s2);
	void (__stdcall *xzeromem)(void *s, SIZE_T n);
	SIZE_T (__stdcall *xstrlen)(const CHAR * s);
	ULONG (__stdcall *xrand)();
}CRYPT_XFUN, *PCRYPT_XFUN;

INT CryptInitialize(PCRYPT_XFUN xfun);
INT CryptCleanup(void);

INT CryptGenContext(INT hard, PCRYPT_CONTEXT context);
INT CryptRestoreContext(PCRYPT_CONTEXT context);
INT CryptCleanupContext(PCRYPT_CONTEXT context);

INT CryptDecryptSector(PCRYPT_CONTEXT context, const void * cipher, void * plain, ULONG sector_index, ULONGLONG cluster_index);
INT CryptEncryptSector(PCRYPT_CONTEXT context, const void * plain, void * cipher, ULONG sector_index, ULONGLONG cluster_index);

INT CryptEncryptCluster(PCRYPT_CONTEXT context, const void * plain, void * cipher, ULONGLONG cluster_index);
INT CryptDecryptCluster(PCRYPT_CONTEXT context, const void * cipher, void * plain, ULONGLONG cluster_index);

INT CryptEncodeKey(const PCRYPT_KEY in, PCRYPT_KEY work, void * out, const CHAR * password, ULONG *out_size);
INT CryptDecodeKey(const void * in, PCRYPT_KEY out, const CHAR * password, ULONG in_size);

CONST CHAR * CryptAlgoName(INT algo);

#ifdef __cplusplus
   }
#endif

#endif /* TOMCRYPT_H_ */


/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt.h,v $ */
/* $Revision: 1.21 $ */
/* $Date: 2006/12/16 19:34:05 $ */
