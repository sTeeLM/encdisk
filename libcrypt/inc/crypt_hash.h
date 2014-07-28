#ifndef __CRYPT_HASH_H__
#define __CRYPT_HASH_H__

/* ---- HASH FUNCTIONS ---- */
#ifdef LTC_SHA512
struct sha512_state {
    ULONG64  length, state[8];
    ULONG curlen;
    UCHAR buf[128];
};
#endif

#ifdef LTC_SHA256
struct sha256_state {
    ULONG64 length;
    ULONG state[8], curlen;
    UCHAR buf[64];
};
#endif

#ifdef LTC_SHA1
struct sha1_state {
    ULONG64 length;
    ULONG state[5], curlen;
    UCHAR buf[64];
};
#endif

#ifdef LTC_MD5
struct md5_state {
    ULONG64 length;
    ULONG state[4], curlen;
    UCHAR buf[64];
};
#endif

#ifdef LTC_MD4
struct md4_state {
    ULONG64 length;
    ULONG state[4], curlen;
    UCHAR buf[64];
};
#endif

#ifdef LTC_TIGER
struct tiger_state {
    ULONG64 state[3], length;
    ULONG curlen;
    UCHAR buf[64];
};
#endif

#ifdef LTC_MD2
struct md2_state {
    UCHAR chksum[16], X[48], buf[16];
    ULONG curlen;
};
#endif

#ifdef LTC_RIPEMD128
struct rmd128_state {
    ULONG64 length;
    UCHAR buf[64];
    ULONG curlen, state[4];
};
#endif

#ifdef LTC_RIPEMD160
struct rmd160_state {
    ULONG64 length;
    UCHAR buf[64];
    ULONG curlen, state[5];
};
#endif

#ifdef LTC_RIPEMD256
struct rmd256_state {
    ULONG64 length;
    UCHAR buf[64];
    ULONG curlen, state[8];
};
#endif

#ifdef LTC_RIPEMD320
struct rmd320_state {
    ULONG64 length;
    UCHAR buf[64];
    ULONG curlen, state[10];
};
#endif

#ifdef LTC_WHIRLPOOL
struct whirlpool_state {
    ULONG64 length, state[8];
    UCHAR buf[64];
    ULONG curlen;
};
#endif

#ifdef LTC_CHC_HASH
struct chc_state {
    ULONG64 length;
    UCHAR state[MAXBLOCKSIZE], buf[MAXBLOCKSIZE];
    ULONG curlen;
};
#endif

typedef union Hash_state {
    CHAR dummy[1];
#ifdef LTC_CHC_HASH
    struct chc_state chc;
#endif
#ifdef LTC_WHIRLPOOL
    struct whirlpool_state whirlpool;
#endif
#ifdef LTC_SHA512
    struct sha512_state sha512;
#endif
#ifdef LTC_SHA256
    struct sha256_state sha256;
#endif
#ifdef LTC_SHA1
    struct sha1_state   sha1;
#endif
#ifdef LTC_MD5
    struct md5_state    md5;
#endif
#ifdef LTC_MD4
    struct md4_state    md4;
#endif
#ifdef LTC_MD2
    struct md2_state    md2;
#endif
#ifdef LTC_TIGER
    struct tiger_state  tiger;
#endif
#ifdef LTC_RIPEMD128
    struct rmd128_state rmd128;
#endif
#ifdef LTC_RIPEMD160
    struct rmd160_state rmd160;
#endif
#ifdef LTC_RIPEMD256
    struct rmd256_state rmd256;
#endif
#ifdef LTC_RIPEMD320
    struct rmd320_state rmd320;
#endif
    void *data;
} hash_state;

/** hash descriptor */
extern  struct ltc_hash_descriptor {
    /** name of hash */
    CHAR *name;
    /** internal ID */
    UCHAR ID;
    /** Size of digest in octets */
    ULONG hashsize;
    /** Input block size in octets */
    ULONG blocksize;
    /** ASN.1 OID */
    ULONG OID[16];
    /** Length of DER encoding */
    ULONG OIDlen;

    /** Init a hash state
      @param hash   The hash to initialize
      @return CRYPT_OK if successful
    */
    INT (*init)(hash_state *hash);
    /** Process a block of data 
      @param hash   The hash state
      @param in     The data to hash
      @param inlen  The length of the data (octets)
      @return CRYPT_OK if successful
    */
    INT (*process)(hash_state *hash, const UCHAR *in, ULONG inlen);
    /** Produce the digest and store it
      @param hash   The hash state
      @param out    [out] The destination of the digest
      @return CRYPT_OK if successful
    */
    INT (*done)(hash_state *hash, UCHAR *out);
    /** Self-test
      @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
    */
    INT (*test)(void);

    /* accelerated hmac callback: if you need to-do multiple packets just use the generic hmac_memory and provide a hash callback */
    INT  (*hmac_block)(const UCHAR *key, ULONG  keylen,
                       const UCHAR *in,  ULONG  inlen, 
                             UCHAR *out, ULONG *outlen);

} hash_descriptor[];

#ifdef LTC_CHC_HASH
INT chc_register(INT cipher);
INT chc_init(hash_state * md);
INT chc_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT chc_done(hash_state * md, UCHAR *hash);
INT chc_test(void);
extern const struct ltc_hash_descriptor chc_desc;
#endif

#ifdef LTC_WHIRLPOOL
INT whirlpool_init(hash_state * md);
INT whirlpool_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT whirlpool_done(hash_state * md, UCHAR *hash);
INT whirlpool_test(void);
extern const struct ltc_hash_descriptor whirlpool_desc;
#endif

#ifdef LTC_SHA512
INT sha512_init(hash_state * md);
INT sha512_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT sha512_done(hash_state * md, UCHAR *hash);
INT sha512_test(void);
extern const struct ltc_hash_descriptor sha512_desc;
#endif

#ifdef LTC_SHA384
#ifndef LTC_SHA512
   #error LTC_SHA512 is required for LTC_SHA384
#endif
INT sha384_init(hash_state * md);
#define sha384_process sha512_process
INT sha384_done(hash_state * md, UCHAR *hash);
INT sha384_test(void);
extern const struct ltc_hash_descriptor sha384_desc;
#endif

#ifdef LTC_SHA256
INT sha256_init(hash_state * md);
INT sha256_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT sha256_done(hash_state * md, UCHAR *hash);
INT sha256_test(void);
extern const struct ltc_hash_descriptor sha256_desc;

#ifdef LTC_SHA224
#ifndef LTC_SHA256
   #error LTC_SHA256 is required for LTC_SHA224
#endif
INT sha224_init(hash_state * md);
#define sha224_process sha256_process
INT sha224_done(hash_state * md, UCHAR *hash);
INT sha224_test(void);
extern const struct ltc_hash_descriptor sha224_desc;
#endif
#endif

#ifdef LTC_SHA1
INT sha1_init(hash_state * md);
INT sha1_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT sha1_done(hash_state * md, UCHAR *hash);
INT sha1_test(void);
extern const struct ltc_hash_descriptor sha1_desc;
#endif

#ifdef LTC_MD5
INT md5_init(hash_state * md);
INT md5_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT md5_done(hash_state * md, UCHAR *hash);
INT md5_test(void);
extern const struct ltc_hash_descriptor md5_desc;
#endif

#ifdef LTC_MD4
INT md4_init(hash_state * md);
INT md4_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT md4_done(hash_state * md, UCHAR *hash);
INT md4_test(void);
extern const struct ltc_hash_descriptor md4_desc;
#endif

#ifdef LTC_MD2
INT md2_init(hash_state * md);
INT md2_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT md2_done(hash_state * md, UCHAR *hash);
INT md2_test(void);
extern const struct ltc_hash_descriptor md2_desc;
#endif

#ifdef LTC_TIGER
INT tiger_init(hash_state * md);
INT tiger_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT tiger_done(hash_state * md, UCHAR *hash);
INT tiger_test(void);
extern const struct ltc_hash_descriptor tiger_desc;
#endif

#ifdef LTC_RIPEMD128
INT rmd128_init(hash_state * md);
INT rmd128_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT rmd128_done(hash_state * md, UCHAR *hash);
INT rmd128_test(void);
extern const struct ltc_hash_descriptor rmd128_desc;
#endif

#ifdef LTC_RIPEMD160
INT rmd160_init(hash_state * md);
INT rmd160_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT rmd160_done(hash_state * md, UCHAR *hash);
INT rmd160_test(void);
extern const struct ltc_hash_descriptor rmd160_desc;
#endif

#ifdef LTC_RIPEMD256
INT rmd256_init(hash_state * md);
INT rmd256_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT rmd256_done(hash_state * md, UCHAR *hash);
INT rmd256_test(void);
extern const struct ltc_hash_descriptor rmd256_desc;
#endif

#ifdef LTC_RIPEMD320
INT rmd320_init(hash_state * md);
INT rmd320_process(hash_state * md, const UCHAR *in, ULONG inlen);
INT rmd320_done(hash_state * md, UCHAR *hash);
INT rmd320_test(void);
extern const struct ltc_hash_descriptor rmd320_desc;
#endif

INT find_hash(const CHAR *name);
INT find_hash_id(UCHAR ID);
INT find_hash_oid(const ULONG *ID, ULONG IDlen);
INT find_hash_any(const CHAR *name, INT digestlen);
INT register_hash(const struct ltc_hash_descriptor *hash);
INT unregister_hash(const struct ltc_hash_descriptor *hash);
INT hash_is_valid(INT idx);

/* a simple macro for making hash "process" functions */
#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
INT func_name (hash_state * md, const UCHAR *in, ULONG inlen)               \
{                                                                                           \
    ULONG n;                                                                        \
    INT           err;                                                                      \
    LTC_ARGCHK(md != NULL);                                                                 \
    LTC_ARGCHK(in != NULL);                                                                 \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf)) {                             \
       return CRYPT_INVALID_ARG;                                                            \
    }                                                                                       \
    while (inlen > 0) {                                                                     \
        if (md-> state_var .curlen == 0 && inlen >= block_size) {                           \
           if ((err = compress_name (md, (UCHAR *)in)) != CRYPT_OK) {               \
              return err;                                                                   \
           }                                                                                \
           md-> state_var .length += block_size * 8;                                        \
           in             += block_size;                                                    \
           inlen          -= block_size;                                                    \
        } else {                                                                            \
           n = MIN(inlen, (block_size - md-> state_var .curlen));                           \
           XMEMCPY(md-> state_var .buf + md-> state_var.curlen, in, (size_t)n);              \
           md-> state_var .curlen += n;                                                     \
           in             += n;                                                             \
           inlen          -= n;                                                             \
           if (md-> state_var .curlen == block_size) {                                      \
              if ((err = compress_name (md, md-> state_var .buf)) != CRYPT_OK) {            \
                 return err;                                                                \
              }                                                                             \
              md-> state_var .length += 8*block_size;                                       \
              md-> state_var .curlen = 0;                                                   \
           }                                                                                \
       }                                                                                    \
    }                                                                                       \
    return CRYPT_OK;                                                                        \
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_hash.h,v $ */
/* $Revision: 1.22 $ */
/* $Date: 2007/05/12 14:32:35 $ */
