#ifndef __CRYPT_CIPHER_H__
#define __CRYPT_CIPHER_H__

/* ---- SYMMETRIC KEY STUFF -----
 *
 * We put each of the ciphers scheduled keys in their own structs then we put all of 
 * the key formats in one union.  This makes the function prototypes easier to use.
 */
#ifdef LTC_BLOWFISH
struct blowfish_key {
   ULONG S[4][256];
   ULONG K[18];
};
#endif

#ifdef LTC_RC5
struct rc5_key {
   INT rounds;
   ULONG K[50];
};
#endif

#ifdef LTC_RC6
struct rc6_key {
   ULONG K[44];
};
#endif

#ifdef LTC_SAFERP
struct saferp_key {
   UCHAR K[33][16];
   LONG rounds;
};
#endif

#ifdef LTC_RIJNDAEL
struct rijndael_key {
   ULONG eK[60], dK[60];
   INT Nr;
};
#endif

#ifdef LTC_KSEED
struct kseed_key {
    ULONG K[32], dK[32];
};
#endif

#ifdef LTC_KASUMI
struct kasumi_key {
    ULONG KLi1[8], KLi2[8],
            KOi1[8], KOi2[8], KOi3[8],
            KIi1[8], KIi2[8], KIi3[8];
};
#endif

#ifdef LTC_XTEA
struct xtea_key {
   ULONG A[32], B[32];
};
#endif

#ifdef LTC_TWOFISH
#ifndef LTC_TWOFISH_SMALL
   struct twofish_key {
      ULONG S[4][256], K[40];
   };
#else
   struct twofish_key {
      ULONG K[40];
      UCHAR S[32], start;
   };
#endif
#endif

#ifdef LTC_SAFER
#define LTC_SAFER_K64_DEFAULT_NOF_ROUNDS     6
#define LTC_SAFER_K128_DEFAULT_NOF_ROUNDS   10
#define LTC_SAFER_SK64_DEFAULT_NOF_ROUNDS    8
#define LTC_SAFER_SK128_DEFAULT_NOF_ROUNDS  10
#define LTC_SAFER_MAX_NOF_ROUNDS            13
#define LTC_SAFER_BLOCK_LEN                  8
#define LTC_SAFER_KEY_LEN     (1 + LTC_SAFER_BLOCK_LEN * (1 + 2 * LTC_SAFER_MAX_NOF_ROUNDS))
typedef UCHAR safer_block_t[LTC_SAFER_BLOCK_LEN];
typedef UCHAR safer_key_t[LTC_SAFER_KEY_LEN];
struct safer_key { safer_key_t key; };
#endif

#ifdef LTC_RC2
struct rc2_key { unsigned xkey[64]; };
#endif

#ifdef LTC_DES
struct des_key {
    ULONG ek[32], dk[32];
};

struct des3_key {
    ULONG ek[3][32], dk[3][32];
};
#endif

#ifdef LTC_CAST5
struct cast5_key {
    ULONG K[32], keylen;
};
#endif

#ifdef LTC_NOEKEON
struct noekeon_key {
    ULONG K[4], dK[4];
};
#endif

#ifdef LTC_SKIPJACK 
struct skipjack_key {
    UCHAR key[10];
};
#endif

#ifdef LTC_KHAZAD
struct khazad_key {
   ULONG64 roundKeyEnc[8 + 1]; 
   ULONG64 roundKeyDec[8 + 1]; 
};
#endif

#ifdef LTC_ANUBIS
struct anubis_key { 
   INT keyBits; 
   INT R; 
   ULONG roundKeyEnc[18 + 1][4]; 
   ULONG roundKeyDec[18 + 1][4]; 
}; 
#endif

#ifdef LTC_MULTI2
struct multi2_key {
    INT N;
    ULONG uk[8];
};
#endif

typedef union Symmetric_key {
#ifdef LTC_DES
   struct des_key des;
   struct des3_key des3;
#endif
#ifdef LTC_RC2
   struct rc2_key rc2;
#endif
#ifdef LTC_SAFER
   struct safer_key safer;
#endif
#ifdef LTC_TWOFISH
   struct twofish_key  twofish;
#endif
#ifdef LTC_BLOWFISH
   struct blowfish_key blowfish;
#endif
#ifdef LTC_RC5
   struct rc5_key      rc5;
#endif
#ifdef LTC_RC6
   struct rc6_key      rc6;
#endif
#ifdef LTC_SAFERP
   struct saferp_key   saferp;
#endif
#ifdef LTC_RIJNDAEL
   struct rijndael_key rijndael;
#endif
#ifdef LTC_XTEA
   struct xtea_key     xtea;
#endif
#ifdef LTC_CAST5
   struct cast5_key    cast5;
#endif
#ifdef LTC_NOEKEON
   struct noekeon_key  noekeon;
#endif   
#ifdef LTC_SKIPJACK
   struct skipjack_key skipjack;
#endif
#ifdef LTC_KHAZAD
   struct khazad_key   khazad;
#endif
#ifdef LTC_ANUBIS
   struct anubis_key   anubis;
#endif
#ifdef LTC_KSEED
   struct kseed_key    kseed;
#endif
#ifdef LTC_KASUMI
   struct kasumi_key   kasumi;
#endif  
#ifdef LTC_MULTI2
   struct multi2_key   multi2;
#endif
   void   *data;
} symmetric_key;

#ifdef LTC_ECB_MODE
/** A block cipher ECB structure */
typedef struct {
   /** The index of the cipher chosen */
   INT                 cipher, 
   /** The block size of the given cipher */
                       blocklen;
   /** The scheduled key */                       
   symmetric_key       key;
} symmetric_ECB;
#endif

#ifdef LTC_CFB_MODE
/** A block cipher CFB structure */
typedef struct {
   /** The index of the cipher chosen */
   INT                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen, 
   /** The padding offset */
                       padlen;
   /** The current IV */
   UCHAR       IV[MAXBLOCKSIZE], 
   /** The pad used to encrypt/decrypt */ 
                       pad[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CFB;
#endif

#ifdef LTC_OFB_MODE
/** A block cipher OFB structure */
typedef struct {
   /** The index of the cipher chosen */
   INT                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen, 
   /** The padding offset */
                       padlen;
   /** The current IV */
   UCHAR       IV[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_OFB;
#endif

#ifdef LTC_CBC_MODE
/** A block cipher CBC structure */
typedef struct {
   /** The index of the cipher chosen */
   INT                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen;
   /** The current IV */
   UCHAR       IV[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CBC;
#endif


#ifdef LTC_CTR_MODE
/** A block cipher CTR structure */
typedef struct {
   /** The index of the cipher chosen */
   INT                 cipher,
   /** The block size of the given cipher */                        
                       blocklen, 
   /** The padding offset */
                       padlen, 
   /** The mode (endianess) of the CTR, 0==little, 1==big */
                       mode,
   /** counter width */
                       ctrlen;

   /** The counter */                       
   UCHAR       ctr[MAXBLOCKSIZE], 
   /** The pad used to encrypt/decrypt */                       
                       pad[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CTR;
#endif


#ifdef LTC_LRW_MODE
/** A LRW structure */
typedef struct {
    /** The index of the cipher chosen (must be a 128-bit block cipher) */
    INT               cipher;

    /** The current IV */
    UCHAR     IV[16],
 
    /** the tweak key */
                      tweak[16],

    /** The current pad, it's the product of the first 15 bytes against the tweak key */
                      pad[16];

    /** The scheduled symmetric key */
    symmetric_key     key;

#ifdef LRW_TABLES
    /** The pre-computed multiplication table */
    UCHAR     PC[16][256][16];
#endif
} symmetric_LRW;
#endif

#ifdef LTC_F8_MODE
/** A block cipher F8 structure */
typedef struct {
   /** The index of the cipher chosen */
   INT                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen, 
   /** The padding offset */
                       padlen;
   /** The current IV */
   UCHAR       IV[MAXBLOCKSIZE],
                       MIV[MAXBLOCKSIZE];
   /** Current block count */
   ULONG             blockcnt;
   /** The scheduled key */
   symmetric_key       key;
} symmetric_F8;
#endif


/** cipher descriptor table, last entry has "name == NULL" to mark the end of table */
extern struct ltc_cipher_descriptor {
   /** name of cipher */
   char *name;
   /** INTernal ID */
   UCHAR ID;
   /** min keysize (octets) */
   INT  min_key_length, 
   /** max keysize (octets) */
        max_key_length, 
   /** block size (octets) */
        block_length, 
   /** default number of rounds */
        default_rounds;
   /** Setup the cipher 
      @param key         The input symmetric key
      @param keylen      The length of the input key (octets)
      @param num_rounds  The requested number of rounds (0==default)
      @param skey        [out] The destination of the scheduled key
      @return CRYPT_OK if successful
   */
   INT  (*setup)(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
   /** Encrypt a block
      @param pt      The plaINText
      @param ct      [out] The ciphertext
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   INT (*ecb_encrypt)(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
   /** Decrypt a block
      @param ct      The ciphertext
      @param pt      [out] The plaINText
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   INT (*ecb_decrypt)(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
   /** Test the block cipher
       @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
   */
   INT (*test)(void);

   /** Terminate the context 
      @param skey    The scheduled key
   */
   void (*done)(symmetric_key *skey);      

   /** Determine a key size
       @param keysize    [in/out] The size of the key desired and the suggested size
       @return CRYPT_OK if successful
   */
   INT  (*keysize)(INT *keysize);

/** Accelerators **/
   /** Accelerated ECB encryption 
       @param pt      PlaINText
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   INT (*accel_ecb_encrypt)(const UCHAR *pt, UCHAR *ct, ULONG blocks, symmetric_key *skey);

   /** Accelerated ECB decryption 
       @param pt      PlaINText
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   INT (*accel_ecb_decrypt)(const UCHAR *ct, UCHAR *pt, ULONG blocks, symmetric_key *skey);

   /** Accelerated CBC encryption 
       @param pt      PlaINText
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   INT (*accel_cbc_encrypt)(const UCHAR *pt, UCHAR *ct, ULONG blocks, UCHAR *IV, symmetric_key *skey);

   /** Accelerated CBC decryption 
       @param pt      PlaINText
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   INT (*accel_cbc_decrypt)(const UCHAR *ct, UCHAR *pt, ULONG blocks, UCHAR *IV, symmetric_key *skey);

   /** Accelerated CTR encryption 
       @param pt      PlaINText
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param mode    little or big endian counter (mode=0 or mode=1)
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   INT (*accel_ctr_encrypt)(const UCHAR *pt, UCHAR *ct, ULONG blocks, UCHAR *IV, INT mode, symmetric_key *skey);

   /** Accelerated LRW 
       @param pt      PlaINText
       @param ct      Ciphertext
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param tweak   The LRW tweak
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   INT (*accel_lrw_encrypt)(const UCHAR *pt, UCHAR *ct, ULONG blocks, UCHAR *IV, const UCHAR *tweak, symmetric_key *skey);

   /** Accelerated LRW 
       @param ct      Ciphertext
       @param pt      PlaINText
       @param blocks  The number of complete blocks to process
       @param IV      The initial value (input/output)
       @param tweak   The LRW tweak
       @param skey    The scheduled key context
       @return CRYPT_OK if successful
   */
   INT (*accel_lrw_decrypt)(const UCHAR *ct, UCHAR *pt, ULONG blocks, UCHAR *IV, const UCHAR *tweak, symmetric_key *skey);

   /** Accelerated CCM packet (one-shot)
       @param key        The secret key to use
       @param keylen     The length of the secret key (octets)
       @param uskey      A previously scheduled key [optional can be NULL]
       @param nonce      The session nonce [use once]
       @param noncelen   The length of the nonce
       @param header     The header for the session
       @param headerlen  The length of the header (octets)
       @param pt         [out] The plaINText
       @param ptlen      The length of the plaINText (octets)
       @param ct         [out] The ciphertext
       @param tag        [out] The destination tag
       @param taglen     [in/out] The max size and resulting size of the authentication tag
       @param direction  Encrypt or Decrypt direction (0 or 1)
       @return CRYPT_OK if successful
   */
   INT (*accel_ccm_memory)(
       const UCHAR *key,    ULONG keylen,
       symmetric_key       *uskey,
       const UCHAR *nonce,  ULONG noncelen,
       const UCHAR *header, ULONG headerlen,
             UCHAR *pt,     ULONG ptlen,
             UCHAR *ct,
             UCHAR *tag,    ULONG *taglen,
                       INT  direction);

   /** Accelerated GCM packet (one shot)
       @param key        The secret key
       @param keylen     The length of the secret key
       @param IV         The initial vector 
       @param IVlen      The length of the initial vector
       @param adata      The additional authentication data (header)
       @param adatalen   The length of the adata
       @param pt         The plaINText
       @param ptlen      The length of the plaINText (ciphertext length is the same)
       @param ct         The ciphertext
       @param tag        [out] The MAC tag
       @param taglen     [in/out] The MAC tag length
       @param direction  Encrypt or Decrypt mode (GCM_ENCRYPT or GCM_DECRYPT)
       @return CRYPT_OK on success
   */
   INT (*accel_gcm_memory)(
       const UCHAR *key,    ULONG keylen,
       const UCHAR *IV,     ULONG IVlen,
       const UCHAR *adata,  ULONG adatalen,
             UCHAR *pt,     ULONG ptlen,
             UCHAR *ct, 
             UCHAR *tag,    ULONG *taglen,
                       INT direction);

   /** Accelerated one shot LTC_OMAC 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
   */
   INT (*omac_memory)(
       const UCHAR *key, ULONG keylen,
       const UCHAR *in,  ULONG inlen,
             UCHAR *out, ULONG *outlen);

   /** Accelerated one shot XCBC 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
   */
   INT (*xcbc_memory)(
       const UCHAR *key, ULONG keylen,
       const UCHAR *in,  ULONG inlen,
             UCHAR *out, ULONG *outlen);

   /** Accelerated one shot F9 
       @param key            The secret key
       @param keylen         The key length (octets) 
       @param in             The message 
       @param inlen          Length of message (octets)
       @param out            [out] Destination for tag
       @param outlen         [in/out] Initial and final size of out
       @return CRYPT_OK on success
       @remark Requires manual padding
   */
   INT (*f9_memory)(
       const UCHAR *key, ULONG keylen,
       const UCHAR *in,  ULONG inlen,
             UCHAR *out, ULONG *outlen);
} cipher_descriptor[];

#ifdef LTC_NOP
INT nop_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT nop_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT nop_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT nop_test(void);
void nop_done(symmetric_key *skey);
INT nop_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor nop_desc;
#endif

#ifdef LTC_BLOWFISH
INT blowfish_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT blowfish_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT blowfish_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT blowfish_test(void);
void blowfish_done(symmetric_key *skey);
INT blowfish_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor blowfish_desc;
#endif

#ifdef LTC_RC5
INT rc5_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT rc5_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT rc5_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT rc5_test(void);
void rc5_done(symmetric_key *skey);
INT rc5_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor rc5_desc;
#endif

#ifdef LTC_RC6
INT rc6_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT rc6_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT rc6_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT rc6_test(void);
void rc6_done(symmetric_key *skey);
INT rc6_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor rc6_desc;
#endif

#ifdef LTC_RC2
INT rc2_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT rc2_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT rc2_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT rc2_test(void);
void rc2_done(symmetric_key *skey);
INT rc2_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor rc2_desc;
#endif

#ifdef LTC_SAFERP
INT saferp_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT saferp_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT saferp_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT saferp_test(void);
void saferp_done(symmetric_key *skey);
INT saferp_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor saferp_desc;
#endif

#ifdef LTC_SAFER
INT safer_k64_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT safer_sk64_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT safer_k128_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT safer_sk128_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT safer_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *key);
INT safer_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *key);
INT safer_k64_test(void);
INT safer_sk64_test(void);
INT safer_sk128_test(void);
void safer_done(symmetric_key *skey);
INT safer_64_keysize(INT *keysize);
INT safer_128_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor safer_k64_desc, safer_k128_desc, safer_sk64_desc, safer_sk128_desc;
#endif

#ifdef LTC_RIJNDAEL

/* make aes an alias */
#define aes_setup           rijndael_setup
#define aes_ecb_encrypt     rijndael_ecb_encrypt
#define aes_ecb_decrypt     rijndael_ecb_decrypt
#define aes_test            rijndael_test
#define aes_done            rijndael_done
#define aes_keysize         rijndael_keysize

#define aes_enc_setup           rijndael_enc_setup
#define aes_enc_ecb_encrypt     rijndael_enc_ecb_encrypt
#define aes_enc_keysize         rijndael_enc_keysize

INT rijndael_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT rijndael_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT rijndael_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT rijndael_test(void);
void rijndael_done(symmetric_key *skey);
INT rijndael_keysize(INT *keysize);
INT rijndael_enc_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT rijndael_enc_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
void rijndael_enc_done(symmetric_key *skey);
INT rijndael_enc_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor rijndael_desc, aes_desc;
extern const struct ltc_cipher_descriptor rijndael_enc_desc, aes_enc_desc;
#endif

#ifdef LTC_XTEA
INT xtea_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT xtea_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT xtea_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT xtea_test(void);
void xtea_done(symmetric_key *skey);
INT xtea_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor xtea_desc;
#endif

#ifdef LTC_TWOFISH
INT twofish_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT twofish_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT twofish_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT twofish_test(void);
void twofish_done(symmetric_key *skey);
INT twofish_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor twofish_desc;
#endif

#ifdef LTC_DES
INT des_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT des_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT des_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT des_test(void);
void des_done(symmetric_key *skey);
INT des_keysize(INT *keysize);
INT des3_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT des3_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT des3_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT des3_test(void);
void des3_done(symmetric_key *skey);
INT des3_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor des_desc, des3_desc;
#endif

#ifdef LTC_CAST5
INT cast5_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT cast5_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT cast5_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT cast5_test(void);
void cast5_done(symmetric_key *skey);
INT cast5_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor cast5_desc;
#endif

#ifdef LTC_NOEKEON
INT noekeon_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT noekeon_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT noekeon_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT noekeon_test(void);
void noekeon_done(symmetric_key *skey);
INT noekeon_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor noekeon_desc;
#endif

#ifdef LTC_SKIPJACK
INT skipjack_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT skipjack_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT skipjack_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT skipjack_test(void);
void skipjack_done(symmetric_key *skey);
INT skipjack_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor skipjack_desc;
#endif

#ifdef LTC_KHAZAD
INT khazad_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT khazad_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT khazad_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT khazad_test(void);
void khazad_done(symmetric_key *skey);
INT khazad_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor khazad_desc;
#endif

#ifdef LTC_ANUBIS
INT anubis_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT anubis_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT anubis_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT anubis_test(void);
void anubis_done(symmetric_key *skey);
INT anubis_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor anubis_desc;
#endif

#ifdef LTC_KSEED
INT kseed_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT kseed_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT kseed_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT kseed_test(void);
void kseed_done(symmetric_key *skey);
INT kseed_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor kseed_desc;
#endif

#ifdef LTC_KASUMI
INT kasumi_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT kasumi_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT kasumi_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT kasumi_test(void);
void kasumi_done(symmetric_key *skey);
INT kasumi_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor kasumi_desc;
#endif


#ifdef LTC_MULTI2
INT multi2_setup(const UCHAR *key, INT keylen, INT num_rounds, symmetric_key *skey);
INT multi2_ecb_encrypt(const UCHAR *pt, UCHAR *ct, symmetric_key *skey);
INT multi2_ecb_decrypt(const UCHAR *ct, UCHAR *pt, symmetric_key *skey);
INT multi2_test(void);
void multi2_done(symmetric_key *skey);
INT multi2_keysize(INT *keysize);
extern const struct ltc_cipher_descriptor multi2_desc;
#endif

#ifdef LTC_ECB_MODE
INT ecb_start(INT cipher, const UCHAR *key, 
              INT keylen, INT num_rounds, symmetric_ECB *ecb);
INT ecb_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_ECB *ecb);
INT ecb_decrypt(const UCHAR *ct, UCHAR *pt, ULONG len, symmetric_ECB *ecb);
INT ecb_done(symmetric_ECB *ecb);
#endif

#ifdef LTC_CFB_MODE
INT cfb_start(INT cipher, const UCHAR *IV, const UCHAR *key, 
              INT keylen, INT num_rounds, symmetric_CFB *cfb);
INT cfb_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_CFB *cfb);
INT cfb_decrypt(const UCHAR *ct, UCHAR *pt, ULONG len, symmetric_CFB *cfb);
INT cfb_getiv(UCHAR *IV, ULONG *len, symmetric_CFB *cfb);
INT cfb_setiv(const UCHAR *IV, ULONG len, symmetric_CFB *cfb);
INT cfb_done(symmetric_CFB *cfb);
#endif

#ifdef LTC_OFB_MODE
INT ofb_start(INT cipher, const UCHAR *IV, const UCHAR *key, 
              INT keylen, INT num_rounds, symmetric_OFB *ofb);
INT ofb_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_OFB *ofb);
INT ofb_decrypt(const UCHAR *ct, UCHAR *pt, ULONG len, symmetric_OFB *ofb);
INT ofb_getiv(UCHAR *IV, ULONG *len, symmetric_OFB *ofb);
INT ofb_setiv(const UCHAR *IV, ULONG len, symmetric_OFB *ofb);
INT ofb_done(symmetric_OFB *ofb);
#endif

#ifdef LTC_CBC_MODE
INT cbc_start(INT cipher, const UCHAR *IV, const UCHAR *key,
               INT keylen, INT num_rounds, symmetric_CBC *cbc);
INT cbc_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_CBC *cbc);
INT cbc_decrypt(const UCHAR *ct, UCHAR *pt, ULONG len, symmetric_CBC *cbc);
INT cbc_getiv(UCHAR *IV, ULONG *len, symmetric_CBC *cbc);
INT cbc_setiv(const UCHAR *IV, ULONG len, symmetric_CBC *cbc);
INT cbc_done(symmetric_CBC *cbc);
#endif

#ifdef LTC_CTR_MODE

#define CTR_COUNTER_LITTLE_ENDIAN    0x0000
#define CTR_COUNTER_BIG_ENDIAN       0x1000
#define LTC_CTR_RFC3686              0x2000

INT ctr_start(               INT   cipher,
              const UCHAR *IV,
              const UCHAR *key,       INT keylen,
                             INT  num_rounds, INT ctr_mode,
                   symmetric_CTR *ctr);
INT ctr_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_CTR *ctr);
INT ctr_decrypt(const UCHAR *ct, UCHAR *pt, ULONG len, symmetric_CTR *ctr);
INT ctr_getiv(UCHAR *IV, ULONG *len, symmetric_CTR *ctr);
INT ctr_setiv(const UCHAR *IV, ULONG len, symmetric_CTR *ctr);
INT ctr_done(symmetric_CTR *ctr);
INT ctr_test(void);
#endif

#ifdef LTC_F8_MODE
INT f8_start(                INT  cipher, const UCHAR *IV, 
             const UCHAR *key,                    INT  keylen, 
             const UCHAR *salt_key,               INT  skeylen,
                             INT  num_rounds,   symmetric_F8  *f8);
INT f8_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_F8 *f8);
INT f8_decrypt(const UCHAR *ct, UCHAR *pt, ULONG len, symmetric_F8 *f8);
INT f8_getiv(UCHAR *IV, ULONG *len, symmetric_F8 *f8);
INT f8_setiv(const UCHAR *IV, ULONG len, symmetric_F8 *f8);
INT f8_done(symmetric_F8 *f8);
INT f8_test_mode(void);
#endif

#ifdef LTC_XTS_MODE
typedef struct {
   symmetric_key  key1, key2;
   INT            cipher;
} symmetric_xts;

INT xts_start(                INT  cipher,
              const UCHAR *key1, 
              const UCHAR *key2, 
                    ULONG  keylen,
                              INT  num_rounds, 
                    symmetric_xts *xts);

INT xts_encrypt(
   const UCHAR *pt, ULONG ptlen,
         UCHAR *ct,
   const UCHAR *tweak,
         symmetric_xts *xts);
INT xts_decrypt(
   const UCHAR *ct, ULONG ptlen,
         UCHAR *pt,
   const UCHAR *tweak,
         symmetric_xts *xts);

void xts_done(symmetric_xts *xts);
INT  xts_test(void);
void xts_mult_x(UCHAR *I);
#endif

int find_cipher(const char *name);
int find_cipher_any(const char *name, int blocklen, int keylen);
int find_cipher_id(unsigned char ID);
int register_cipher(const struct ltc_cipher_descriptor *cipher);
int unregister_cipher(const struct ltc_cipher_descriptor *cipher);
int cipher_is_valid(int idx);

LTC_MUTEX_PROTO(ltc_cipher_mutex)


#endif
/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_cipher.h,v $ */
/* $Revision: 1.54 $ */
/* $Date: 2007/05/12 14:37:41 $ */
