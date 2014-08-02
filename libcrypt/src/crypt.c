#include "crypt.h"

#include <stddef.h>

#define CRYPT_ALGO_NOP 0
#define CRYPT_ALGO_BLOWFISH 1
#define CRYPT_ALGO_RC5 2
#define CRYPT_ALGO_RC6 3
#define CRYPT_ALGO_RC2 4
#define CRYPT_ALGO_SAFER 5
#define CRYPT_ALGO_AES 6
#define CRYPT_ALGO_XTEA 7
#define CRYPT_ALGO_TWOFISH 8
#define CRYPT_ALGO_DES3 9
#define CRYPT_ALGO_CAST5 10
#define CRYPT_ALGO_NOEKEON 11
#define CRYPT_ALGO_SKIPJACK 12
#define CRYPT_ALGO_KHAZAD 13
#define CRYPT_ALGO_KSEED 14
#define CRYPT_ALGO_KASUMI 15

#define CRYPT_ALGO_NUMBER 16


static INT CryptVerifyKey(const PCRYPT_KEY key)
{
    
	UCHAR signature[16];
	UCHAR *p = NULL;
	
	p = (UCHAR*)(key);
    p+= sizeof(key->signature);

	if(GenMd5(p, sizeof(CRYPT_KEY) - sizeof(key->signature), signature) != CRYPT_OK) 
		return CRYPT_ERROR;

	if(!XMEMCMP(signature, key->signature, sizeof(signature)))
		return CRYPT_OK;

    return CRYPT_ERROR;
}

INT CryptCleanupContext(PCRYPT_CONTEXT context)
{
    INT i;
    for(i = 0 ; i < CRYPT_SLOT_NUMBER; i ++){
        if(cbc_done(
            &context->cbc[i]
            ) != CRYPT_OK) return CRYPT_ERROR;
    }

    if(shuffle3done(&context->shuc3) != CRYPT_OK)
        return CRYPT_ERROR;

    if(shuffle8done(&context->shuc8) != CRYPT_OK)
        return CRYPT_ERROR;

    XZEROMEM(context, sizeof(CRYPT_CONTEXT));

    return CRYPT_OK;
}

INT CryptRestoreContext(PCRYPT_CONTEXT context)
{
    INT i;
    INT keylen;
    /* fill fn point*/ 
    for(i = 0 ; i < CRYPT_SLOT_NUMBER; i ++){
        keylen = sizeof(context->key.key[i]);
        if(cipher_descriptor[context->key.algo[i]].keysize(&keylen) != CRYPT_OK)
            return CRYPT_ERROR;
        
        if(cbc_start(context->key.algo[i], context->key.iv[i], 
            context->key.key[i], keylen, 0, &context->cbc[i]) != CRYPT_OK)
            return CRYPT_ERROR;
    }

    if(shuffle3setup(context->key.shu3, sizeof(context->key.shu3), 
        &context->shuc3) != CRYPT_OK) return CRYPT_ERROR;
    if(shuffle8setup(context->key.shu8, sizeof(context->key.shu8), 
        &context->shuc8) != CRYPT_OK) return CRYPT_ERROR;  
    
    return CRYPT_OK;
}

INT CryptGenContext(INT hard, PCRYPT_CONTEXT context)
{
    INT i, keysize;
    UCHAR key[CRYPT_KEY_SIZE];
    UCHAR iv[CRYPT_IV_SIZE];
	UCHAR *p = NULL;

    if(hard < CRYPT_MIN_HARD )
        hard = CRYPT_MIN_HARD;
    if(hard > CRYPT_MAX_HARD)
        hard = CRYPT_MAX_HARD;


    RngGetBytes(context, sizeof(CRYPT_CONTEXT));

    /* fill algo array */
    for(i = 0 ; i < CRYPT_SLOT_NUMBER; i ++) {
        if(i < hard)
            while((context->key.algo[i] = XRAND() % CRYPT_ALGO_NUMBER) == CRYPT_ALGO_NOP);
        else
            context->key.algo[i] = CRYPT_ALGO_NOP;

        if(cipher_descriptor[context->key.algo[i]].test() != CRYPT_OK)
            goto err;
        if(RngGetBytes(key, sizeof(key)) == 0)
            goto err;
        if(RngGetBytes(iv, sizeof(iv)) == 0)
            goto err;
        XMEMCPY(context->key.key[i], key, sizeof(context->key.key[i]));
        XMEMCPY(context->key.iv[i], iv, sizeof(context->key.iv[i]));
    }

    /* fill cbc struct */
    if(CryptRestoreContext(context) != CRYPT_OK) goto err;

	p = (UCHAR*)(&context->key);
    p+= sizeof(context->key.signature);

	if(GenMd5(p, sizeof(CRYPT_KEY) - sizeof(context->key.signature), context->key.signature) != CRYPT_OK) goto err;

    return CRYPT_OK;
err:
    return CRYPT_ERROR;
}

/* 
 sector_index: index within one cluster
 cluster_index: index of cluster
 buffer must have CRYPT_SECTOR_SIZE bytes ! */
INT CryptEncryptSector(PCRYPT_CONTEXT context, const void * plain, void * cipher, ULONG sector_index, ULONGLONG cluster_index)
{

    UCHAR  i, x;

    XMEMCPY(cipher, plain, CRYPT_SECTOR_SIZE);
    for(i = 0; i < CRYPT_SLOT_NUMBER; i ++) {
        //x = (cluster_index + i) % CRYPT_SLOT_NUMBER;
        x = shuffle3encrypt(&context->shuc3, i, sector_index + cluster_index * CRYPT_SECTOR_P_CLUSTER);
        /* reset iv */
        if(cbc_setiv(
            context->key.iv[x],
            cipher_descriptor[context->key.algo[x]].block_length,
            &context->cbc[x]
            )!= CRYPT_OK) return CRYPT_ERROR;
        /* encrypt it */

        if(cbc_encrypt(
            cipher, 
            cipher, 
            CRYPT_SECTOR_SIZE, 
            &context->cbc[x]
            ) != CRYPT_OK) return CRYPT_ERROR;
    }
    return CRYPT_OK;
}

/* 
 sector_index: index within one cluster
 cluster_index: index of cluster
 buffer must have CRYPT_SECTOR_SIZE bytes ! */
INT CryptDecryptSector(PCRYPT_CONTEXT context, const void * cipher, void * plain, ULONG sector_index, ULONGLONG cluster_index)
{

    UCHAR i,x;

    XMEMCPY(plain, cipher, CRYPT_SECTOR_SIZE);
    for(i = CRYPT_SLOT_NUMBER ; i > 0 ; i--) {
        //x = (cluster_index + i - 1) % CRYPT_SLOT_NUMBER;
        x = shuffle3encrypt(&context->shuc3, i - 1, sector_index + cluster_index * CRYPT_SECTOR_P_CLUSTER);
        /* reset iv */
        if(cbc_setiv(
            context->key.iv[x],
            cipher_descriptor[context->key.algo[x]].block_length,
            &context->cbc[x]
            )!= CRYPT_OK) return CRYPT_ERROR;

        /* decrypt it */
  
        if(cbc_decrypt(
            plain,
            plain, 
            CRYPT_SECTOR_SIZE, 
            &context->cbc[x]
            ) != CRYPT_OK) return CRYPT_ERROR;
    }
    return CRYPT_OK;
}

/* 
index: cluster number from begin of disk
buffer must have CRYPT_CLUSTER_SIZE bytes ! */
INT CryptEncryptCluster(PCRYPT_CONTEXT context, const void * plain, void * cipher, ULONGLONG cluster_index)
{

    ULONG i;
    UCHAR x;
    const UCHAR * p = (UCHAR *) plain;
    UCHAR * c = (UCHAR *) cipher;

    for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER ; i++) {
        //x = SingleByteEncrypt(&context->shuff, i % 256 , index);
        x = shuffle8encrypt(&context->shuc8, (UCHAR)(i), cluster_index);
        if(CryptEncryptSector(context, p + i * CRYPT_SECTOR_SIZE, c + 
            x * CRYPT_SECTOR_SIZE, i, cluster_index) != CRYPT_OK)
            return CRYPT_ERROR;
    }
    return CRYPT_OK;
}

/* 
index: cluster number from begin of disk
buffer must have CRYPT_CLUSTER_SIZE bytes ! */
INT CryptDecryptCluster(PCRYPT_CONTEXT context, const void * cipher, void * plain, ULONGLONG cluster_index)
{
    ULONG i;
    UCHAR x;
    UCHAR * p = (UCHAR *) plain;
    const UCHAR * c = (UCHAR *) cipher;

    for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER ; i++) {
        //x = SingleByteDecrypt(&context->shuff, i % 256 , index);
        x = shuffle8decrypt(&context->shuc8, (UCHAR)(i), cluster_index);
        if(CryptDecryptSector(context, c + i * CRYPT_SECTOR_SIZE, 
            p + x * CRYPT_SECTOR_SIZE, x, cluster_index) != CRYPT_OK)
            return CRYPT_ERROR;
    }
    return CRYPT_OK;
}

static INT AesEncrypt(void * buf, ULONG size, const CHAR * pass)
{
	
	UCHAR key[16], iv[16];
	symmetric_CFB cfb;	

	// generate key
	if(GenMd5(pass, XSTRLEN(pass), key) != CRYPT_OK) goto err;

	// generate iv
	if(GenMd5(key, sizeof(key), iv) != CRYPT_OK) goto err;

	// encrypt with cfb mode
	//INT cfb_start(INT cipher, const UCHAR  *IV, const UCHAR  *key, 
    //          INT keylen, INT num_rounds, symmetric_CFB *cfb)
	if(cfb_start(CRYPT_ALGO_AES, iv, key, sizeof(key), 0, &cfb) != CRYPT_OK) goto err;

	//INT cfb_encrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_CFB *cfb)
	if(cfb_encrypt(buf, buf, size, &cfb) != CRYPT_OK) goto err;

	if(cfb_done(&cfb) != CRYPT_OK) goto err;

	return CRYPT_OK;
err:
    return CRYPT_ERROR;
}

static INT AesDecrypt(void * buf, ULONG size, const CHAR * pass)
{
	UCHAR key[16], iv[16];
	symmetric_CFB cfb;

	// generate key
	if(GenMd5(pass, XSTRLEN(pass), key) != CRYPT_OK) goto err;

	// generate iv
	if(GenMd5(key, sizeof(key), iv) != CRYPT_OK) goto err;

	// encrypt with cfb mode
	//INT cfb_start(INT cipher, const UCHAR  *IV, const UCHAR  *key, 
    //          INT keylen, INT num_rounds, symmetric_CFB *cfb)
	if(cfb_start(CRYPT_ALGO_AES, iv, key, sizeof(key), 0, &cfb) != CRYPT_OK) goto err;

	//INT cfb_decrypt(const UCHAR *pt, UCHAR *ct, ULONG len, symmetric_CFB *cfb)
	if(cfb_decrypt(buf, buf, size, &cfb) != CRYPT_OK) goto err;

	if(cfb_done(&cfb) != CRYPT_OK) goto err;

	return CRYPT_OK;
err:
	return CRYPT_ERROR;
}

INT CryptEncodeKey(const PCRYPT_KEY in, PCRYPT_KEY work, void * out, const CHAR * password, ULONG * out_size)
{
    CHAR * buf = (CHAR *)out;
	CHAR junk;
	INT ret;

    XMEMCPY(work, in, sizeof(CRYPT_KEY));
    
    if(AesEncrypt(work, sizeof(CRYPT_KEY), password) != CRYPT_OK) {
        return CRYPT_ERROR;
    }

	if(buf == NULL && *out_size == 0) {
		buf = &junk;
	}

	ret = base64_encode((const UCHAR *)work, sizeof(CRYPT_KEY), buf, out_size);

    if(ret == CRYPT_OK) {
        return CRYPT_OK;
    } else if(ret == CRYPT_BUFFER_OVERFLOW) {
		return CRYPT_BUFFER_OVERFLOW;
	} else {
		return CRYPT_ERROR;
	}
}

/*CryptDecodeKey(p, &context1.key, "finish", size);*/
INT CryptDecodeKey(const void * in, PCRYPT_KEY out, const CHAR * password, ULONG in_size)
{

    ULONG len = sizeof(CRYPT_KEY);

    if(base64_decode((const UCHAR *)in, in_size, (UCHAR *) out, &len) != CRYPT_OK) {
        return CRYPT_ERROR;
    }

    if(len != sizeof(CRYPT_KEY)) {
        return CRYPT_ERROR;
    }

    if(AesDecrypt(out, sizeof(CRYPT_KEY), password) != CRYPT_OK) {
        return CRYPT_ERROR;
    }

    if(CryptVerifyKey(out) != CRYPT_OK) {
        return CRYPT_ERROR;
    }
   
    return CRYPT_OK;
}

extern CRYPT_XFUN xfun;
INT CryptInitialize(PCRYPT_XFUN newfun)
{
    INT i;
    if(newfun != NULL)
	    XMEMCPY(&xfun, newfun, sizeof(xfun));

    // register cipher
    if(register_cipher(&nop_desc) != CRYPT_ALGO_NOP ) return CRYPT_ERROR;
    if(register_cipher(&blowfish_desc) != CRYPT_ALGO_BLOWFISH ) return CRYPT_ERROR;
    if(register_cipher(&rc5_desc) != CRYPT_ALGO_RC5 ) return CRYPT_ERROR;
    if(register_cipher(&rc6_desc) != CRYPT_ALGO_RC6 ) return CRYPT_ERROR;
    if(register_cipher(&rc2_desc) != CRYPT_ALGO_RC2 ) return CRYPT_ERROR;
    
    

    if(register_cipher(&saferp_desc) != CRYPT_ALGO_SAFER ) return CRYPT_ERROR;
    if(register_cipher(&aes_desc) != CRYPT_ALGO_AES ) return CRYPT_ERROR;
    if(register_cipher(&xtea_desc) != CRYPT_ALGO_XTEA ) return CRYPT_ERROR;
    if(register_cipher(&twofish_desc) != CRYPT_ALGO_TWOFISH ) return CRYPT_ERROR;
    if(register_cipher(&des3_desc) != CRYPT_ALGO_DES3 ) return CRYPT_ERROR;

    if(register_cipher(&cast5_desc) != CRYPT_ALGO_CAST5 ) return CRYPT_ERROR;
    if(register_cipher(&noekeon_desc) != CRYPT_ALGO_NOEKEON ) return CRYPT_ERROR;
    if(register_cipher(&skipjack_desc) != CRYPT_ALGO_SKIPJACK ) return CRYPT_ERROR;
    if(register_cipher(&khazad_desc) != CRYPT_ALGO_KHAZAD ) return CRYPT_ERROR;
    if(register_cipher(&kseed_desc) != CRYPT_ALGO_KSEED ) return CRYPT_ERROR;

    if(register_cipher(&kasumi_desc) != CRYPT_ALGO_KASUMI ) return CRYPT_ERROR;

	return CRYPT_OK;
}

INT CryptCleanup(void)
{
    XZEROMEM(&xfun, sizeof(xfun));

    // unregister cipher
    if(unregister_cipher(&nop_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&blowfish_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&rc5_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&rc6_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&rc2_desc) != CRYPT_OK) return CRYPT_ERROR;

    if(unregister_cipher(&saferp_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&aes_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&xtea_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&twofish_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&des3_desc) != CRYPT_OK) return CRYPT_ERROR;

    if(unregister_cipher(&cast5_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&noekeon_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&skipjack_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&khazad_desc) != CRYPT_OK) return CRYPT_ERROR;
    if(unregister_cipher(&kseed_desc) != CRYPT_OK) return CRYPT_ERROR;

    if(unregister_cipher(&kasumi_desc) != CRYPT_OK) return CRYPT_ERROR;

	return CRYPT_OK;
}

CONST CHAR * CryptAlgoName(INT algo)
{
    if(algo < CRYPT_ALGO_NUMBER && algo >= 0)
        return cipher_descriptor[algo].name;
    return "unknown";
}
