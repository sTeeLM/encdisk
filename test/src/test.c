/*
    This is a virtual disk driver for Windows that uses one or more files to
    emulate physical disks.
    Copyright (C) 1999-2009 Bo Brantén.
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <windows.h>
#include <winioctl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "crypt.h"


CRYPT_CONTEXT context, context1;

void test1()
{
	/* test all cypher */
	printf("test all cypher\n");
	printf("nop_desc: %d\n", nop_desc.test());
	printf("blowfish_desc: %d\n", blowfish_desc.test());
	printf("rc5_desc: %d\n", rc5_desc.test());
	printf("rc6_desc: %d\n", rc6_desc.test());
	printf("rc2_desc: %d\n", rc2_desc.test());
	printf("saferp_desc: %d\n", saferp_desc.test());

	printf("aes_desc: %d\n", aes_desc.test());
	printf("xtea_desc: %d\n", xtea_desc.test());
	printf("twofish_desc: %d\n", twofish_desc.test());
	printf("des3_desc: %d\n", rc6_desc.test());
	printf("cast5_desc: %d\n", rc2_desc.test());
	printf("noekeon_desc: %d\n", saferp_desc.test());

	printf("skipjack_desc: %d\n", skipjack_desc.test());
	printf("khazad_desc: %d\n", khazad_desc.test());
	printf("kseed_desc: %d\n", kseed_desc.test());
	printf("kasumi_desc: %d\n", kasumi_desc.test());

    printf("test1 passed\n");
}

CRYPT_XFUN xfun;
/* one block test */


ULONG __stdcall myrand()
{
    return rand();
}

/* one sector test*/
void test2()
{
	int ret = 0, i, j;
	unsigned char plain[CRYPT_SECTOR_SIZE];
    unsigned char cipher[CRYPT_SECTOR_SIZE];
    unsigned char check[CRYPT_SECTOR_SIZE];

	for(i = 0 ; i < CRYPT_SECTOR_SIZE; i ++) {
		//plain[i] = 'A';
		//check[i] = 'A';
		plain[i] = 0;
		check[i] = 0;
	}
    memset(&xfun, 0, sizeof(xfun));
    xfun.xrand = myrand;

    if(CryptInitialize(&xfun) != CRYPT_OK) {
        printf("CryptInitialize failed\n");
        exit(1);
    }

	for(i = 0 ; i < 100; i ++) {
		printf("test 2 hard %d\n", i);
		ret = CryptGenContext(i % 10, &context);
		if(ret != 0) {
			printf("CryptGenContext ret %d\n", ret);
			exit(0);
		}
		ret = CryptEncryptSector(&context, plain, cipher, i);
		if(ret != 0) {
			printf("CryptEncrypt ret %d\n", ret);
			exit(0);
		}

		printf("after encrypt\n");

		for(j = 0 ; j < sizeof(cipher); j ++)
			printf("%02x", cipher[j]);

		printf("\n");

		ret = CryptDecryptSector(&context, cipher, plain, i);
		if(ret != 0) {
			printf("CryptDecrypt ret %d\n", ret);
			exit(0);
		}

		printf("after decrypt\n");

		for(j = 0 ; j < sizeof(plain); j ++)
			printf("%02x", plain[j]);

		printf("\n");

		if(XMEMCMP(plain, check, sizeof(plain)) != 0) {
			printf("check failed\n");
			exit(0);
		}
	}
    if(CryptCleanupContext(&context) != CRYPT_OK) {
        printf("CryptCleanupContext failed\n");
        exit(0);
    }

    if(CryptCleanup() != CRYPT_OK) {
        printf("CryptCleanup failed\n");
        exit(0);
    }
	printf("test 2 passed!\n");
}

/* single bytes test */
void test3()
{
	unsigned char plain[CRYPT_SECTOR_P_CLUSTER];
    unsigned char cipher[CRYPT_SECTOR_P_CLUSTER];
    unsigned char check[CRYPT_SECTOR_P_CLUSTER];  
    int i, ret;

    memset(&xfun, 0, sizeof(xfun));
    xfun.xrand = myrand;

    if(CryptInitialize(&xfun) != CRYPT_OK) {
        printf("CryptInitialize failed\n");
        exit(1);
    }

    ret = CryptGenContext(10, &context);
	if(ret != 0) {
        printf("CryptGenContext ret %d\n", ret);
        exit(0);
	}

    for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER; i ++) {
        plain[i] = (unsigned char)i;
        check[i] = (unsigned char)i;
    }

    for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER; i ++) {
        cipher[i] = SingleByteEncrypt(&context.shuff, plain[i], i);
        printf("enc: %d->%d\n", plain[i], cipher[i]);
    }


    for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER; i ++) {
        plain[i] = SingleByteDecrypt(&context.shuff, cipher[i], i);
        printf("dec: %d->%d\n", cipher[i], plain[i]);
    }

    ret = CryptCleanupContext(&context);
	if(ret != 0) {
        printf("CryptCleanupContext ret %d\n", ret);
        exit(0);
	}

    if(XMEMCMP(plain, check, sizeof(plain))) {
        printf("check failed\n");
    }
    printf("test 3 passed");
}

/* one cluster test */
void test4()
{
	int ret = 0, i, j;
	unsigned char* plain;
	unsigned char* cipher;
    unsigned char* check;

    plain = malloc(CRYPT_CLUSTER_SIZE);
    cipher = malloc(CRYPT_CLUSTER_SIZE);
    check = malloc(CRYPT_CLUSTER_SIZE);

	for(i = 0 ; i < CRYPT_CLUSTER_SIZE; i ++) {
		plain[i] = 'A';
		check[i] = 'A';
	}

    memset(&xfun, 0, sizeof(xfun));

    xfun.xrand = myrand;

    if(CryptInitialize(&xfun) != CRYPT_OK) {
        printf("CryptInitialize failed\n");
        exit(1);
    }

	for(i = 0 ; i < 100; i ++) {
		printf("test4 hard %d\n", i);
		ret = CryptGenContext(i % 10, &context);
		if(ret != 0) {
			printf("CryptGenContext ret %d\n", ret);
			exit(0);
		}
        
	    ret = CryptEncryptCluster(&context, plain, cipher, 0);
		if(ret != 0) {
			printf("CryptEncrypt ret %d\n", ret);
			exit(0);
		}


		ret = CryptDecryptCluster(&context, cipher, plain, 0);
    	if(ret != 0) {
		    printf("CryptDecrypt ret %d\n", ret);
			exit(0);
        }

		if(XMEMCMP(plain, check, CRYPT_CLUSTER_SIZE) != 0) {
			printf("check failed\n");
			return;
		}
	}
    if(CryptCleanupContext(&context) != CRYPT_OK) {
        printf("CryptCleanupContext failed\n");
        exit(0);
    }

    if(CryptCleanup() != CRYPT_OK) {
        printf("CryptCleanup failed\n");
        exit(0);
    }
    free(plain);
    free(cipher);
    free(check);
	printf(" test 4 passed!\n");
}

/* multi cluster test */
void test5()
{
	int ret = 0, i, j;
	unsigned char* plain;
    unsigned char* cipher;
    unsigned char* check;

    plain = malloc(CRYPT_CLUSTER_SIZE);
    cipher = malloc(CRYPT_CLUSTER_SIZE);
    check = malloc(CRYPT_CLUSTER_SIZE);

	for(i = 0 ; i < CRYPT_CLUSTER_SIZE; i ++) {
		plain[i] = 'A';
		check[i] = 'A';
	}

    memset(&xfun, 0, sizeof(xfun));

    xfun.xrand = myrand;

    if(CryptInitialize(&xfun) != CRYPT_OK) {
        printf("CryptInitialize failed\n");
        exit(1);
    }

	for(i = 0 ; i < 100; i ++) {
		printf("test5 hard %d\n", i);
		ret = CryptGenContext(i % 10, &context);
		if(ret != 0) {
			printf("CryptGenContext ret %d\n", ret);
			exit(0);
		}
        
	    ret = CryptEncryptCluster(&context, plain, cipher, i);
		if(ret != 0) {
			printf("CryptEncrypt ret %d\n", ret);
			exit(0);
		}


		ret = CryptDecryptCluster(&context, cipher, plain, i);
    	if(ret != 0) {
		    printf("CryptDecrypt ret %d\n", ret);
			exit(0);
        }

		if(XMEMCMP(plain, check, CRYPT_CLUSTER_SIZE) != 0) {
			printf("check failed\n");
			return;
		}
	}
    if(CryptCleanupContext(&context) != CRYPT_OK) {
        printf("CryptCleanupContext failed\n");
        exit(0);
    }

    if(CryptCleanup() != CRYPT_OK) {
        printf("CryptCleanup failed\n");
        exit(0);
    }
    free(plain);
    free(cipher);
    free(check);
	printf(" test 5 passed!\n");
}

/* key test */
void test6()
{
	ULONG i;
	
	int ret;
	ULONG size;
	UCHAR * p = NULL;
	unsigned char* plain;
    unsigned char* cipher;
    unsigned char* check;

    plain = malloc(CRYPT_CLUSTER_SIZE);
    cipher = malloc(CRYPT_CLUSTER_SIZE);
    check = malloc(CRYPT_CLUSTER_SIZE);

	for(i = 0 ; i < CRYPT_CLUSTER_SIZE; i ++) {
		plain[i] = 'A';
		check[i] = 'A';
	}

    memset(&xfun, 0, sizeof(xfun));

    xfun.xrand = myrand;

    if(CryptInitialize(&xfun) != CRYPT_OK) {
        printf("CryptInitialize failed\n");
        exit(1);
    }

	ret = CryptGenContext(9, &context);
	if(ret != 0) {
		printf("CryptGenContext ret %d\n", ret);
		exit(1);;
	}
	size = 0;
	ret = CryptEncodeKey(&context.key, &context1.key, p, "finish", &size);
	//printf("CryptEncodeKey ret %d\n", ret);
	if(size == 0) {
		printf("CryptEncodeKey size %d\n", size);
		exit(1);
	}

	p = malloc(size);
	ret = CryptEncodeKey(&context.key, &context1.key, p, "finish", &size);
	if(ret != 0) {
		printf("CryptEncodeKey ret %d\n", ret);
		exit(1);
	}


	for(i = 0 ; i < size; i ++) {
		printf("%c", p[i]);
	}
	printf("\n");

	
	ret = CryptDecodeKey(p, &context1.key, "finish", size);

	if(ret != 0) {
		printf("CryptDecodeKey ret %d\n", ret);
		exit(1);
	}

	if(CryptRestoreContext(&context1) != CRYPT_OK) {
		printf("CryptRestoreContext ret %d\n", ret);
		exit(1);
    }

    for(i = 0 ; i < 100; i ++) {
	    ret = CryptEncryptCluster(&context, plain, cipher, i);
		if(ret != 0) {
			printf("CryptEncrypt ret %d\n", ret);
			exit(0);
		}


		ret = CryptDecryptCluster(&context1, cipher, plain, i);
    	if(ret != 0) {
		    printf("CryptDecrypt ret %d\n", ret);
			exit(0);
        }

		if(XMEMCMP(plain, check, 4096) != 0) {
			printf("check failed\n");
			return;
		}
    }
    if(CryptCleanupContext(&context) != CRYPT_OK) {
        printf("CryptCleanupContext failed\n");
        exit(0);
    }
    if(CryptCleanupContext(&context1) != CRYPT_OK) {
        printf("CryptCleanupContext failed\n");
        exit(0);
    }
    if(CryptCleanup() != CRYPT_OK) {
        printf("CryptCleanup failed\n");
        exit(0);
    }
	printf("test 6 passed!\n");
}

int __cdecl main(int argc, char* argv[])
{
    srand((int)time(NULL));
	test1();
	test2();
	test3();
	test4();
    test5();
    test6();
	return 0;
}
