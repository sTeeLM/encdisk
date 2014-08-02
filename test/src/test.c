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

void test_all_cipher()
{
	/* test all cypher */
	printf("test_all_cipher----------------------------------------\n");
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

    printf("test_all_cipher passed----------------------------------------\n");
}

CRYPT_XFUN xfun;
/* one block test */


ULONG __stdcall myrand()
{
    return rand();
}

/* one sector test*/
void test_one_sector()
{
	int ret = 0, i, j;
	unsigned char plain[CRYPT_SECTOR_SIZE];
    unsigned char cipher[CRYPT_SECTOR_SIZE];
    unsigned char check[CRYPT_SECTOR_SIZE];

    printf("test_one_sector----------------------------------------\n");

	for(i = 0 ; i < CRYPT_SECTOR_SIZE; i ++) {
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
		printf("test 2 hard %d\n", i);
		ret = CryptGenContext(i % 10, &context);
		if(ret != 0) {
			printf("CryptGenContext ret %d\n", ret);
			exit(0);
		}
		ret = CryptEncryptSector(&context, plain, cipher, i, i);
		if(ret != 0) {
			printf("CryptEncrypt ret %d\n", ret);
			exit(0);
		}

		printf("after encrypt\n");

		for(j = 0 ; j < sizeof(cipher); j ++)
			printf("%02x", cipher[j]);

		printf("\n");

		ret = CryptDecryptSector(&context, cipher, plain, i, i);
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
	printf("test_one_sector passed!----------------------------------------\n");
}

int __cdecl mycmp (const void * a, const void * b)
{
    unsigned char * p1 = (unsigned char *) a;
    unsigned char * p2 = (unsigned char *) b;
    if(*p1 == *p2) return 0;
    if(*p1 > *p2) return 1;
    return -1;
}

void test_shuffle3()
{
	unsigned char plain[CRYPT_SLOT_NUMBER];
    unsigned char cipher[CRYPT_SLOT_NUMBER];
    unsigned char check[CRYPT_SLOT_NUMBER];  
    int i, j, ret;


    printf("test_shuffle3----------------------------------------\n");

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
    for(j = 0 ; j < 100; j ++ ) {
        for(i = 0 ; i < CRYPT_SLOT_NUMBER; i ++) {
            plain[i] = (unsigned char)((i + j) % CRYPT_SLOT_NUMBER);
            check[i] = plain[i];
            printf("%d ", plain[i]);
        }
        printf("\n");

        for(i = 0 ; i < CRYPT_SLOT_NUMBER; i ++) {
            cipher[i] = shuffle3encrypt(&context.shuc3, plain[i], j);
            printf("%d ", cipher[i]);
        }
        printf("\n");

        for(i = 0 ; i < CRYPT_SLOT_NUMBER; i ++) {
            plain[i] = shuffle3decrypt(&context.shuc3, cipher[i], j);
        }
        
        if(XMEMCMP(plain, check, sizeof(plain))) {
            printf("check failed\n");
            exit(1);
        }
        
        qsort(cipher, sizeof(cipher), 1, mycmp);
        qsort(plain, sizeof(plain), 1, mycmp);
        printf("\n\n");
        if(XMEMCMP(plain, cipher, sizeof(plain))) {
            printf("check dup failed\n");
            exit(1);
        }
    }
    ret = CryptCleanupContext(&context);
	if(ret != 0) {
        printf("CryptCleanupContext ret %d\n", ret);
        exit(0);
	}
    printf("test_shuffle3 passed----------------------------------------\n");
}

/* single bytes test */
void test_shuffle8()
{
	unsigned char plain[CRYPT_SECTOR_P_CLUSTER];
    unsigned char cipher[CRYPT_SECTOR_P_CLUSTER];
    unsigned char check[CRYPT_SECTOR_P_CLUSTER];  
    int i, j, ret;


    printf("test_shuffle8----------------------------------------\n");

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
    for(j = 0 ; j < 100; j ++ ) {
        for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER; i ++) {
            plain[i] = (unsigned char)((i + j) % CRYPT_SECTOR_P_CLUSTER);
            check[i] = plain[i];
            printf("%d ", plain[i]);
        }
        printf("\n");

        for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER; i ++) {
            cipher[i] = shuffle8encrypt(&context.shuc8, plain[i], j);
            printf("%d ", cipher[i]);
        }
        printf("\n");

        for(i = 0 ; i < CRYPT_SECTOR_P_CLUSTER; i ++) {
            plain[i] = shuffle8decrypt(&context.shuc8, cipher[i], j);
        }

        if(XMEMCMP(plain, check, sizeof(plain))) {
            printf("check failed\n");
            exit(1);
        }
        qsort(cipher, sizeof(cipher), 1, mycmp);
        qsort(plain, sizeof(plain), 1, mycmp);
        printf("\n\n");
        if(XMEMCMP(plain, cipher, sizeof(plain))) {
            printf("check dup failed\n");
            exit(1);
        }
    }
    ret = CryptCleanupContext(&context);
	if(ret != 0) {
        printf("CryptCleanupContext ret %d\n", ret);
        exit(0);
	}
    printf("test_shuffle8 passed----------------------------------------\n");
}

/* one cluster test */
void test_one_cluster()
{
	int ret = 0, i, j;
	unsigned char* plain;
	unsigned char* cipher;
    unsigned char* check;

    printf("test_one_cluster----------------------------------------\n");

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
    printf("test_one_cluster passed!----------------------------------------\n");
}

void mymemcpy(void *dest, const void *src, SIZE_T n)
{
    RtlCopyMemory(dest, src, n);
}

INT mymemcmp(const void *s1, const void *s2, SIZE_T n)
{
    return (INT)memcmp(s1, s2, n);
}

/* multi cluster test */
void test_n_cluster()
{
	int ret = 0, i, j;
	unsigned char* plain;
    unsigned char* cipher;
    unsigned char* check;
    int cluster_cnt = 64;
    int size = cluster_cnt * CRYPT_CLUSTER_SIZE;
    time_t begin, end;

    printf("test_n_cluster----------------------------------------\n");

    plain = malloc(size);
    cipher = malloc(size);
    check = malloc(size);

	for(i = 0 ; i < size; i ++) {
		plain[i] = 'A';
		check[i] = 'A';
	}

    memset(&xfun, 0, sizeof(xfun));

    xfun.xrand = myrand;
    xfun.xmemcpy = mymemcpy;
    xfun.xmemcmp = mymemcmp;

    if(CryptInitialize(&xfun) != CRYPT_OK) {
        printf("CryptInitialize failed\n");
        exit(1);
    }
    for(j = CRYPT_MIN_HARD; j <= CRYPT_MAX_HARD; j ++) {
        ret = CryptGenContext(j, &context);
        if(ret != 0) {
            printf("CryptGenContext ret %d\n", ret);
            exit(0);
        }
        begin = time(NULL);
        for(i = 0 ; i < cluster_cnt; i ++) {
            
            ret = CryptEncryptCluster(&context, plain + i * CRYPT_CLUSTER_SIZE, 
                cipher + i * CRYPT_CLUSTER_SIZE, i);
            if(ret != 0) {
                printf("CryptEncrypt ret %d\n", ret);
                exit(0);
            }
            

            ret = CryptDecryptCluster(&context, cipher + i * CRYPT_CLUSTER_SIZE,
                plain + i * CRYPT_CLUSTER_SIZE, i);
            if(ret != 0) {
                printf("CryptDecrypt ret %d\n", ret);
                exit(0);
            }

            if(XMEMCMP(plain, check, size) != 0) {
                printf("check failed\n");
                exit(0);
            }
        }
        end = time(NULL);
        printf("%d cluster use %d sec at hard %d\n", cluster_cnt, end - begin, j);
        if(CryptCleanupContext(&context) != CRYPT_OK) {
            printf("CryptCleanupContext failed\n");
            exit(0);
        }

    }

    if(CryptCleanup() != CRYPT_OK) {
        printf("CryptCleanup failed\n");
        exit(0);
    }
    free(plain);
    free(cipher);
    free(check);
	printf("test_n_cluster passed!----------------------------------------\n");
}

/* key test */
void test_key()
{
	ULONG i;
	
	int ret;
	ULONG size;
	UCHAR * p = NULL;
	unsigned char* plain;
    unsigned char* cipher;
    unsigned char* check;

    printf("test_key----------------------------------------\n");

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
	printf("test_key passed!----------------------------------------\n");
}

int __cdecl main(int argc, char* argv[])
{
    srand((int)time(NULL));
	test_all_cipher();
    test_shuffle3();
	test_shuffle8();
    test_one_sector();
	test_one_cluster();
    test_n_cluster();
    test_key();
	return 0;
}
