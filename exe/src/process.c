#include "control.h"


INT ProcessFile(HANDLE hFile, 
    PCRYPT_CONTEXT DecryptContext, 
    PCRYPT_CONTEXT EncryptContext)
{
    
    LARGE_INTEGER FileSize;
    LARGE_INTEGER Pos;
    ULONG b, n, i, j;
    ULONG Index;
    ULONG ClusterCount = 1024;
    LPBYTE Buffer1 = NULL;
    LPBYTE Buffer2 = NULL;
    DWORD Junk;
    INT Ret = -1;
    double Process = 0.0;


    // alloc buffer
    if((Buffer1 = malloc(CRYPT_CLUSTER_SIZE * ClusterCount)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ProcessFile:");
        goto err;
    }

    if((Buffer2 = malloc(CRYPT_CLUSTER_SIZE * ClusterCount)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ProcessFile:");
        goto err;
    }

    if(!GetFileSizeEx(hFile, &FileSize)) {
        PrintLastError("ProcessFile:");
        goto err;
    }

    n = (ULONG)(FileSize.QuadPart / CRYPT_CLUSTER_SIZE);
    Pos.QuadPart = 0;
    b = n / ClusterCount;
    i = 0;
    
again:
    // big block: process big block
    for(; i < b ; i ++) {
        if(!ReadFile(hFile, Buffer1, CRYPT_CLUSTER_SIZE * ClusterCount, &Junk, NULL)
            || Junk != CRYPT_CLUSTER_SIZE * ClusterCount) {
            PrintLastError("ProcessFile:");
            goto err;
        }
        for(j = 0 ; j < ClusterCount; j ++) {
            Process = (double)(((Pos.QuadPart + j * CRYPT_CLUSTER_SIZE) * 100) / FileSize.QuadPart);
            PrintMessage("\b\b\b\b\b\b%3.1f%%", Process);
            if(NULL != DecryptContext) {
                if(CryptDecryptCluster(DecryptContext, Buffer1 + j * CRYPT_CLUSTER_SIZE,
                    Buffer2 + j * CRYPT_CLUSTER_SIZE, i * ClusterCount + j) != CRYPT_OK) {
                    SetLastError(ERROR_INTERNAL_ERROR);
                    PrintLastError("ProcessFile:");
                    goto err;
                }
            } else {
                memcpy(Buffer2 + j * CRYPT_CLUSTER_SIZE, Buffer1 + j * CRYPT_CLUSTER_SIZE, CRYPT_CLUSTER_SIZE);
            }


            if(NULL != EncryptContext) {
                if(CryptEncryptCluster(EncryptContext, Buffer2 + j * CRYPT_CLUSTER_SIZE, 
                    Buffer1 + j * CRYPT_CLUSTER_SIZE, i * ClusterCount + j) != CRYPT_OK) {
                    SetLastError(ERROR_INTERNAL_ERROR);
                    PrintLastError("ProcessFile:");
                    goto err;
                }
            } else {
                memcpy(Buffer1+ j * CRYPT_CLUSTER_SIZE, Buffer2 + j * CRYPT_CLUSTER_SIZE, CRYPT_CLUSTER_SIZE);
            }

        }
        if(!SetFilePointerEx(hFile, Pos, NULL, FILE_BEGIN)) {
            PrintLastError("ProcessFile:");
            goto err;
        }

        if(!WriteFile(hFile, Buffer1, CRYPT_CLUSTER_SIZE * ClusterCount, &Junk, NULL)
            ||Junk != CRYPT_CLUSTER_SIZE * ClusterCount) {
            PrintLastError("ProcessFile:");
            goto err;
        }
        Pos.QuadPart += CRYPT_CLUSTER_SIZE * ClusterCount;
    }

    // small block: process cluster one by one
    if(ClusterCount != 1) {
        i = b * ClusterCount;
        b = n;
        ClusterCount = 1;
        goto again;
    }

    Process = 100.0;
    PrintMessage("\b\b\b\b\b\b%3.1f%%\n", Process);

    Ret = 0;

err:
    if(NULL  != Buffer1) {
        free(Buffer1);
        Buffer1 = NULL;
    }
    if(NULL  != Buffer2) {
        free(Buffer2);
        Buffer2 = NULL;
    }
    return Ret;

}
