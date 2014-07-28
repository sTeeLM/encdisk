#include "control.h"

INT ProcessFile(HANDLE hFile, 
    PCRYPT_CONTEXT DecryptContext, 
    PCRYPT_CONTEXT EncryptContext)
{
    

    LARGE_INTEGER FileSize;
    LARGE_INTEGER Pos;
    ULONG  n, i;
    ULONG Index;
    LPBYTE Buffer1 = NULL;
    LPBYTE Buffer2 = NULL;
    DWORD Junk;
    INT Ret = -1;
    INT Process = 0;


    // alloc buffer
    if((Buffer1 = malloc(CRYPT_CLUSTER_SIZE)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ProcessFile:");
        goto err;
    }

    if((Buffer2 = malloc(CRYPT_CLUSTER_SIZE)) == NULL) {
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

    // process cluster one by one
    for(i = 0 ; i < n ; i ++) {
        Process = (INT)((Pos.QuadPart * 100) / FileSize.QuadPart);
        PrintMessage("\b\b\b\b\b%d%%", Process);
        if(!ReadFile(hFile, Buffer1, CRYPT_CLUSTER_SIZE, &Junk, NULL)
            || Junk != CRYPT_CLUSTER_SIZE) {
            PrintLastError("ProcessFile:");
            goto err;
        }
        
        if(NULL != DecryptContext) {
            if(CryptDecryptCluster(DecryptContext, Buffer1, Buffer2, i) != CRYPT_OK) {
                SetLastError(ERROR_INTERNAL_ERROR);
                PrintLastError("ProcessFile:");
                goto err;
            }
        } else {
            memcpy(Buffer2, Buffer1, CRYPT_CLUSTER_SIZE);
        }

        if(NULL != EncryptContext) {
            if(CryptEncryptCluster(EncryptContext, Buffer2, Buffer1, i) != CRYPT_OK) {
                SetLastError(ERROR_INTERNAL_ERROR);
                PrintLastError("ProcessFile:");
                goto err;
            }
        } else {
            memcpy(Buffer1, Buffer2, CRYPT_CLUSTER_SIZE);
        }

        if(!SetFilePointerEx(hFile, Pos, NULL, FILE_BEGIN)) {
            PrintLastError("ProcessFile:");
            goto err;
        }

        if(!WriteFile(hFile, Buffer1, CRYPT_CLUSTER_SIZE, &Junk, NULL)
            ||Junk != CRYPT_CLUSTER_SIZE) {
            PrintLastError("ProcessFile:");
            goto err;
        }
        Pos.QuadPart += CRYPT_CLUSTER_SIZE;
    }

    Process = 100;
    PrintMessage("\b\b\b\b\b%d%%\n", Process);

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
