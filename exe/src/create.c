#include "control.h"

static VOID
GetRandSeq(VOID * out, SIZE_T outlen)
{
   ULONG x, n, r, i;
   ULONG * p;
   UCHAR * p1;

   p = (ULONG *)out;
   n = (ULONG)(outlen / sizeof(ULONG));
   r = (ULONG)(outlen % sizeof(ULONG));

   for( i = 0 ; i < n ; i ++) {
        x = XRAND();
        *p = x;
        p ++;
   }
   p1 = (UCHAR *)p;

   for( i = 0 ; i < r; i ++) {
        x = XRAND();
        *p1 = (UCHAR)x;
        p1 ++;
   }
}

static BOOL
RandFile(HANDLE hFile, LARGE_INTEGER Size)
{
    BOOL Ret = FALSE;
    ULONG BlockSize = CRYPT_CLUSTER_SIZE;
    ULONG n,r,i, Junk;
    LPBYTE Buffer = NULL;
    INT Process;

    n = (ULONG)(Size.QuadPart / BlockSize);
    r = (ULONG)(Size.QuadPart % BlockSize);

    if((Buffer = malloc(BlockSize)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("EncDiskCreate:");
        goto err;
    }

    for(i = 0; i < n ; i ++) {
        Process = (INT)((i * (LONGLONG)BlockSize * 100UL)/ Size.QuadPart);
        PrintMessage("\b\b\b\b\b%d%%", Process);
        GetRandSeq(Buffer, BlockSize);
        if(!WriteFile(hFile, Buffer, BlockSize, &Junk, NULL)
            ||Junk != BlockSize) {
            PrintLastError("EncDiskCreate:");
            goto err;
        }
    }

    GetRandSeq(Buffer, BlockSize);

    if(!WriteFile(hFile, Buffer, r, &Junk, NULL)
        ||Junk != r) {
        PrintLastError("EncDiskCreate:");
        goto err;
    }
    Process = 100;
    PrintMessage("\b\b\b\b\b%d%%\n", Process);
    Ret = TRUE;

err:
    if(NULL != Buffer) {
        free(Buffer);
        Buffer = NULL;
    }
    return Ret;
}

INT 
EncDiskCreate(
    CHAR* FileName, 
    LARGE_INTEGER RealFileSize
)
{
    CHAR * Pass = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    INT Ret = -1;
    
    // create an empty sparse file
    hFile = CreateFile(
        FileName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_NEW,
        0,
        NULL
        );
    if(hFile == INVALID_HANDLE_VALUE) {
        PrintLastError("EncDiskCreate:");
        goto err;
    }

    if(!RandFile(hFile, RealFileSize)) {
        goto err;
    }
    
    if(!SetFilePointerEx(
            hFile,
            RealFileSize,
            NULL,
            FILE_BEGIN)) {
        PrintLastError("EncDiskCreate:");
        goto err;
    }

    if(!SetEndOfFile(hFile)) {
        PrintLastError("EncDiskCreate:");
        goto err;
    }

    PrintMessage("%s\n", "EncDiskCreate: success!");

    Ret = 0;

err:
    if(hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return Ret;
}
