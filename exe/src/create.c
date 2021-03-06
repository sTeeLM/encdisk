#include "control.h"
#include <Wincrypt.h>
static INT
GetRandSeq(VOID * out, SIZE_T outlen)
{
   HCRYPTPROV hProvider = 0;
   INT Ret = -1;

	if (!CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return Ret;


	if (!CryptGenRandom(hProvider, (DWORD)outlen, (BYTE*)out))
	{
		CryptReleaseContext(hProvider, 0);
		return Ret;
	}

	if (!CryptReleaseContext(hProvider, 0))
		return Ret;

    Ret = 0;
    return Ret;
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
        if(GetRandSeq(Buffer, BlockSize) != 0) {
            PrintLastError("EncDiskCreate:");
            goto err;
        }
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
