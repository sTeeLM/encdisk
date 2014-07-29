#include "control.h"

INT EncDiskDecrypt(const CHAR * FileName, const CHAR * PrivateKey, INT ThreadNum)
{
    PCRYPT_CONTEXT Context = NULL;
    CHAR * Pass = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER FileSize;
    INT Ret = -1;

    if((Pass = AskPass(CHECK_PASS, "Enter the password for the key:", NULL)) == NULL)
        goto err;

    if((Context = ReadKeyFile(PrivateKey, Pass)) == NULL) {
        goto err;
    }

    // open file
    hFile = CreateFile(
        FileName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        );
    if(hFile == INVALID_HANDLE_VALUE) {
        PrintLastError("EncDiskDecrypt:");
        goto err;
    }

    if(!GetFileSizeEx(hFile, &FileSize)) {
        PrintLastError("EncDiskDecrypt:");
        goto err;
    }
    
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;
    // file size should be n * CRYPT_CLUSTER_SIZE

    if(FileSize.QuadPart % CRYPT_CLUSTER_SIZE != 0) {
        PrintMessage("%s\n", "EncDiskDecrypt: invalid disk image");
        goto err;
    }

    if(ProcessFile(FileName, Context, NULL, ThreadNum)!= 0) {
        goto err;
    }
    
    Ret = 0;
    PrintMessage("%s\n", "EncDiskDecrypt: success!");
err:
    if(NULL != Pass) {
        free(Pass);
        Pass = NULL;
    }
    if(NULL != Context) {
        free(Context);
        Context = NULL;
    }
    if(INVALID_HANDLE_VALUE != hFile) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return Ret;
}
