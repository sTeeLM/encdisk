#include "control.h"

INT
EncDiskRekey(
    CHAR* FileName, 
    CHAR* OldPrivateKey, 
    CHAR* NewPrivateKey
)
{
    PCRYPT_CONTEXT ContextDecrypt = NULL;
    PCRYPT_CONTEXT ContextEncrypt = NULL;
    CHAR * PassDecrypt = NULL;
    CHAR * PassEncrypt = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER FileSize;
    INT Ret = -1;
    CHAR * Pass;

    if((PassDecrypt = AskPass(CHECK_PASS, "Enter the password for the decrypt key:", NULL)) == NULL)
        goto err;

    if((PassEncrypt = AskPass(CHECK_PASS, "Enter the password for the encrypt key:", NULL)) == NULL)
        goto err;

    if((ContextDecrypt = ReadKeyFile(OldPrivateKey, PassDecrypt)) == NULL) {
        goto err;
    }

    if((ContextEncrypt = ReadKeyFile(NewPrivateKey, PassEncrypt)) == NULL) {
        goto err;
    }

    // open file
    hFile = CreateFile(
        FileName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        );
    if(hFile == INVALID_HANDLE_VALUE) {
        PrintLastError("EncDiskRekey:");
        goto err;
    }

    if(!GetFileSizeEx(hFile, &FileSize)) {
        PrintLastError("EncDiskRekey:");
        goto err;
    }

    // file size should be n * CRYPT_CLUSTER_SIZE

    if(FileSize.QuadPart % CRYPT_CLUSTER_SIZE != 0) {
        PrintMessage("%s\n", "EncDiskRekey: invalid disk image");
        goto err;
    }

    if(ProcessFile(hFile, ContextDecrypt, ContextEncrypt)!= 0) {
        goto err;
    }
    
    Ret = 0;
    PrintMessage("%s\n", "EncDiskRekey: success!");
err:
    if(NULL != PassDecrypt) {
        free(PassDecrypt);
        PassDecrypt = NULL;
    }
    if(NULL != ContextDecrypt) {
        free(ContextDecrypt);
        ContextDecrypt = NULL;
    }
    if(NULL != PassEncrypt) {
        free(PassEncrypt);
        PassEncrypt = NULL;
    }
    if(NULL != ContextEncrypt) {
        free(ContextEncrypt);
        ContextEncrypt = NULL;
    }
    if(INVALID_HANDLE_VALUE != hFile) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return Ret;
}
