#include "control.h"

static const CHAR * header = 
"------------------------------BEGIN ENC DISK KEY----------------------------";

static const CHAR * footer = 
"-------------------------------END ENC DISK KEY-----------------------------";

#define ENC_KEY_LINE_LENGTH 76

static LPBYTE
FormatKey(const LPBYTE src, SIZE_T s, SIZE_T * d)
{
    SIZE_T total, line, i, j, line_size;
    LPBYTE Ret = NULL;
    LPBYTE p = NULL;

    line_size = ENC_KEY_LINE_LENGTH;

    line = s / line_size + 1;
    total = strlen(header) + strlen(footer) + 4 + s + line * 2;

//    printf("FormatKey: input size is %d total size is %d\n", s, total);

    Ret = malloc(total);
    if(NULL == Ret) return Ret;

    p = Ret;
    memcpy(p, header, strlen(header));
    p += strlen(header);
    p[0] = '\r';
    p[1] = '\n';
    p+=2;
    
    j = 0;
    for(i = 0 ; i < s; i ++) {
        p[0] = src[i];
        p ++; j++;
        if(j == line_size) {
            j = 0;
            p[0] = '\r';
            p[1] = '\n';
            p+=2;
        }
    }
    p[0] = '\r';
    p[1] = '\n';
    p+=2;

    memcpy(p, footer, strlen(footer));
    p += strlen(footer);
    p[0] = '\r';
    p[1] = '\n';
    p+=2;

    *d = total;
    return Ret;
}

static LPBYTE
UnformatKey(LPBYTE src, SIZE_T s, SIZE_T * d)
{
    LPBYTE Ret = NULL;
    LPBYTE p = src;
    SIZE_T i;

    if(s < strlen(header) + strlen(footer)) return NULL;

    Ret = malloc(s);
    if(NULL == Ret) return NULL;
    
    i = 0;
    while(s > 0) {
        if(!memcmp(p, header, strlen(header))) {
            p += strlen(header);
            s -= strlen(header);
        } 
        else if(!memcmp(p, footer, strlen(footer)))
        {
            p += strlen(footer);
            s -= strlen(footer);
        }
        else if(p[0] == '\r' || p[0] == '\n'|| p[0] == '\t' || p[0] == ' ') {
            p++;
            s--;
        }
        else {
            Ret[i] = *p;
            p ++; i ++; s--;
        }
    }

    *d = i;
    return Ret;
}

PCRYPT_CONTEXT ReadKeyFile(
    const CHAR * FileName,
    const CHAR * Pass
)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PCRYPT_CONTEXT KeyBuffer = NULL;
    LPBYTE Buffer = NULL;
    LPBYTE UnformatBuffer = NULL;
    LARGE_INTEGER Size;
    ULONG Junk;
    SIZE_T NewSize;

    // alloc buffer
    if((KeyBuffer = malloc(sizeof(CRYPT_CONTEXT))) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ReadKeyFile:");
        goto err;
    }

    // open file
    if((hFile = CreateFile(
        FileName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ| FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        )) == INVALID_HANDLE_VALUE) {
        PrintLastError("ReadKeyFile:");
        goto err;
    }

    // get file size
    if(!GetFileSizeEx(hFile, &Size)) {
        PrintLastError("ReadKeyFile:");
        goto err;
    }

    if(Size.QuadPart == 0 || Size.HighPart != 0) {
        PrintMessage("ReadKeyFile: invalid key file %s\n", FileName);
        goto err;
    }

    // alloc buffer
    if((Buffer = malloc(Size.LowPart)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ReadKeyFile:");
        goto err;
    }

    // Read file
    if(!ReadFile(hFile, Buffer, Size.LowPart, &Junk, NULL) ||
        Junk != Size.LowPart) {
        PrintLastError("ReadKeyFile:");
        free(KeyBuffer);
        KeyBuffer = NULL;
        goto err;
    }

    if((UnformatBuffer = UnformatKey(Buffer, Size.LowPart, &NewSize)) == NULL) {
        free(KeyBuffer);
        KeyBuffer = NULL;
        PrintMessage("%s\n", "ReadKeyFile: %s invalid key file or invalid password", FileName);
        goto err;
    }

    // decode it!
    if(CryptDecodeKey(UnformatBuffer, &KeyBuffer->key, Pass, (ULONG)NewSize) != CRYPT_OK) {
        free(KeyBuffer);
        KeyBuffer = NULL;
        PrintMessage("%s\n", "ReadKeyFile: %s invalid key file or invalid password", FileName);
        goto err;
    }

    if(CryptRestoreContext(KeyBuffer) != CRYPT_OK) {
        free(KeyBuffer);
        KeyBuffer = NULL;
        SetLastError(ERROR_INTERNAL_ERROR);
        PrintLastError("ReadKeyFile:");
        goto err;
    }

err:
    if(NULL != Buffer) {
        free(Buffer);
        Buffer = NULL;
    }
    if(NULL != UnformatBuffer) {
        free(UnformatBuffer);
        UnformatBuffer = NULL;
    }
    if(hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return KeyBuffer;
}

INT WriteKeyFile(
    PCRYPT_KEY Key,
    const CHAR * FileName,
    const CHAR * Pass
)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    INT Ret = -1;
    PCRYPT_KEY KeyBuffer = NULL;
    LPBYTE Buffer = NULL;
    LPBYTE FormatBuffer = NULL;
    ULONG Size = 0;
    ULONG Junk;
    SIZE_T NewSize;
    
    // alloc buffer
    if((KeyBuffer = malloc(sizeof(CRYPT_KEY))) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("WriteKeyFile:");
        goto err;
    }
    
    // get encode buffer size
    if(CryptEncodeKey(Key, KeyBuffer, Buffer, Pass, &Size) != CRYPT_BUFFER_OVERFLOW) {
        SetLastError(ERROR_INTERNAL_ERROR);
        PrintLastError("WriteKeyFile:");
        goto err;
    }

    // alloc buffer
    if((Buffer = malloc(Size)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("WriteKeyFile:");
        goto err;
    }

    if(CryptEncodeKey(Key, KeyBuffer, Buffer, Pass, &Size) != CRYPT_OK) {
        SetLastError(ERROR_INTERNAL_ERROR);
        PrintLastError("WriteKeyFile:");
        goto err;
    }

    if((FormatBuffer = FormatKey(Buffer, Size, &NewSize)) == NULL) {
        goto err;
    }

    // open file
    if((hFile = CreateFile(
        FileName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ| FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        0,
        NULL
        )) == INVALID_HANDLE_VALUE) {
        PrintLastError("WriteKeyFile:");
        goto err;
    }

    if(!SetEndOfFile(hFile)) {
        PrintLastError("WriteKeyFile:");
        goto err;
    }

    // write file
    if(!WriteFile(hFile, FormatBuffer, (ULONG)NewSize, &Junk, NULL) ||
        Junk != NewSize) {
        PrintLastError("WriteKeyFile:");
        goto err;
    }

    Ret = 0;
err:

    if(hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if(NULL != KeyBuffer) {
        free(KeyBuffer);
        KeyBuffer = NULL;
    }
    if(NULL != Buffer) {
        free(Buffer);
        Buffer = NULL;
    }
    if(NULL != FormatBuffer) {
        free(FormatBuffer);
        FormatBuffer = NULL;
    }
    return Ret;
}
