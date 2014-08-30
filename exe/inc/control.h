#ifndef __END_CONTROL_H__
#define __END_CONTROL_H__

#include <windows.h>
#include <winioctl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <shlobj.h>

#include "common.h"
#include "encdisk_version.h"
#include "crypt.h"

#define ENC_MAX_DEVICE_CNT 512

void PrintLastError(const CHAR* Prefix);

void PrintMessage(const CHAR* fmt, ...);

INT GetWideLength(const CHAR * src);

INT AsciiToWide(const CHAR * src, WCHAR * dst, SIZE_T dst_len);

INT WideToAscii(const WCHAR * src, CHAR * dst, SIZE_T dst_len);

BOOL GetDeviceNumber(const CHAR * arg, PDEVICE_NUMBER DeviceNumber);

INT EncDiskList();

INT DumpDiskInfo(HANDLE Device, PDEVICE_NUMBER DeviceNumber, BOOL Detail);

HANDLE EncOpenDevice(
);

INT EncCallSrb(
    HANDLE Device, 
    PSRB_IO_CONTROL SrbData, 
    DWORD SrbDataLen, 
    DWORD *Error
);

PCRYPT_CONTEXT ReadKeyFile(
    const CHAR * FileName,
    const CHAR * Pass
);

void DumpKey(
    PCRYPT_KEY key
);

INT EncKeyInfo(
    const CHAR * PrivateKey
);

INT EncDiskEncrypt(
    const CHAR * FileName, 
    const CHAR * PrivateKey,
    INT ThreadNum
);

INT EncDiskDecrypt(
    const CHAR * FileName, 
    const CHAR * PrivateKey,
    INT ThreadNum
);

#define ENC_DEFAULT_THREAD_NUM 4
INT ProcessFile(
    const CHAR * FileName, 
    PCRYPT_CONTEXT DecryptContext, 
    PCRYPT_CONTEXT EncryptContext,
    ULONG ThreadNum
);

INT WriteKeyFile(
    PCRYPT_KEY Key,
    const CHAR * FileName,
    const CHAR * Pass
);

INT EncDiskNewKey(
    const CHAR * PrivateKey, 
    INT HardLevel
);

#define ASK_NEW_PASS 0
#define CHECK_PASS   1
#define MAX_PASS_LEN 4096
CHAR * AskPass(INT Type, const CHAR * Prompt1, const CHAR * Prompt2);

INT
EncDiskRekey(
    CHAR* FileName, 
    CHAR* OldPrivateKey, 
    CHAR* NewPrivateKey,
    INT ThreadNum
);

INT 
EncDiskCreate(
    CHAR* FileName, 
    LARGE_INTEGER RealFileSize
);

INT
EncDiskMount(
    const CHAR* FileName,
    const CHAR* PrivateKey,
    BOOL        RO
);

INT EncDiskUmount(PDEVICE_NUMBER DeviceNumber);

INT EncDiskStatus(PDEVICE_NUMBER DeviceNumber);

BOOL RandInitialize();

#endif
