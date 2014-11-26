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

INT EncKeyPass(
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

#define ENC_DISK_DEFAULT_THREAD_CNT 4
#define ENC_DISK_MAX_THREAD_CNT (MAXIMUM_WAIT_OBJECTS - 1)

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

#define ENC_RESUME_FILE_SIGNATURE 0x11223344
#define ENC_CLUSTER_BLOCK_COUNT 64
#define ENC_SLOT_SIZE (ENC_CLUSTER_BLOCK_COUNT * CRYPT_CLUSTER_SIZE)
#define ENC_DEFAULT_THREAD_NUM 4

#pragma pack(push, r1, 1)
typedef struct _ENC_RESUME_HEADER
{
    DWORD Signature;
    UCHAR EncryptKeyID[16]; // all zero if none
    UCHAR DecryptKeyID[16];
    DWORD SlotCnt;
    LARGE_INTEGER FileSize;
}ENC_RESUME_HEADER, *PENC_RESUME_HEADER;
#pragma pack(pop, r1)

#define ENC_RESUME_TAG_EMPTY 0
#define ENC_RESUME_TAG_PROCESSING 1
#define ENC_RESUME_TAG_DONE  2

#pragma pack(push, r1, 1)
typedef struct _ENC_RESUME_SLOT
{
    UCHAR Tag;
    UCHAR BigBlock;
    ULONGLONG From;
    ULONGLONG Index;
    ULONGLONG To;
    UCHAR Data[ENC_SLOT_SIZE];
}ENC_RESUME_SLOT, *PENC_RESUME_SLOT;
#pragma pack(pop, r1)

#pragma pack(push, r1, 1)
typedef struct _ENC_RESUME_FILE
{
    ENC_RESUME_HEADER Header;
    ENC_RESUME_SLOT ResumeSlot[ENC_DISK_MAX_THREAD_CNT];
}ENC_RESUME_FILE, *PENC_RESUME_FILE;
#pragma pack(pop, r1)

#endif
