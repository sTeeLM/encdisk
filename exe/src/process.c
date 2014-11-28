#include "control.h"
#include <stdio.h>
#include <time.h> 
#include <sys/timeb.h>
#include <string.h>


static ULONGLONG DoCount, LastDoCount;
static LONG QuitThreadCnt;

typedef struct _ENC_PROCESS_ARG
{
    CHAR * FileName;
    PCRYPT_CONTEXT DecryptContext;
    PCRYPT_CONTEXT EncryptContext;
    HANDLE hThread;
    DWORD  ThreadID;
    HANDLE hResumeFile;
    ENC_RESUME_SLOT Resume;
    ULONG ThreadIndex;
}ENC_PROCESS_ARG, *PENC_PROCESS_ARG;


static const CHAR * GetETA(time_t begin, ULONGLONG DoCount, ULONGLONG ToTal)
{
    time_t current;
    time_t finish, diff;

    current = time(NULL);
    diff = current - begin;
    if(DoCount == LastDoCount)
        finish = (time_t)((ToTal * diff / (DoCount - LastDoCount + 1)) + begin);
    else
        finish = (time_t)((ToTal * diff / (DoCount - LastDoCount)) + begin);
    return ctime(&finish);
}

static ULONG
CalcuteSubSlotCrc(PENC_RESUME_SLOT_BODY SlotBody)
{
    LPBYTE p = (LPBYTE)SlotBody;
    hash_state state;
    ULONG size = sizeof(ENC_RESUME_SLOT_BODY);
    ULONG ret;

    p += sizeof(SlotBody->CRC);
    size -= sizeof(SlotBody->CRC);
    if(!SlotBody->BigBlock) {
        size -= (ENC_CLUSTER_BLOCK_COUNT - 1) * CRYPT_CLUSTER_SIZE;
    }
    crc32_init(&state);
    crc32_process(&state, p, size);
    crc32_done(&state, (UCHAR *)&ret);
    return ret;
}

static INT SaveResumeBlock(PENC_RESUME_SLOT Slot, HANDLE hResumeFile, ULONG ThreadIndex, ULONGLONG ClusterIndex, 
            ULONGLONG Size, LPVOID Data)
{
    LARGE_INTEGER Pos;
    DWORD Junk;

    Pos.QuadPart = sizeof(ENC_RESUME_HEADER) + ThreadIndex * sizeof(ENC_RESUME_SLOT);
    Pos.QuadPart += sizeof(ENC_RESUME_SLOT_HEADER) + Slot->Header.SubSlotIndex * sizeof(ENC_RESUME_SLOT_BODY);

    Slot->Body[Slot->Header.SubSlotIndex].NotEmpty = 1;
    Slot->Body[Slot->Header.SubSlotIndex].BigBlock = Size == ENC_SLOT_BUFFER_SIZE ? 1 : 0;
    Slot->Body[Slot->Header.SubSlotIndex].Index = ClusterIndex;

    memcpy(Slot->Body[Slot->Header.SubSlotIndex].Data, Data, (size_t)Size);
    Slot->Body[Slot->Header.SubSlotIndex].CRC = CalcuteSubSlotCrc(&Slot->Body[Slot->Header.SubSlotIndex]);
    
    if(!SetFilePointerEx(hResumeFile, Pos, NULL, FILE_BEGIN)) {
        return -1;
    }
    if(!WriteFile(hResumeFile, &Slot->Body[Slot->Header.SubSlotIndex], sizeof(ENC_RESUME_SLOT_BODY), &Junk, NULL) 
        || Junk != sizeof(ENC_RESUME_SLOT_BODY)) {
        return -1;
    }
    if(!FlushFileBuffers(hResumeFile)) {
        return -1;
    }
    Slot->Header.SubSlotIndex = (Slot->Header.SubSlotIndex + 1) % ENC_RESUME_HISTORY_DEEP;

    return 0;
}

static INT FixImageFile(
    HANDLE hFile, 
    PENC_RESUME_FILE Resume, 
    PCRYPT_CONTEXT DecryptContext,
    PCRYPT_CONTEXT EncryptContext )
{
    DWORD i;
    LARGE_INTEGER Begin;
    DWORD Junk;
    LPBYTE Buffer1 = NULL;
    LPBYTE Buffer2 = NULL;
    ULONGLONG ClusterCount = ENC_CLUSTER_BLOCK_COUNT;
    ULONGLONG j;
    INT nRet = -1;

    for(i = 0 ; i < Resume->Header.SlotCnt; i ++) {
        if(Resume->Slot[i].Header.Tag == ENC_RESUME_SLOT_TAG_EMPTY) {
            PrintMessage("Slot %d: do nothing\n", i);
            // do nothing
        } else if(Resume->Slot[i].Header.Tag == ENC_RESUME_SLOT_TAG_GOOD) {
            PrintMessage("Slot %d: process one step %I64u -> %I64u\n", 
                i,
                Resume->Slot[i].Header.Index,
                Resume->Slot[i].Body[Resume->Slot[i].Header.SubSlotIndex].BigBlock ?
                    (Resume->Slot[i].Header.Index + ENC_CLUSTER_BLOCK_COUNT) :
                    (Resume->Slot[i].Header.Index + 1)
                );
            ClusterCount = Resume->Slot[i].Body[Resume->Slot[i].Header.SubSlotIndex].BigBlock ?
                ENC_CLUSTER_BLOCK_COUNT : 1;

            Begin.QuadPart = Resume->Slot[i].Header.Index * CRYPT_CLUSTER_SIZE;
            if(!SetFilePointerEx(hFile, Begin, NULL, FILE_BEGIN)) {
                PrintLastError("FixImageFile:");
                goto err;
            }

            if((Buffer2 = malloc((size_t)(CRYPT_CLUSTER_SIZE * ClusterCount))) == NULL) {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                PrintLastError("FixImageFile:");
                goto err;
            }

            

            Buffer1 = (LPBYTE)(Resume->Slot[i].Body[Resume->Slot[i].Header.SubSlotIndex].Data);

            for(j = 0 ; j < ClusterCount; j ++) {
                if(NULL != DecryptContext) {
                    if(CryptDecryptCluster(DecryptContext, Buffer1 + j * CRYPT_CLUSTER_SIZE,
                        Buffer2 + j * CRYPT_CLUSTER_SIZE, Resume->Slot[i].Header.Index + j) != CRYPT_OK) {
                        goto err;
                    }
                } else {
                    memcpy(Buffer2 + j * CRYPT_CLUSTER_SIZE, Buffer1 + j * CRYPT_CLUSTER_SIZE, CRYPT_CLUSTER_SIZE);
                }
                if(NULL != EncryptContext) {
                    if(CryptEncryptCluster(EncryptContext, Buffer2 + j * CRYPT_CLUSTER_SIZE, 
                        Buffer1 + j * CRYPT_CLUSTER_SIZE, Resume->Slot[i].Header.Index + j) != CRYPT_OK) {
                        goto err;
                    }
                } else {
                    memcpy(Buffer1 + j * CRYPT_CLUSTER_SIZE, Buffer2 + j * CRYPT_CLUSTER_SIZE, CRYPT_CLUSTER_SIZE);
                }
            }
            
            if(!WriteFile(hFile, Buffer1, (DWORD)(CRYPT_CLUSTER_SIZE * ClusterCount), &Junk, NULL)
                ||Junk != CRYPT_CLUSTER_SIZE * ClusterCount) {
                PrintLastError("FixImageFile:");
                goto err;
            }
            if(!FlushFileBuffers(hFile)) {
                PrintLastError("FixImageFile:");
                goto err;
            }

            

            DoCount += (Resume->Slot[i].Header.Index - Resume->Slot[i].Header.From);

            Resume->Slot[i].Header.Index += Resume->Slot[i].Body[Resume->Slot[i].Header.SubSlotIndex].BigBlock ?
                ENC_CLUSTER_BLOCK_COUNT : 1;
            Resume->Slot[i].Header.SubSlotIndex = (Resume->Slot[i].Header.SubSlotIndex + 1) % ENC_RESUME_HISTORY_DEEP;

        }
        
    }
    nRet = 0;

err:
    if(NULL != Buffer2) {
        free(Buffer2);
        Buffer2 = NULL;
    }
    return nRet;
}

static const UCHAR NULL_KEY_ID[CRYPT_KEY_SIGNATURE_SIZE] = {0};

// check resume file
// 1. no such file: create one
// 2. has one: check ThreadNum, FileSize, DecryptContext, EncryptContext
// 
static PENC_RESUME_FILE LoadResumeFile(
    const CHAR * FileName, 
    ULONG ThreadNum, 
    LARGE_INTEGER FileSize, 
    PCRYPT_CONTEXT DecryptContext, 
    PCRYPT_CONTEXT EncryptContext)
{
    HANDLE hResumeFile = INVALID_HANDLE_VALUE;
    CHAR ResumeFile[MAX_PATH];
    ULONG ResumeFileSize;
    BOOL bIsNew = FALSE;
    ULONGLONG Cluster;
    ULONG ThreadCnt = 0;
    PENC_RESUME_FILE Resume;
    INT nRet = -1;
    DWORD JunkBytes;
    ULONG i;
    ULONGLONG From[ENC_DISK_MAX_THREAD_CNT] = {0};
    ULONGLONG To[ENC_DISK_MAX_THREAD_CNT] = {0};


   
    // calc slot cnt, from, to
    Cluster = (FileSize.QuadPart / CRYPT_CLUSTER_SIZE / ThreadNum);
    if(Cluster != 0) {
        for(i = 0; i < ThreadNum; i ++) {
            From[i] = i * Cluster;
            To[i] = (i+1) * Cluster - 1;
        }
    }
    if(Cluster * ThreadNum != FileSize.QuadPart / CRYPT_CLUSTER_SIZE) {
        From[i] = i * Cluster;
        To[i] = FileSize.QuadPart / CRYPT_CLUSTER_SIZE - 1;
        i ++;
    }
    ThreadCnt = i;

    ResumeFileSize = sizeof(ENC_RESUME_HEADER) + ThreadCnt * sizeof(ENC_RESUME_SLOT);
    if((Resume = malloc(ResumeFileSize)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("LoadResumeFile:");
        goto err;
    }

    // create file name
    _snprintf(ResumeFile, sizeof(ResumeFile), "%s"ENC_DISK_RESUME_FILE_SURFIX, FileName);

    // open data file
    hResumeFile = CreateFile(
        ResumeFile,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        );
    if(hResumeFile == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND) {
        PrintLastError("LoadResumeFile:");
        goto err;
    }

    if(hResumeFile == INVALID_HANDLE_VALUE) {
        hResumeFile = CreateFile(
            ResumeFile,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            CREATE_NEW,
            0,
            NULL
            );
        if(hResumeFile == INVALID_HANDLE_VALUE) {
            PrintLastError("LoadResumeFile:");
            goto err;
        }
        bIsNew = TRUE;
    }

    if(bIsNew) { // create one
        PrintMessage("Resume file (%s) not found, create new one.\n", ResumeFile);
        memset(Resume, 0, ResumeFileSize);
        Resume->Header.Signature = ENC_RESUME_FILE_SIGNATURE;
        if(NULL != DecryptContext) {
            memcpy(Resume->Header.DecryptKeyID, DecryptContext->key.signature, sizeof(Resume->Header.DecryptKeyID));
        }
        if(NULL != EncryptContext) {
            memcpy(Resume->Header.EncryptKeyID, EncryptContext->key.signature, sizeof(Resume->Header.EncryptKeyID));
        }
        Resume->Header.SlotCnt = ThreadCnt;
        Resume->Header.FileSize = FileSize;
        for(i = 0 ; i < Resume->Header.SlotCnt; i ++) {
            Resume->Slot[i].Header.From = From[i];
            Resume->Slot[i].Header.To = To[i];
            Resume->Slot[i].Header.Index = From[i];
            Resume->Slot[i].Header.SubSlotIndex = 0;
            Resume->Slot[i].Header.Tag = ENC_RESUME_SLOT_TAG_EMPTY;
        }

        if(!WriteFile(hResumeFile, Resume, ResumeFileSize, &JunkBytes, NULL) || 
            JunkBytes != ResumeFileSize) {
            PrintLastError("LoadResumeFile:");
            goto err;
        }

        nRet = 0;

    } else { // check 
        LARGE_INTEGER RealResumeFileSize;
        INT j;

        PrintMessage("Resume file (%s) found.\n", ResumeFile);

        // get real file size
        if(!GetFileSizeEx(hResumeFile, &RealResumeFileSize)) {
            PrintLastError("LoadResumeFile:");
            goto err;
        }

        if(RealResumeFileSize.QuadPart < sizeof(ENC_RESUME_HEADER)) {
            PrintMessage("LoadResumeFile: file size too small < %d\n", sizeof(ENC_RESUME_HEADER));
            goto err;
        }

        if(!ReadFile(hResumeFile, Resume, (DWORD)RealResumeFileSize.QuadPart, &JunkBytes, NULL) || 
            JunkBytes != RealResumeFileSize.QuadPart) {
            PrintLastError("LoadResumeFile:");
            goto err;
        }

        if(Resume->Header.Signature != ENC_RESUME_FILE_SIGNATURE) {
            PrintMessage("LoadResumeFile: Invalid signature\n");
            goto err;
        }
        if(Resume->Header.SlotCnt != ThreadCnt) {
            PrintMessage("LoadResumeFile: Invalid thread cnt %d, should be %d\n", Resume->Header.SlotCnt, ThreadCnt);
            goto err;
        }

        if(Resume->Header.FileSize.QuadPart != FileSize.QuadPart) {
            PrintMessage("LoadResumeFile: Invalid data file size %I64u, should be %I64u\n", 
                Resume->Header.FileSize.QuadPart, FileSize.QuadPart);
            goto err;
        }

        if(RealResumeFileSize.QuadPart != ResumeFileSize) {
            PrintMessage("LoadResumeFile: file size %I64u miss match %d\n", RealResumeFileSize.QuadPart, ResumeFileSize);
            goto err;
        }
        
        if(NULL != DecryptContext) {
            if(memcmp(Resume->Header.DecryptKeyID, DecryptContext->key.signature, sizeof(Resume->Header.DecryptKeyID)) != 0) {
                PrintMessage("LoadResumeFile: Invalid decrypt context\n");
                goto err;
            }
        } else if(memcmp(Resume->Header.DecryptKeyID, NULL_KEY_ID, sizeof(Resume->Header.DecryptKeyID)) != 0) {
            PrintMessage("LoadResumeFile: Invalid decrypt context\n");
            goto err;
        }

        if(NULL != EncryptContext) {
            if(memcmp(Resume->Header.EncryptKeyID, EncryptContext->key.signature, sizeof(Resume->Header.EncryptKeyID)) != 0) {
                PrintMessage("LoadResumeFile: Invalid encrypt context\n");
                goto err;
            }
        } else if(memcmp(Resume->Header.EncryptKeyID, NULL_KEY_ID, sizeof(Resume->Header.EncryptKeyID)) != 0) {
            PrintMessage("LoadResumeFile: Invalid encrypt context\n");
            goto err;
        }

        for(i = 0 ; i < Resume->Header.SlotCnt; i ++) {
            ULONGLONG RealIndex = 0L;
            CHAR RealSubSlotIndex = -1;
            CHAR FirstBadSubSlotIndex = -1;
            UCHAR EmptySubSlotCnt = 0;
            UCHAR BadSubSlotCnt = 0;
            UCHAR GoodSubSlotCnt = 0;

            PrintMessage("Slot %d: [%I64u -> %I64u] :\n", i, Resume->Slot[i].Header.From, Resume->Slot[i].Header.To);

            // check from to
            if(Resume->Slot[i].Header.From != From[i]) {
                PrintMessage("LoadResumeFile: Invalid begin offset %I64u, should be %I64u\n", Resume->Slot[i].Header.From, From[i]);
                goto err;
            }
            if(Resume->Slot[i].Header.To != To[i]) {
                PrintMessage("LoadResumeFile: Invalid end offset %I64u, should be %I64u\n", Resume->Slot[i].Header.To, To[i]);
                goto err;
            }

            // find valid sub slot
            for(j = 0 ; j < ENC_RESUME_HISTORY_DEEP; j ++) {
                ULONG CRC;
                CRC = CalcuteSubSlotCrc(&Resume->Slot[i].Body[j]);
                PrintMessage("  Sub Slot: [%08x(%08x) | %d | %d | %I64u]\n", 
                    Resume->Slot[i].Body[j].CRC, 
                    CRC,
                    Resume->Slot[i].Body[j].NotEmpty, 
                    Resume->Slot[i].Body[j].BigBlock, 
                    Resume->Slot[i].Body[j].Index);

                if(Resume->Slot[i].Body[j].NotEmpty) {
                    if(CRC != Resume->Slot[i].Body[j].CRC) {
                        BadSubSlotCnt ++;
                        if(FirstBadSubSlotIndex != -1) {
                            FirstBadSubSlotIndex = (CHAR)j;
                        }
                    } else {
                        // find bigest index of good slot
                        GoodSubSlotCnt ++;
                        if(Resume->Slot[i].Body[j].Index >= RealIndex) {
                            RealSubSlotIndex = (CHAR)j;
                            RealIndex = Resume->Slot[i].Body[j].Index;
                        }
                        // check Index
                        if(RealIndex < From[i] || RealIndex > To[i] 
                            || (Resume->Slot[i].Body[j].BigBlock == 1 && (RealIndex + ENC_CLUSTER_BLOCK_COUNT - 1) > To[i] )) {
                            PrintMessage("LoadResumeFile: Invalid index %I64u\n", RealIndex);
                            goto err;
                        }
                    }
                } else {
                    EmptySubSlotCnt ++;
                }
            }
            if(EmptySubSlotCnt == ENC_RESUME_HISTORY_DEEP || 
                (BadSubSlotCnt == 1 
                && GoodSubSlotCnt == 0 
                && EmptySubSlotCnt == (ENC_RESUME_HISTORY_DEEP - BadSubSlotCnt)
                && FirstBadSubSlotIndex == 0)) {
                Resume->Slot[i].Header.Tag = ENC_RESUME_SLOT_TAG_EMPTY;
                PrintMessage("Slot %d empty\n", i);
            } else if(GoodSubSlotCnt != 0) {
                Resume->Slot[i].Header.Tag = ENC_RESUME_SLOT_TAG_GOOD;
                Resume->Slot[i].Header.SubSlotIndex = RealSubSlotIndex;
                Resume->Slot[i].Header.Index = RealIndex;
                PrintMessage("Slot %d good, Index is %I64u, from sub slot %d\n", i, RealIndex, RealSubSlotIndex);
            } else {
                PrintMessage("Slot %d bad\n", i);
                goto err;
            }
            
        }
        nRet = 0;
    }

err:

    if(hResumeFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hResumeFile);
        hResumeFile = INVALID_HANDLE_VALUE;
    }
    if(nRet != 0) {
        if(NULL != Resume) {
            free(Resume);
            Resume = NULL;
        }
    }
    return Resume;
}

static VOID DeleteResumeFile(const CHAR * FileName)
{
    CHAR ResumeFile[MAX_PATH];
    _snprintf(ResumeFile, sizeof(ResumeFile), "%s"ENC_DISK_RESUME_FILE_SURFIX, FileName);
    DeleteFile(ResumeFile);
}

static DWORD WINAPI ProcessWorker(LPVOID Param)
{
    PENC_PROCESS_ARG P = (PENC_PROCESS_ARG) Param;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONGLONG ClusterCount = ENC_CLUSTER_BLOCK_COUNT;
    LPBYTE Buffer1 = NULL;
    LPBYTE Buffer2 = NULL;
    LARGE_INTEGER Pos, Begin;
    DWORD Junk;
    ULONGLONG b, n, i = 0, j = 0;
    DWORD Ret = 1;
    ULONGLONG Start;

    if(P->Resume.Header.Index > P->Resume.Header.To) {
        Ret = 0;
        goto err;
    }

    if((Buffer1 = malloc((size_t)(CRYPT_CLUSTER_SIZE * ClusterCount))) == NULL) {
        goto err;
    }

    if((Buffer2 = malloc((size_t)(CRYPT_CLUSTER_SIZE * ClusterCount))) == NULL) {
        goto err;
    }

    
    hFile = CreateFile(
        P->FileName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        );
    if(hFile == INVALID_HANDLE_VALUE) {
        PrintLastError("ProcessFile:");
        goto err;
    }

    Start = P->Resume.Header.Index;
    Begin.QuadPart = Start * CRYPT_CLUSTER_SIZE;
    Pos.QuadPart = Begin.QuadPart;
    b = (P->Resume.Header.To - Start + 1) / ClusterCount; /* how many big block? */
    i = 0;

    if(!SetFilePointerEx(hFile, Begin, NULL, FILE_BEGIN)) {
        PrintLastError("ProcessFile:");
        goto err;
    }

again:
    // big block: process big block
    for(; i < b ; i ++) {
        if(!ReadFile(hFile, Buffer1, (DWORD)(CRYPT_CLUSTER_SIZE * ClusterCount), &Junk, NULL)
            || Junk != CRYPT_CLUSTER_SIZE * ClusterCount) {
            PrintLastError("ProcessFile:");
            goto err;
        }

        if(SaveResumeBlock(&P->Resume, P->hResumeFile, P->ThreadIndex, Start + i * ClusterCount, 
            CRYPT_CLUSTER_SIZE * ClusterCount, Buffer1) != 0) {
            PrintLastError("ProcessFile:");
            goto err;
        }

        for(j = 0 ; j < ClusterCount; j ++) {
            InterlockedIncrement64(&DoCount);
            if(NULL != P->DecryptContext) {
                if(CryptDecryptCluster(P->DecryptContext, Buffer1 + j * CRYPT_CLUSTER_SIZE,
                    Buffer2 + j * CRYPT_CLUSTER_SIZE, Start + i * ClusterCount + j) != CRYPT_OK) {
                    goto err;
                }
            } else {
                memcpy(Buffer2 + j * CRYPT_CLUSTER_SIZE, Buffer1 + j * CRYPT_CLUSTER_SIZE, CRYPT_CLUSTER_SIZE);
            }


            if(NULL != P->EncryptContext) {
                if(CryptEncryptCluster(P->EncryptContext, Buffer2 + j * CRYPT_CLUSTER_SIZE, 
                    Buffer1 + j * CRYPT_CLUSTER_SIZE, Start + i * ClusterCount + j) != CRYPT_OK) {
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

        if(!WriteFile(hFile, Buffer1, (DWORD)(CRYPT_CLUSTER_SIZE * ClusterCount), &Junk, NULL)
            ||Junk != CRYPT_CLUSTER_SIZE * ClusterCount) {
            PrintLastError("ProcessFile:");
            goto err;
        }
        if(!FlushFileBuffers(hFile)) {
            PrintLastError("ProcessFile:");
            goto err;
        }        

        Pos.QuadPart += CRYPT_CLUSTER_SIZE * ClusterCount;
    }

    // small block: process cluster one by one
    if(ClusterCount != 1) {
        i = b * ClusterCount;
        b = P->Resume.Header.To - Start + 1;
        ClusterCount = 1;
        goto again;
    }
    InterlockedIncrement(&QuitThreadCnt);
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
    if(INVALID_HANDLE_VALUE != hFile) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return Ret;
}


static PENC_PROCESS_ARG ProcessFileBlock(
    ULONG ThreadIndex,
    const CHAR * FileName,
    PCRYPT_CONTEXT DecryptContext,
    PCRYPT_CONTEXT EncryptContext,
    PENC_RESUME_SLOT Slot
    )
{
    PENC_PROCESS_ARG Arg = NULL;
    INT Ret = -1;
    CHAR ResumeFile[MAX_PATH];
    DWORD JunkBytes;
   
    if((Arg = malloc(sizeof(ENC_PROCESS_ARG))) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ProcessFile:");
        goto err;
    }

    memset(Arg, 0, sizeof(ENC_PROCESS_ARG));
    Arg->hResumeFile = INVALID_HANDLE_VALUE;

    if(DecryptContext) {
        if((Arg->DecryptContext = malloc(sizeof(CRYPT_CONTEXT))) == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            PrintLastError("ProcessFile:");
            goto err;
        }
    }

    if(EncryptContext) {
        if((Arg->EncryptContext = malloc(sizeof(CRYPT_CONTEXT))) == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            PrintLastError("ProcessFile:");
            goto err;
        }
    }

    if((Arg->FileName = malloc(MAX_PATH)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ProcessFile:");
        goto err;
    }

    
    strcpy(Arg->FileName, FileName);

    if(DecryptContext)
        memcpy(Arg->DecryptContext, DecryptContext, sizeof(CRYPT_CONTEXT));
    if(EncryptContext)
        memcpy(Arg->EncryptContext, EncryptContext, sizeof(CRYPT_CONTEXT));

    // open resume file
    _snprintf(ResumeFile, sizeof(ResumeFile), "%s"ENC_DISK_RESUME_FILE_SURFIX, FileName);
    Arg->hResumeFile = CreateFile(
        ResumeFile,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        );
    if(Arg->hResumeFile == INVALID_HANDLE_VALUE) {
        PrintLastError("ProcessFile:");
        goto err;
    }

    memcpy(&Arg->Resume, Slot, sizeof(Arg->Resume));

    Arg->hThread = CreateThread(
        NULL,
        0,
        ProcessWorker,
        Arg,
        0,
        &Arg->ThreadID
        );
    if(NULL == Arg->hThread) {
        PrintLastError("ProcessFile:");
        goto err;
    }

    Arg->ThreadIndex = ThreadIndex;

    PrintMessage("Thread [%u][%I64u %I64u %I64u]\n", Arg->ThreadIndex, Slot->Header.From, Slot->Header.Index, Slot->Header.To);

    Ret = 0;
err:
    if(Ret != 0) {
        if(NULL != Arg) {
            if(Arg->DecryptContext) free(Arg->DecryptContext);
            if(Arg->EncryptContext) free(Arg->EncryptContext);
            if(Arg->hThread) CloseHandle(Arg->hThread);
            if(Arg->FileName) free(Arg->FileName);
            if(Arg->hResumeFile != INVALID_HANDLE_VALUE) CloseHandle(Arg->hResumeFile);
            free(Arg);
        }
        Arg = NULL;
    }
    return Arg;
}


INT ProcessFile(const CHAR * FileName, 
    PCRYPT_CONTEXT DecryptContext, 
    PCRYPT_CONTEXT EncryptContext, 
    ULONG ThreadNum)
{
    LARGE_INTEGER FileSize;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PENC_PROCESS_ARG Threads[ENC_DISK_MAX_THREAD_CNT] = {NULL};
    HANDLE hThreads[ENC_DISK_MAX_THREAD_CNT];
    ULONG i = 0, j, ThreadCnt = 0;
    DWORD WaitStatus;
    INT Ret = -1;
    INT Progress;
    time_t begin;
    PENC_RESUME_FILE Resume = NULL;

    DoCount = 0;
    QuitThreadCnt = 0;

    begin = time(NULL);

    if(ThreadNum == 0)
        ThreadNum = ENC_DISK_DEFAULT_THREAD_CNT;
    if(ThreadNum > ENC_DISK_MAX_THREAD_CNT)
        ThreadNum = ENC_DISK_MAX_THREAD_CNT;

    // open data file
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
        PrintLastError("ProcessFile:");
        goto err;
    }

    if(!GetFileSizeEx(hFile, &FileSize)) {
        PrintLastError("ProcessFile:");
        goto err;
    }

    // load resume file 
    if((Resume = LoadResumeFile(FileName, ThreadNum, FileSize, DecryptContext, EncryptContext)) == NULL) {
        goto err;
    }

    // fix data
    if(FixImageFile(hFile, Resume, DecryptContext, EncryptContext) != 0) {
        goto err;
    }
    
    LastDoCount = DoCount;

    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    ThreadCnt = 0;
    for(i = 0; i < Resume->Header.SlotCnt; i ++) {
        Threads[i] = ProcessFileBlock(i, FileName, DecryptContext, EncryptContext, &Resume->Slot[i]);
        if(Threads[i] == NULL) {
            goto err;
        } else {
            hThreads[i] = Threads[i]->hThread;
        }
        ThreadCnt ++;
    }

    ThreadCnt = i;

    free(Resume);
    Resume = NULL;

again:
    /*wait for thread exit*/
    WaitStatus = WaitForMultipleObjects(ThreadCnt, hThreads, TRUE, 10000);
    
    if(WaitStatus == WAIT_FAILED) {
        PrintLastError("ProcessFile:");
        goto err;
    } else if(WaitStatus == WAIT_TIMEOUT){
        Progress = (INT)((DoCount * 100) / (FileSize.QuadPart / CRYPT_CLUSTER_SIZE));
        PrintMessage("[%d%%][Quit Thread %u] ETA: %s", Progress, QuitThreadCnt, 
            GetETA(begin, DoCount, FileSize.QuadPart / CRYPT_CLUSTER_SIZE));
        goto again;  
    }
    Progress = 100;
    PrintMessage("[%d%%][Quit Thread %u]\n", Progress, QuitThreadCnt);

    Ret = 0;

err:
    if(NULL != Resume) {
        free(Resume);
        Resume = NULL;
    }
    if(hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if(Ret != 0) {
        for(j = 0; j < ThreadCnt; j ++) {
            TerminateThread(hThreads[j], 1);
        }
    }
    for(j = 0; j < ThreadCnt; j ++) {
        if(GetExitCodeThread(hThreads[j], &WaitStatus)) {
            if(WaitStatus) {
                Ret = -1;
            }
        }
        CloseHandle(hThreads[j]);
        hThreads[j] = NULL;
        if(NULL != Threads[j]) {
            if(NULL != Threads[j]->DecryptContext) {
                free(Threads[j]->DecryptContext);
                Threads[j]->DecryptContext = NULL;
            }
            if(NULL != Threads[j]->EncryptContext) {
                free(Threads[j]->EncryptContext);
                Threads[j]->EncryptContext = NULL;
            }
            if(NULL != Threads[j]->FileName) {
                free(Threads[j]->FileName);
                Threads[j]->FileName = NULL;
            }
            if(INVALID_HANDLE_VALUE != Threads[j]->hResumeFile) {
                CloseHandle(Threads[j]->hResumeFile);
                Threads[j]->hResumeFile = INVALID_HANDLE_VALUE;
            }
            free(Threads[j]);
        }
    }
    if(Ret == 0)
        DeleteResumeFile(FileName);
    return Ret;
}
