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

static INT SaveResumeBlock(PENC_RESUME_SLOT Slot, HANDLE hResumeFile, ULONG ThreadIndex, ULONGLONG ClusterIndex, 
            ULONGLONG Size, LPVOID Data)
{
    LARGE_INTEGER Pos;
    DWORD Junk;

    Slot->Tag = ENC_RESUME_TAG_PROCESSING;
    Slot->BigBlock = Size == ENC_SLOT_SIZE ? 1 : 0;
    Slot->Index = ClusterIndex;
    memcpy(Slot->Data, Data, (size_t)Size);

    Pos.QuadPart = sizeof(ENC_RESUME_HEADER) + ThreadIndex * sizeof(ENC_RESUME_SLOT);
    if(!SetFilePointerEx(hResumeFile, Pos, NULL, FILE_BEGIN)) {
        return -1;
    }
    if(!WriteFile(hResumeFile, Slot, sizeof(ENC_RESUME_SLOT), &Junk, NULL) || Junk != sizeof(ENC_RESUME_SLOT)) {
        return -1;
    }
    if(!FlushFileBuffers(hResumeFile)) {
        return -1;
    }
    return 0;
}

static INT MarkResumeBlockDone(PENC_RESUME_SLOT Slot, HANDLE hResumeFile, ULONG ThreadIndex, ULONGLONG ClusterIndex, 
            ULONGLONG Size, LPVOID Data)
{
    LARGE_INTEGER Pos;
    DWORD Junk;

    Slot->Tag = ENC_RESUME_TAG_DONE;
    Slot->BigBlock = Size == ENC_SLOT_SIZE ? 1 : 0;
    Slot->Index = ClusterIndex;

    Pos.QuadPart = sizeof(ENC_RESUME_HEADER) + ThreadIndex * sizeof(ENC_RESUME_SLOT);
    if(!SetFilePointerEx(hResumeFile, Pos, NULL, FILE_BEGIN)) {
        return -1;
    }
    if(!WriteFile(hResumeFile, Slot, sizeof(ENC_RESUME_SLOT), &Junk, NULL) || Junk != sizeof(ENC_RESUME_SLOT)) {
        return -1;
    }
    if(!FlushFileBuffers(hResumeFile)) {
        return -1;
    }
    return 0;
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

    if(P->Resume.Index > P->Resume.To) {
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

    Start = P->Resume.Index;
    Begin.QuadPart = Start * CRYPT_CLUSTER_SIZE;
    Pos.QuadPart = Begin.QuadPart;
    b = (P->Resume.To - Start + 1) / ClusterCount; /* how many big block? */
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
            PrintLastError("FixImageFile:");
            goto err;
        }        
        if(MarkResumeBlockDone(&P->Resume, P->hResumeFile, P->ThreadIndex, Start + i * ClusterCount, 
            CRYPT_CLUSTER_SIZE * ClusterCount, Buffer1) != 0) {
            PrintLastError("ProcessFile:");
            goto err;
        }

        Pos.QuadPart += CRYPT_CLUSTER_SIZE * ClusterCount;
    }

    // small block: process cluster one by one
    if(ClusterCount != 1) {
        i = b * ClusterCount;
        b = P->Resume.To - Start + 1;
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
    ULONGLONG From,
    ULONGLONG To,
    ULONGLONG Index
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
    _snprintf(ResumeFile, sizeof(ResumeFile), "%s.res", FileName);
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

    Arg->Resume.From = From;
    Arg->Resume.To = To;
    Arg->Resume.Index = Index;

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

    PrintMessage("Thread [%u][%I64u %I64u %I64u]\n", Arg->ThreadIndex, From, Index, To);

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

static INT FixImageFile(HANDLE hFile, PENC_RESUME_FILE Resume)
{
    DWORD i;
    LARGE_INTEGER Begin;
    DWORD Junk;

    for(i = 0 ; i < Resume->Header.SlotCnt; i ++) {
        if(Resume->ResumeSlot[i].Tag == ENC_RESUME_TAG_EMPTY) {
            PrintMessage("Slot %d: do nothing\n", i);
            // do nothing
        } else if(Resume->ResumeSlot[i].Tag == ENC_RESUME_TAG_PROCESSING) {
            // copy resume data back to hFile
            // reset start point to Index
            PrintMessage("Slot %d: copy data back to image(start %I64u size %u clusters)\n", i, 
                Resume->ResumeSlot[i].Index, 
                Resume->ResumeSlot[i].BigBlock == 1 ? ENC_CLUSTER_BLOCK_COUNT : 1);
            Begin.QuadPart = Resume->ResumeSlot[i].Index * CRYPT_CLUSTER_SIZE;
            if(!SetFilePointerEx(hFile, Begin, NULL, FILE_BEGIN)) {
                PrintLastError("FixImageFile:");
                return -1;
            }
            if(!WriteFile(hFile, Resume->ResumeSlot[i].Data, 
                Resume->ResumeSlot[i].BigBlock == 1 ? ENC_CLUSTER_BLOCK_COUNT * CRYPT_CLUSTER_SIZE 
                    : CRYPT_CLUSTER_SIZE , &Junk, NULL)
                || Junk != (Resume->ResumeSlot[i].BigBlock == 1 ? ENC_CLUSTER_BLOCK_COUNT * CRYPT_CLUSTER_SIZE 
                    : CRYPT_CLUSTER_SIZE)) {
                PrintLastError("FixImageFile:");
                return -1;
            } 
            if(!FlushFileBuffers(hFile)) {
                PrintLastError("FixImageFile:");
                return -1;
            }
        } else if(Resume->ResumeSlot[i].Tag == ENC_RESUME_TAG_DONE) {
            PrintMessage("Slot %d: move start point from %I64u to %I64u\n", i, 
                Resume->ResumeSlot[i].Index,
                Resume->ResumeSlot[i].BigBlock == 1 ? Resume->ResumeSlot[i].Index + ENC_CLUSTER_BLOCK_COUNT
                    : Resume->ResumeSlot[i].Index + 1);
            Resume->ResumeSlot[i].Index = Resume->ResumeSlot[i].BigBlock == 1 ? 
            Resume->ResumeSlot[i].Index + ENC_CLUSTER_BLOCK_COUNT :
            Resume->ResumeSlot[i].Index + 1;
        }
        DoCount += (Resume->ResumeSlot[i].Index - Resume->ResumeSlot[i].From);
    }

    return 0;
}

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
    LARGE_INTEGER ResumeFileSize;
    BOOL bIsNew = FALSE;
    ULONGLONG Cluster;
    ULONG ThreadCnt = 0;
    PENC_RESUME_FILE Resume;
    INT nRet = -1;
    DWORD JunkBytes;
    ULONG i;
    ULONGLONG From[ENC_DISK_MAX_THREAD_CNT] = {0};
    ULONGLONG To[ENC_DISK_MAX_THREAD_CNT] = {0};

    if((Resume = malloc(sizeof(ENC_RESUME_FILE))) == NULL) {
        goto err;
    }
    

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

    

    // create file name
    _snprintf(ResumeFile, sizeof(ResumeFile), "%s.res", FileName);

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
        PrintMessage("No resume file (%s) found, create new one.\n", ResumeFile);
        memset(Resume, 0, sizeof(ENC_RESUME_FILE));
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
            Resume->ResumeSlot[i].From = From[i];
            Resume->ResumeSlot[i].To = To[i];
            Resume->ResumeSlot[i].Index = From[i];
        }

        if(!WriteFile(hResumeFile, Resume, sizeof(ENC_RESUME_FILE), &JunkBytes, NULL) || 
            JunkBytes != sizeof(ENC_RESUME_FILE)) {
            PrintLastError("LoadResumeFile:");
            goto err;
        }

        nRet = 0;

    } else { // check 
        PrintMessage("Resume file (%s) found.\n", ResumeFile);
        if(!ReadFile(hResumeFile, Resume, sizeof(ENC_RESUME_FILE), &JunkBytes, NULL) || 
            JunkBytes != sizeof(ENC_RESUME_FILE)) {
            PrintLastError("LoadResumeFile:");
            goto err;
        }

        if(Resume->Header.Signature != ENC_RESUME_FILE_SIGNATURE) {
            PrintMessage("LoadResumeFile: Invalid resume file (signature)\n");
            goto err;
        }
        if(Resume->Header.SlotCnt != ThreadCnt) {
            PrintMessage("LoadResumeFile: Invalid resume file (thread cnt)\n");
            goto err;
        }
        PrintMessage("SlotCnt is %u\n", Resume->Header.SlotCnt);

        if(Resume->Header.FileSize.QuadPart != FileSize.QuadPart) {
            PrintMessage("LoadResumeFile: Invalid resume file (file size)\n");
            goto err;
        }
        PrintMessage("FileSize is %I64u\n", Resume->Header.FileSize.QuadPart);

        if(NULL != DecryptContext) {
            if(memcmp(Resume->Header.DecryptKeyID, DecryptContext->key.signature, sizeof(Resume->Header.DecryptKeyID)) != 0) {
                PrintMessage("LoadResumeFile: Invalid resume file (decrypt context)\n");
                goto err;
            }
        }

        if(NULL != EncryptContext) {
            if(memcmp(Resume->Header.EncryptKeyID, EncryptContext->key.signature, sizeof(Resume->Header.EncryptKeyID)) != 0) {
                PrintMessage("LoadResumeFile: Invalid resume file (encrypt context)\n");
                goto err;
            }
        }
        for(i = 0 ; i < Resume->Header.SlotCnt; i ++) {
            PrintMessage("Slot %d: [%I64u | %I64u | %I64u] %d %d\n", 
                i, From[i], Resume->ResumeSlot[i].Index, 
                To[i], Resume->ResumeSlot[i].Tag, Resume->ResumeSlot[i].BigBlock);

            if(Resume->ResumeSlot[i].Tag != ENC_RESUME_TAG_PROCESSING 
                && Resume->ResumeSlot[i].Tag != ENC_RESUME_TAG_DONE
                && Resume->ResumeSlot[i].Tag != ENC_RESUME_TAG_EMPTY) {
                    PrintMessage("LoadResumeFile: Invalid resume file (tag of slot %d)\n", i);
                    goto err;
            }
            if(Resume->ResumeSlot[i].Index > (ULONGLONG)(FileSize.QuadPart / CRYPT_CLUSTER_SIZE)) {
                PrintMessage("LoadResumeFile: Invalid resume file (index of slot %d too big)\n", i);
                goto err;
            }
            if(Resume->ResumeSlot[i].Index < Resume->ResumeSlot[i].From || Resume->ResumeSlot[i].Index > Resume->ResumeSlot[i].To) {
                PrintMessage("LoadResumeFile: Invalid resume file (index of slot %d not between from & to)\n", i);
                goto err;
            }
            if(Resume->ResumeSlot[i].BigBlock && Resume->ResumeSlot[i].Index + ENC_CLUSTER_BLOCK_COUNT - 1 > Resume->ResumeSlot[i].To) {
                PrintMessage("LoadResumeFile: Invalid resume file (index not valid on slot %d)\n", i);
                goto err;
            }
            if(Resume->ResumeSlot[i].From != From[i] || Resume->ResumeSlot[i].To != To[i]) {
                PrintMessage("LoadResumeFile: Invalid resume file (from & to of slot %d)\n", i);
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
    _snprintf(ResumeFile, sizeof(ResumeFile), "%s.res", FileName);
    DeleteFile(ResumeFile);
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
    if(FixImageFile(hFile, Resume) != 0) {
        goto err;
    }
    
    LastDoCount = DoCount;

    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    ThreadCnt = 0;
    for(i = 0; i < Resume->Header.SlotCnt; i ++) {
        Threads[i] = ProcessFileBlock(i, FileName, DecryptContext, EncryptContext,
            Resume->ResumeSlot[i].From, Resume->ResumeSlot[i].To, Resume->ResumeSlot[i].Index);
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
