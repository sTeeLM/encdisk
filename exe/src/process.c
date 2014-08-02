#include "control.h"

#define ENC_CLUSTER_COUNT 64
#define ENC_DISK_MAX_THREAD_CNT MAXIMUM_WAIT_OBJECTS

static LONG DoCount;
static LONG QuitThreadCnt;

typedef struct _ENC_PROCESS_ARG
{
    CHAR * FileName;
    PCRYPT_CONTEXT DecryptContext;
    PCRYPT_CONTEXT EncryptContext;
    ULONGLONG From;
    ULONGLONG To;
    HANDLE hThread;
    DWORD  ThreadID;
}ENC_PROCESS_ARG, *PENC_PROCESS_ARG;


static DWORD WINAPI ProcessWorker(LPVOID Param)
{
    PENC_PROCESS_ARG P = (PENC_PROCESS_ARG) Param;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONGLONG ClusterCount = ENC_CLUSTER_COUNT;
    LPBYTE Buffer1 = NULL;
    LPBYTE Buffer2 = NULL;
    LARGE_INTEGER Pos, Begin;
    DWORD Junk;
    ULONGLONG b, n, i = 0, j = 0;
    DWORD Ret = 1;

    if((Buffer1 = malloc((size_t)(CRYPT_CLUSTER_SIZE * ClusterCount))) == NULL) {
        goto err;
    }

    if((Buffer2 = malloc((size_t)(CRYPT_CLUSTER_SIZE * ClusterCount))) == NULL) {
        goto err;
    }

    
    Begin.QuadPart = P->From * CRYPT_CLUSTER_SIZE;
    Pos.QuadPart = Begin.QuadPart;
    b = (P->To - P->From + 1) / ClusterCount; /* how many big block? */
    i = 0;

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
        for(j = 0 ; j < ClusterCount; j ++) {
            InterlockedIncrement(&DoCount);
            if(NULL != P->DecryptContext) {
                if(CryptDecryptCluster(P->DecryptContext, Buffer1 + j * CRYPT_CLUSTER_SIZE,
                    Buffer2 + j * CRYPT_CLUSTER_SIZE, P->From + i * ClusterCount + j) != CRYPT_OK) {
                    goto err;
                }
            } else {
                memcpy(Buffer2 + j * CRYPT_CLUSTER_SIZE, Buffer1 + j * CRYPT_CLUSTER_SIZE, CRYPT_CLUSTER_SIZE);
            }


            if(NULL != P->EncryptContext) {
                if(CryptEncryptCluster(P->EncryptContext, Buffer2 + j * CRYPT_CLUSTER_SIZE, 
                    Buffer1 + j * CRYPT_CLUSTER_SIZE, P->From + i * ClusterCount + j) != CRYPT_OK) {
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
        Pos.QuadPart += CRYPT_CLUSTER_SIZE * ClusterCount;
    }

    // small block: process cluster one by one
    if(ClusterCount != 1) {
        i = b * ClusterCount;
        b = P->To - P->From + 1;
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
    const CHAR * FileName,
    PCRYPT_CONTEXT DecryptContext,
    PCRYPT_CONTEXT EncryptContext,
    ULONGLONG From,
    ULONGLONG To
    )
{
    PENC_PROCESS_ARG Arg = NULL;
    INT Ret = -1;

   
    if((Arg = malloc(sizeof(ENC_PROCESS_ARG))) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("ProcessFile:");
        goto err;
    }

    memset(Arg, 0, sizeof(ENC_PROCESS_ARG));


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
    
    Arg->To = To;
    Arg->From = From;
   
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
    PrintMessage("Thread [%u][%I64u - %I64u]\n", Arg->ThreadID, From, To);

    Ret = 0;
err:
    if(Ret != 0) {
        if(NULL != Arg) {
            if(Arg->DecryptContext) free(Arg->DecryptContext);
            if(Arg->EncryptContext) free(Arg->EncryptContext);
            if(Arg->hThread) CloseHandle(Arg->hThread);
            if(Arg->FileName) free(Arg->FileName);
            free(Arg);
        }
        Arg = NULL;
    }
    return Arg;
}

INT ProcessFile(const CHAR * FileName, 
    PCRYPT_CONTEXT DecryptContext, 
    PCRYPT_CONTEXT EncryptContext, ULONG ThreadNum)
{
    LARGE_INTEGER FileSize;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONGLONG Cluster;
    PENC_PROCESS_ARG Threads[ENC_DISK_MAX_THREAD_CNT] = {NULL};
    HANDLE hThreads[ENC_DISK_MAX_THREAD_CNT];
    ULONG i = 0, j, ThreadCnt = 0;
    DWORD WaitStatus;
    INT Ret = -1;
    INT Progress;

    DoCount = 0;
    QuitThreadCnt = 0;

    if(ThreadNum == 0)
        ThreadNum = ENC_DEFAULT_THREAD_NUM;
    if(ThreadNum > ENC_DISK_MAX_THREAD_CNT - 1)
        ThreadNum = ENC_DISK_MAX_THREAD_CNT - 1;

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
        PrintLastError("ProcessFile:");
        goto err;
    }

    if(!GetFileSizeEx(hFile, &FileSize)) {
        PrintLastError("ProcessFile:");
        goto err;
    }
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    Cluster = (FileSize.QuadPart / CRYPT_CLUSTER_SIZE / ThreadNum);

    PrintMessage("ProcessFile: Total %I64u block, %I64u block per thread\n", FileSize.QuadPart / CRYPT_CLUSTER_SIZE, Cluster);

    if(Cluster != 0) { // create threads to process file
        for(i = 0; i < ThreadNum; i ++) {
            if((Threads[i] = ProcessFileBlock(FileName, 
                DecryptContext, EncryptContext, 
                i * Cluster, (i+1) * Cluster - 1)) == NULL) {
                    goto err;
            } else {
                hThreads[i] = Threads[i]->hThread;
            }
        }
    }
    if(Cluster * ThreadNum != FileSize.QuadPart / CRYPT_CLUSTER_SIZE) {
        Threads[i] = ProcessFileBlock(FileName, DecryptContext, EncryptContext,
            i * Cluster, FileSize.QuadPart / CRYPT_CLUSTER_SIZE - 1);
        if(Threads[i] == NULL) {
            goto err;
        } else {
            hThreads[i] = Threads[i]->hThread;
        }
        i++;
    }

    ThreadCnt = i;
    PrintMessage("[%d%%][Quit Thread %u]\n", 0, 0);
again:
    /*wait for thread exit*/
    WaitStatus = WaitForMultipleObjects(ThreadCnt, hThreads, TRUE, 10000);
    
    if(WaitStatus == WAIT_FAILED) {
        PrintLastError("ProcessFile:");
        goto err;
    } else if(WaitStatus == WAIT_TIMEOUT){
        Progress = (INT)((DoCount * 100) / (FileSize.QuadPart / CRYPT_CLUSTER_SIZE));
        PrintMessage("[%d%%][Quit Thread %u]\n", Progress, QuitThreadCnt);
        goto again;  
    }
    Progress = 100;
    PrintMessage("[%d%%][Quit Thread %u]\n", Progress, QuitThreadCnt);

    Ret = 0;

err:
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
                fprintf(stderr, "fuck %u\n", WaitStatus);
                Ret = -1;
            }
        }
        CloseHandle(hThreads[j]);
        hThreads[j] = NULL;
        if(NULL != Threads[j]) {
            if(NULL != Threads[j]->DecryptContext) {
                free(Threads[j]->DecryptContext);
            }
            if(NULL != Threads[j]->EncryptContext) {
                free(Threads[j]->EncryptContext);
            }
            if(NULL != Threads[j]->FileName) {
                free(Threads[j]->FileName);
            }
            free(Threads[j]);
        }
    }
    return Ret;
}
