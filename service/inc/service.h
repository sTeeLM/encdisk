#ifndef __ENC_SERVICE_H__
#define __ENC_SERVICE_H__

#include <windows.h>
#include <stdio.h>

#include "encdisk_version.h"
#include "common.h"

#define ENC_MON_SERVICE_NAME "EncMon"
#define ENC_MON_SERVICE_DISPLAY_NAME "Enc Disk Monitor Service"
#define ENC_MON_SERVICE_DESCRIPTION "Enc Disk Monitor Service, prevent data lost when system shutdown"

#define ENC_DISK_SERVICE_NAME "EncDisk\0\0"

#define ENC_MON_MAX_CHECK_POINT 100

#define ENC_MON_SERVICE_MAX_WAIT_MS (120 * 1000)

#define ENC_LOG_DBG 4
#define ENC_LOG_INF 3
#define ENC_LOG_WAN 2
#define ENC_LOG_ERR 1
 
void EncMonLog(INT LogLevel, const CHAR * fmt, ...);

VOID WINAPI EncServiceMain(DWORD dwArgc, LPSTR* lpszArgv);
DWORD WINAPI EncControlHandler(
    DWORD dwControl,
    DWORD dwEventType,
    LPVOID lpEventData,
    LPVOID lpContext
);
INT EncServiceUninstall();
INT EncServiceInstall();
void PrintLastError(const CHAR* Prefix);
BOOL EncUnmountDisk(BOOL Force);

#endif
