#include "service.h"

void PrintLastError(const CHAR* Prefix)
{
    LPVOID lpMsgBuf;

    FormatMessage( 
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        0,
        (LPTSTR) &lpMsgBuf,
        0,
        NULL
        );

    fprintf(stderr, "%s %s", Prefix, (LPTSTR) lpMsgBuf);

    LocalFree(lpMsgBuf);
}


void EncMonLog(INT LogLevel, const CHAR * fmt, ...)
{
    CHAR LogBuffer[4096];
    INT nSize = 0;
    va_list args;
    SYSTEMTIME tm;
    CHAR * str = "UNK";

    GetLocalTime(&tm);

    switch(LogLevel) {
        case ENC_LOG_ERR:
            str = "ERR";
            break;
        case ENC_LOG_WAN:
            str = "WAN";
            break;
        case ENC_LOG_INF:
            str = "INF";
            break;
        case ENC_LOG_DBG:
            str = "DBG";
            break;
    }
    nSize += _snprintf(LogBuffer + nSize, sizeof(LogBuffer)- nSize - 1, "EncMon [%s][%04d-%02d-%02d %02d:%02d:%02d.%06d]: ",
        str, tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond, tm.wMilliseconds);

    va_start(args, fmt);
    nSize += _vsnprintf(LogBuffer + nSize, sizeof(LogBuffer)- nSize - 1, fmt, args);
    va_end(args);

    LogBuffer[nSize] = 0;

    OutputDebugString(LogBuffer);

}