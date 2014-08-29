#include "control.h"

INT GetWideLength(const CHAR * src)
{
    INT Ret = 0;
    Ret = MultiByteToWideChar(
        CP_OEMCP,
        0,
        src,
        -1,
        NULL,
        0
        );
    if(Ret <= 0)
        return Ret;
    else
        return Ret - 1;
}

INT AsciiToWide(const CHAR * src, WCHAR * dst, SIZE_T dst_len)
{
    INT Ret = 0;
    Ret = MultiByteToWideChar(
        CP_OEMCP,
        0,
        src,
        -1,
        dst,
        (INT)dst_len
        );
    return Ret > 0 ? 0 : -1;
}

INT WideToAscii(const WCHAR * src, CHAR * dst, SIZE_T dst_len)
{
    INT Ret = 0;
    Ret = WideCharToMultiByte(
        CP_OEMCP,
        0,
        src,
        -1,
        dst,
        (INT)dst_len,
        NULL,
        NULL
        );
    return Ret > 0 ? 0 : -1;
}