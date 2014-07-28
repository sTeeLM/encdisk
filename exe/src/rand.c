#include "control.h"

static CRYPT_XFUN xfun;

static ULONG __stdcall Rand()
{
    return rand();
}

BOOL RandInitialize()
{
    memset(&xfun, 0, sizeof(xfun));
    xfun.xrand = Rand;
    srand((INT)time(NULL));
    return CryptInitialize(&xfun) == CRYPT_OK ? TRUE : FALSE;
}