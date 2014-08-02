#include "control.h"

static CRYPT_XFUN xfun;

static ULONG __stdcall Rand()
{
    return rand();
}
static void __stdcall Memcpy(void *dest, const void *src, SIZE_T n)
{
    RtlCopyMemory(dest, src, n);
}

static INT __stdcall Memcmp(const void *s1, const void *s2, SIZE_T n)
{
    return (INT)memcmp(s1, s2, n);
}
BOOL RandInitialize()
{
    memset(&xfun, 0, sizeof(xfun));
    xfun.xrand = Rand;
    xfun.xmemcpy = Memcpy;
    xfun.xmemcmp = Memcmp;
    srand((INT)time(NULL));
    return CryptInitialize(&xfun) == CRYPT_OK ? TRUE : FALSE;
}