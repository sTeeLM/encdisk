#include "control.h"
#include <Wincrypt.h>
static CRYPT_XFUN xfun;

static ULONG __stdcall Rand()
{
	HCRYPTPROV hProvider = 0;
	const DWORD dwLength = 8;
    ULONG Ret = 0;

	if (!CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return Ret;


	if (!CryptGenRandom(hProvider, sizeof(Ret), (BYTE*)&Ret))
	{
		CryptReleaseContext(hProvider, 0);
		return Ret;
	}

	if (!CryptReleaseContext(hProvider, 0))
		return Ret;

    return Ret;
    
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
    return CryptInitialize(&xfun) == CRYPT_OK ? TRUE : FALSE;
}