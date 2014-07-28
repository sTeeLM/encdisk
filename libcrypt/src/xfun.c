#include "crypt.h"
#include <limits.h>

CRYPT_XFUN xfun;

void XMEMCPY(void *dest, const void *src, SIZE_T n)
{
	UCHAR * p1 = (UCHAR *) dest;
	UCHAR * p2 = (UCHAR *) src;

	if(NULL != xfun.xmemcpy)
		xfun.xmemcpy(dest, src, n);

	if(p1 == p2)
		return ;

	while(n --) {
		*p1 = *p2;
		p1 ++;
		p2 ++;
	}
}

INT XMEMCMP(const void *s1, const void *s2, SIZE_T n)
{
	INT ret = 0;
	UCHAR * p1 = (UCHAR *) s1;
	UCHAR * p2 = (UCHAR *) s2;

	if(NULL != xfun.xmemcmp)
		return xfun.xmemcmp(s1, s2, n);

	while(n --) {
		if(*p1 > *p2) {
			ret = 1;
			break;
		}
		else if(*p1 < *p2) {
			ret = -1;
			break;
		}
		p1 ++;
		p2 ++;
	}

	return ret;
}

void XMEMSET(void *s, INT c, SIZE_T n)
{
	UCHAR * p1 = (UCHAR *) s;

	if(NULL != xfun.xmemset)
		xfun.xmemset(s, c, n);

	while(n --) {
		*p1 = (UCHAR)c;
		p1 ++;
	}
}

INT  XSTRCMP(const CHAR *s1, const CHAR *s2)
{
	INT ret = 0;
	CHAR * p1 = (CHAR *) s1;
	CHAR * p2 = (CHAR *) s2;

	if(NULL != xfun.xstrcmp)
		return xfun.xstrcmp(s1, s2);

	while(*p1 && *p2) {
		if(*p1 > *p2) {
			ret = 1;
			break;
		}
		else if(*p1 < *p2) {
			ret = -1;
			break;
		}
		p1 ++;
		p2 ++;
	}
	if(*p1 && ! *p2) {
		ret = 1;
	} else if(! *p1 && *p2) {
		ret = -1;
	}
	return ret;
}

void XZEROMEM(void *s, SIZE_T n)
{
	if(NULL != xfun.xzeromem) {
		xfun.xzeromem(s, n);
	} else {
		XMEMSET(s, 0, n);
	}
}

SIZE_T XSTRLEN(const CHAR * s)
{

	const CHAR * p = s;
	SIZE_T ret = 0;

	if(NULL != xfun.xstrlen)
		return xfun.xstrlen(s);

	while(*p) {
		p ++;
		ret ++;
	}
	return ret;
}

static ULONG rand_seed;

ULONG XRAND()
{
	if(NULL != xfun.xrand)
		return xfun.xrand();

	rand_seed = (rand_seed * 123 + 59 )% ULONG_MAX; 

	return(rand_seed); 
}