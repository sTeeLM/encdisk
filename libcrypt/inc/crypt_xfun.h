#ifndef __CRYPT_XFUN_H__
#define __CRYPT_XFUN_H__

/* you can change how memory allocation works ... */
void XMEMCPY(void *dest, const void *src, SIZE_T n);
INT   XMEMCMP(const void *s1, const void *s2, SIZE_T n);
void XMEMSET(void *s, INT c, SIZE_T n);
INT   XSTRCMP(const CHAR *s1, const CHAR *s2);
void XZEROMEM(void *s, SIZE_T n);
ULONG XRAND();
SIZE_T XSTRLEN(const CHAR * str);
#endif