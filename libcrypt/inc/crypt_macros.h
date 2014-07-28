#ifndef __CRYPT_MACROS_H__
#define __CRYPT_MACROS_H__

/* fix for MSVC ...evil! */

#define CONST64(n) n ## ULL



/* ---- HELPER MACROS ---- */
#ifdef ENDIAN_NEUTRAL

#define STORE32L(x, y)                                                                     \
     { (y)[3] = (UCHAR)(((x)>>24)&255); (y)[2] = (UCHAR)(((x)>>16)&255);   \
       (y)[1] = (UCHAR)(((x)>>8)&255); (y)[0] = (UCHAR)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((ULONG)((y)[3] & 255)<<24) | \
           ((ULONG)((y)[2] & 255)<<16) | \
           ((ULONG)((y)[1] & 255)<<8)  | \
           ((ULONG)((y)[0] & 255)); }

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (UCHAR)(((x)>>56)&255); (y)[6] = (UCHAR)(((x)>>48)&255);   \
       (y)[5] = (UCHAR)(((x)>>40)&255); (y)[4] = (UCHAR)(((x)>>32)&255);   \
       (y)[3] = (UCHAR)(((x)>>24)&255); (y)[2] = (UCHAR)(((x)>>16)&255);   \
       (y)[1] = (UCHAR)(((x)>>8)&255); (y)[0] = (UCHAR)((x)&255); }

#define LOAD64L(x, y)                                                       \
     { x = (((ULONG64)((y)[7] & 255))<<56)|(((ULONG64)((y)[6] & 255))<<48)| \
           (((ULONG64)((y)[5] & 255))<<40)|(((ULONG64)((y)[4] & 255))<<32)| \
           (((ULONG64)((y)[3] & 255))<<24)|(((ULONG64)((y)[2] & 255))<<16)| \
           (((ULONG64)((y)[1] & 255))<<8)|(((ULONG64)((y)[0] & 255))); }

#define STORE32H(x, y)                                                                     \
     { (y)[0] = (UCHAR)(((x)>>24)&255); (y)[1] = (UCHAR)(((x)>>16)&255);   \
       (y)[2] = (UCHAR)(((x)>>8)&255); (y)[3] = (UCHAR)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((ULONG)((y)[0] & 255)<<24) | \
           ((ULONG)((y)[1] & 255)<<16) | \
           ((ULONG)((y)[2] & 255)<<8)  | \
           ((ULONG)((y)[3] & 255)); }

#define STORE64H(x, y)                                                                     \
   { (y)[0] = (UCHAR)(((x)>>56)&255); (y)[1] = (UCHAR)(((x)>>48)&255);     \
     (y)[2] = (UCHAR)(((x)>>40)&255); (y)[3] = (UCHAR)(((x)>>32)&255);     \
     (y)[4] = (UCHAR)(((x)>>24)&255); (y)[5] = (UCHAR)(((x)>>16)&255);     \
     (y)[6] = (UCHAR)(((x)>>8)&255); (y)[7] = (UCHAR)((x)&255); }

#define LOAD64H(x, y)                                                      \
   { x = (((ULONG64)((y)[0] & 255))<<56)|(((ULONG64)((y)[1] & 255))<<48) | \
         (((ULONG64)((y)[2] & 255))<<40)|(((ULONG64)((y)[3] & 255))<<32) | \
         (((ULONG64)((y)[4] & 255))<<24)|(((ULONG64)((y)[5] & 255))<<16) | \
         (((ULONG64)((y)[6] & 255))<<8)|(((ULONG64)((y)[7] & 255))); }

#endif /* ENDIAN_NEUTRAL */

#ifdef ENDIAN_LITTLE



#define STORE32H(x, y)                                                                     \
     { (y)[0] = (UCHAR)(((x)>>24)&255); (y)[1] = (UCHAR)(((x)>>16)&255);   \
       (y)[2] = (UCHAR)(((x)>>8)&255); (y)[3] = (UCHAR)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((ULONG)((y)[0] & 255)<<24) | \
           ((ULONG)((y)[1] & 255)<<16) | \
           ((ULONG)((y)[2] & 255)<<8)  | \
           ((ULONG)((y)[3] & 255)); }



#define STORE64H(x, y)                                                                     \
   { (y)[0] = (UCHAR)(((x)>>56)&255); (y)[1] = (UCHAR)(((x)>>48)&255);     \
     (y)[2] = (UCHAR)(((x)>>40)&255); (y)[3] = (UCHAR)(((x)>>32)&255);     \
     (y)[4] = (UCHAR)(((x)>>24)&255); (y)[5] = (UCHAR)(((x)>>16)&255);     \
     (y)[6] = (UCHAR)(((x)>>8)&255); (y)[7] = (UCHAR)((x)&255); }

#define LOAD64H(x, y)                                                      \
   { x = (((ULONG64)((y)[0] & 255))<<56)|(((ULONG64)((y)[1] & 255))<<48) | \
         (((ULONG64)((y)[2] & 255))<<40)|(((ULONG64)((y)[3] & 255))<<32) | \
         (((ULONG64)((y)[4] & 255))<<24)|(((ULONG64)((y)[5] & 255))<<16) | \
         (((ULONG64)((y)[6] & 255))<<8)|(((ULONG64)((y)[7] & 255))); }


#ifdef ENDIAN_32BITWORD 

#define STORE32L(x, y)        \
     { ULONG  __t = (x); XMEMCPY(y, &__t, 4); }

#define LOAD32L(x, y)         \
     XMEMCPY(&(x), y, 4);

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (UCHAR)(((x)>>56)&255); (y)[6] = (UCHAR)(((x)>>48)&255);   \
       (y)[5] = (UCHAR)(((x)>>40)&255); (y)[4] = (UCHAR)(((x)>>32)&255);   \
       (y)[3] = (UCHAR)(((x)>>24)&255); (y)[2] = (UCHAR)(((x)>>16)&255);   \
       (y)[1] = (UCHAR)(((x)>>8)&255); (y)[0] = (UCHAR)((x)&255); }

#define LOAD64L(x, y)                                                       \
     { x = (((ULONG64)((y)[7] & 255))<<56)|(((ULONG64)((y)[6] & 255))<<48)| \
           (((ULONG64)((y)[5] & 255))<<40)|(((ULONG64)((y)[4] & 255))<<32)| \
           (((ULONG64)((y)[3] & 255))<<24)|(((ULONG64)((y)[2] & 255))<<16)| \
           (((ULONG64)((y)[1] & 255))<<8)|(((ULONG64)((y)[0] & 255))); }

#else /* 64-bit words then  */

#define STORE32L(x, y)        \
     { ULONG __t = (x); XMEMCPY(y, &__t, 4); }

#define LOAD32L(x, y)         \
     { XMEMCPY(&(x), y, 4); x &= 0xFFFFFFFF; }

#define STORE64L(x, y)        \
     { ULONG64 __t = (x); XMEMCPY(y, &__t, 8); }

#define LOAD64L(x, y)         \
    { XMEMCPY(&(x), y, 8); }

#endif /* ENDIAN_64BITWORD */

#endif /* ENDIAN_LITTLE */

#ifdef ENDIAN_BIG
#define STORE32L(x, y)                                                                     \
     { (y)[3] = (UCHAR)(((x)>>24)&255); (y)[2] = (UCHAR)(((x)>>16)&255);   \
       (y)[1] = (UCHAR)(((x)>>8)&255); (y)[0] = (UCHAR)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((ULONG)((y)[3] & 255)<<24) | \
           ((ULONG)((y)[2] & 255)<<16) | \
           ((ULONG)((y)[1] & 255)<<8)  | \
           ((ULONG)((y)[0] & 255)); }

#define STORE64L(x, y)                                                                     \
   { (y)[7] = (UCHAR)(((x)>>56)&255); (y)[6] = (UCHAR)(((x)>>48)&255);     \
     (y)[5] = (UCHAR)(((x)>>40)&255); (y)[4] = (UCHAR)(((x)>>32)&255);     \
     (y)[3] = (UCHAR)(((x)>>24)&255); (y)[2] = (UCHAR)(((x)>>16)&255);     \
     (y)[1] = (UCHAR)(((x)>>8)&255); (y)[0] = (UCHAR)((x)&255); }

#define LOAD64L(x, y)                                                      \
   { x = (((ULONG64)((y)[7] & 255))<<56)|(((ULONG64)((y)[6] & 255))<<48) | \
         (((ULONG64)((y)[5] & 255))<<40)|(((ULONG64)((y)[4] & 255))<<32) | \
         (((ULONG64)((y)[3] & 255))<<24)|(((ULONG64)((y)[2] & 255))<<16) | \
         (((ULONG64)((y)[1] & 255))<<8)|(((ULONG64)((y)[0] & 255))); }

#ifdef ENDIAN_32BITWORD 

#define STORE32H(x, y)        \
     { ULONG __t = (x); XMEMCPY(y, &__t, 4); }

#define LOAD32H(x, y)         \
     XMEMCPY(&(x), y, 4);

#define STORE64H(x, y)                                                                     \
     { (y)[0] = (UCHAR)(((x)>>56)&255); (y)[1] = (UCHAR)(((x)>>48)&255);   \
       (y)[2] = (UCHAR)(((x)>>40)&255); (y)[3] = (UCHAR)(((x)>>32)&255);   \
       (y)[4] = (UCHAR)(((x)>>24)&255); (y)[5] = (UCHAR)(((x)>>16)&255);   \
       (y)[6] = (UCHAR)(((x)>>8)&255);  (y)[7] = (UCHAR)((x)&255); }

#define LOAD64H(x, y)                                                       \
     { x = (((ULONG64)((y)[0] & 255))<<56)|(((ULONG64)((y)[1] & 255))<<48)| \
           (((ULONG64)((y)[2] & 255))<<40)|(((ULONG64)((y)[3] & 255))<<32)| \
           (((ULONG64)((y)[4] & 255))<<24)|(((ULONG64)((y)[5] & 255))<<16)| \
           (((ULONG64)((y)[6] & 255))<<8)| (((ULONG64)((y)[7] & 255))); }

#else /* 64-bit words then  */

#define STORE32H(x, y)        \
     { ULONG __t = (x); XMEMCPY(y, &__t, 4); }

#define LOAD32H(x, y)         \
     { XMEMCPY(&(x), y, 4); x &= 0xFFFFFFFF; }

#define STORE64H(x, y)        \
     { ULONG64 __t = (x); XMEMCPY(y, &__t, 8); }

#define LOAD64H(x, y)         \
    { XMEMCPY(&(x), y, 8); }

#endif /* ENDIAN_64BITWORD */
#endif /* ENDIAN_BIG */

#define BSWAP(x)  ( ((x>>24)&0x000000FFUL) | ((x<<24)&0xFF000000UL)  | \
                    ((x>>8)&0x0000FF00UL)  | ((x<<8)&0x00FF0000UL) )





/* rotates the hard way */
#define ROL(x, y) ( (((ULONG)(x)<<(ULONG)((y)&31)) | (((ULONG)(x)&0xFFFFFFFFUL)>>(ULONG)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROR(x, y) ( ((((ULONG)(x)&0xFFFFFFFFUL)>>(ULONG)((y)&31)) | ((ULONG)(x)<<(ULONG)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((ULONG)(x)<<(ULONG)((y)&31)) | (((ULONG)(x)&0xFFFFFFFFUL)>>(ULONG)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define RORc(x, y) ( ((((ULONG)(x)&0xFFFFFFFFUL)>>(ULONG)((y)&31)) | ((ULONG)(x)<<(ULONG)(32-((y)&31)))) & 0xFFFFFFFFUL)



#define ROL64(x, y) \
    ( (((x)<<((ULONG64)(y)&63)) | \
      (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ULONG64)64-((y)&63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64(x, y) \
    ( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ULONG64)(y)&CONST64(63))) | \
      ((x)<<((ULONG64)(64-((y)&CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROL64c(x, y) \
    ( (((x)<<((ULONG64)(y)&63)) | \
      (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ULONG64)64-((y)&63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64c(x, y) \
    ( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ULONG64)(y)&CONST64(63))) | \
      ((x)<<((ULONG64)(64-((y)&CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))

#ifndef MAX
   #define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
   #define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

#define byte(x, n) ((UCHAR)((x) >> (8 * (n))))

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_macros.h,v $ */
/* $Revision: 1.15 $ */
/* $Date: 2006/11/29 23:43:57 $ */
