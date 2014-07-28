/* Defines the LTC_ARGCHK macro used within the library */
/* ARGTYPE is defined in mycrypt_cfg.h */

#ifndef __CRYPT_ARGCHK_H__
#define __CRYPT_ARGCHK_H__

#define LTC_ARGCHK(x)   if (!(x)) return CRYPT_INVALID_ARG;
#define LTC_ARGCHKVD(x) if (!(x)) return;

#endif


/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_argchk.h,v $ */
/* $Revision: 1.5 $ */
/* $Date: 2006/08/27 20:50:21 $ */
