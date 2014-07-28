/*
    This is a virtual disk driver for Windows that uses one or more files to
    emulate physical disks.
    Copyright (C) 1999-2009 Bo Brantén.
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _ENC_DISK_
#define _ENC_DISK_

#ifndef __T
#ifdef _NTDDK_
#define __T(x)  L ## x
#else
#define __T(x)  x
#endif
#endif

#ifndef _T
#define _T(x)   __T(x)
#endif

#define ENC_DISK_VERSION   "1.0.0.0"

#define DEVICE_BASE_NAME    _T("\\EncDisk")
#define DEVICE_DIR_NAME     _T("\\Device")      DEVICE_BASE_NAME
#define DEVICE_NAME_PREFIX  DEVICE_DIR_NAME     DEVICE_BASE_NAME

#define FILE_DEVICE_ENC_DISK       0x8000

#define IOCTL_ENC_DISK_OPEN_FILE   CTL_CODE(FILE_DEVICE_ENC_DISK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_ENC_DISK_CLOSE_FILE  CTL_CODE(FILE_DEVICE_ENC_DISK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_ENC_DISK_QUERY_FILE  CTL_CODE(FILE_DEVICE_ENC_DISK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#include "crypt.h"

typedef struct _OPEN_FILE_INFORMATION {
    LARGE_INTEGER   RealFileSize;   /* total file size - enc header */
    UCHAR           DriveLetter;
    USHORT          FileNameLength;
    CRYPT_KEY       Key;
    UCHAR           FileName[1];
} OPEN_FILE_INFORMATION, *POPEN_FILE_INFORMATION;

#endif
