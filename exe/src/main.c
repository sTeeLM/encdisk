/*
    This is a virtual disk driver for Windows that uses one or more files to
    emulate physical disks.
    Copyright (C) 1999-2009 Bo Brant�n.
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

#include "control.h"

INT EncDiskSyntax(void)
{
    fprintf(stderr, "Encrypt Disk Control Tool, Version %s\n", ENC_DISK_VERSION_STR);
    fprintf(stderr, "  by sTeeL <steel.mental@gmail.com>\n");
    fprintf(stderr, "  Thanks to Bo Branten's filedisk <http://www.acc.umu.se/~bosse/>\n");
    fprintf(stderr, "  and Arsenal Image Mounter <https://github.com/ArsenalRecon>\n");
    fprintf(stderr, "  and Tom St Denis's LibTomCrypt <http://libtom.org/>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "syntax:\n");
    fprintf(stderr, "encdisk-ctl /create <filename> <size[K|M|G>\n");
    fprintf(stderr, "encdisk-ctl /newkey <key file> <hard level %d->%d>\n", CRYPT_MIN_HARD, CRYPT_MAX_HARD);
    fprintf(stderr, "encdisk-ctl /encrypt <filename> <key file> [thread num]\n");
    fprintf(stderr, "encdisk-ctl /decrypt <filename> <key file> [thread num]\n");
    fprintf(stderr, "encdisk-ctl /rekey <filename> <decrypt key file> <encrypt key file> [thread num]\n");
    fprintf(stderr, "encdisk-ctl /mount <filename> [key file]\n");
    fprintf(stderr, "encdisk-ctl /mountro <filename> [key file]\n");
    fprintf(stderr, "encdisk-ctl /umount <device number> \n");
    fprintf(stderr, "encdisk-ctl /list\n");
    fprintf(stderr, "encdisk-ctl /status <device number>\n");
    fprintf(stderr, "encdisk-ctl /keyinfo <key file>\n");
    fprintf(stderr, "encdisk-ctl /keypass <key file>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "example:\n");
    fprintf(stderr, "encdisk-ctl /create encdisk.img 8M\n");
    fprintf(stderr, "  create a new empty disk image\n");
    fprintf(stderr, "encdisk-ctl /newkey newkey.bin %d\n", CRYPT_MAX_HARD);
    fprintf(stderr, "  create new key\n");
    fprintf(stderr, "encdisk-ctl /encrypt encdisk.img key.bin\n");
    fprintf(stderr, "  encrypt disk image with key.bin\n");
    fprintf(stderr, "encdisk-ctl /decrypt encdisk.img key.bin\n");
    fprintf(stderr, "  decrypt disk image with key.bin\n");
    fprintf(stderr, "encdisk-ctl /rekey encdisk.img oldkey.bin newkey.bin\n");
    fprintf(stderr, "  change key of disk image\n");
    fprintf(stderr, "encdisk-ctl /mount encdisk.img key.bin\n");
    fprintf(stderr, "  mount image\n");
    fprintf(stderr, "encdisk-ctl /umount 00:00:00\n");
    fprintf(stderr, "  unmount image at Lun=00, TargetId=00, PathId=00\n");
    fprintf(stderr, "encdisk-ctl /keyinfo key.bin\n");
    fprintf(stderr, "  get information of key.bin\n");
    fprintf(stderr, "encdisk-ctl /keypass key.bin\n");
    fprintf(stderr, "  change password of key.bin\n");
    return -1;
}

static BOOL FullPath(const CHAR * src, SIZE_T dst_size, CHAR * dst)
{
    DWORD n;
    if(src[0] != '\\') {
        n = (DWORD)GetFullPathName(src, (DWORD)dst_size, dst, NULL);
        if(n == 0 || n > dst_size) return FALSE;
        dst[n] = 0;
    } else {
        strncpy(dst, src, dst_size);
    }
    return TRUE;
}


INT __cdecl main(INT argc, CHAR* argv[])
{
    CHAR*                   Command;
    DEVICE_NUMBER           DeviceNumber;
    CHAR*                   FileName;
    CHAR*                   NewPrivateKey;
    CHAR*                   OldPrivateKey;
    CHAR*                   Option;
    LARGE_INTEGER           RealFileSize;
    INT                     HardLevel = CRYPT_MAX_HARD;
    INT                     ThreadNum = ENC_DEFAULT_THREAD_NUM;
    CRYPT_XFUN              xfun;
    CHAR                    Path1[MAX_PATH];
    CHAR                    Path2[MAX_PATH];
    CHAR                    Path3[MAX_PATH];
    BOOLEAN                 Force;

    if(!RandInitialize()) {
        return EncDiskSyntax();
    }

    Command = argv[1];

    if (argc == 4 && !strcmp(Command, "/create"))
    {
        FileName = argv[2];
        Option = argv[3];

        if (strlen(FileName) < 2)
        {
            return EncDiskSyntax();
        }

        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        if (Option[strlen(Option) - 1] == 'G')
        {
            RealFileSize.QuadPart =
                _atoi64(Option) * 1024 * 1024 * 1024;
        }
        else if (Option[strlen(Option) - 1] == 'M')
        {
            RealFileSize.QuadPart =
                _atoi64(Option) * 1024 * 1024;
        }
        else if (Option[strlen(Option) - 1] == 'K')
        {
            RealFileSize.QuadPart =
                _atoi64(Option) * 1024;
        }
        else
        {
            RealFileSize.QuadPart =
                _atoi64(Option);
        }
        
        // size must be n * CRYPT_CLUSTER_SIZE
        RealFileSize.QuadPart = ((RealFileSize.QuadPart + 
            (CRYPT_CLUSTER_SIZE - 1)) >> CRYPT_CLUSTER_SHIFT) << CRYPT_CLUSTER_SHIFT;

        return EncDiskCreate(Path1, RealFileSize);

    } 
    else if((argc == 5 || argc == 6)&& !strcmp(Command, "/rekey"))
    {
        FileName = argv[2];
        OldPrivateKey = argv[3];
        NewPrivateKey = argv[4];
        if(argc == 6)
            ThreadNum = atoi(argv[5]);
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        if(!FullPath(OldPrivateKey, sizeof(Path2), Path2)) 
        {
            return EncDiskSyntax();
        }

        if(!FullPath(NewPrivateKey, sizeof(Path3), Path3)) 
        {
            return EncDiskSyntax();
        }

        return EncDiskRekey(Path1, Path2, Path3, ThreadNum);
    }
    else if(argc == 4 && !strcmp(Command, "/newkey"))
    {
        NewPrivateKey = argv[2];
        HardLevel = atoi(argv[3]);

        if(!FullPath(NewPrivateKey, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        return EncDiskNewKey(Path1, HardLevel);
    }
    else if((argc == 4 || argc == 5) && !strcmp(Command, "/encrypt"))
    {
        FileName = argv[2];
        NewPrivateKey = argv[3];
        if(argc == 5)
            ThreadNum = atoi(argv[4]);
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        if(!FullPath(NewPrivateKey, sizeof(Path2), Path2)) 
        {
            return EncDiskSyntax();
        }
        return EncDiskEncrypt(Path1, Path2, ThreadNum);
    }
    else if((argc == 4 || argc == 5) && !strcmp(Command, "/decrypt"))
    {
        FileName = argv[2];
        NewPrivateKey = argv[3];
        if(argc == 5)
            ThreadNum = atoi(argv[4]);
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        if(!FullPath(NewPrivateKey, sizeof(Path2), Path2)) 
        {
            return EncDiskSyntax();
        }
        return EncDiskDecrypt(Path1, Path2, ThreadNum);
    }
    else if((argc == 3 || argc == 4) && !strcmp(Command, "/mount"))
    {
        FileName = argv[2];
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }
        if(argc == 4) {
            NewPrivateKey = argv[3];
            if(!FullPath(NewPrivateKey, sizeof(Path2), Path2)) 
            {
                return EncDiskSyntax();
            }
        } 
        return EncDiskMount(Path1, argc == 3 ? NULL : Path2, FALSE);
    }
    else if((argc == 3 || argc == 4) && !strcmp(Command, "/mountro"))
    {
        FileName = argv[2];
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }
        if(argc == 4) {
            NewPrivateKey = argv[3];
            if(!FullPath(NewPrivateKey, sizeof(Path2), Path2)) 
            {
                return EncDiskSyntax();
            }
        } 
        return EncDiskMount(Path1, argc == 3 ? NULL : Path2, TRUE);
    }
    else if((argc == 3) && !strcmp(Command, "/umount"))
    {
        if(!GetDeviceNumber(argv[2], &DeviceNumber)) 
        {
            return EncDiskSyntax();
        }
        return EncDiskUmount(&DeviceNumber);
    }
    else if(argc == 2 && !strcmp(Command, "/list"))
    {
        return EncDiskList();
    } 
    else if(argc == 3 && !strcmp(Command, "/status"))
    {
        if(!GetDeviceNumber(argv[2], &DeviceNumber)) 
        {
            return EncDiskSyntax();
        }
        return EncDiskStatus(&DeviceNumber);
    } 
    if(argc == 3 && !strcmp(Command, "/keyinfo")) 
    {
        NewPrivateKey = argv[2];
        if(!FullPath(NewPrivateKey, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }
        return EncKeyInfo(Path1);
    }
    if(argc == 3 && !strcmp(Command, "/keypass")) 
    {
        NewPrivateKey = argv[2];
        if(!FullPath(NewPrivateKey, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }
        return EncKeyPass(Path1);
    }
    else
    {
        return EncDiskSyntax();
    }
}
