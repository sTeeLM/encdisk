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

#include "control.h"

INT EncDiskSyntax(void)
{
    fprintf(stderr, "Encrypt Disk Control Tool, Version %s\n", ENC_DISK_VERSION);
    fprintf(stderr, "  by sTeeL <steel.mental@gmail.com>\n");
    fprintf(stderr, "  Thanks to Bo Brant's filedisk <http://www.acc.umu.se/~bosse/>\n");
    fprintf(stderr, "  and Tom St Denis's LibTomCrypt <http://libtom.org/>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "syntax:\n");
    fprintf(stderr, "encdisk /create <filename> <size[K|M|G>\n");
    fprintf(stderr, "encdisk /newkey <key file> <hard level 0-10>\n");
    fprintf(stderr, "encdisk /encrypt <filename> <key file>\n");
    fprintf(stderr, "encdisk /decrypt <filename> <key file>\n");
    fprintf(stderr, "encdisk /rekey <filename> <decrypt key file> <encrypt key file>\n");
    fprintf(stderr, "encdisk /mount <filename> <key file> <devicenumber> <drive:>\n");
    fprintf(stderr, "encdisk /umount <drive:>\n");
    fprintf(stderr, "encdisk /status <drive:>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "example:\n");
    fprintf(stderr, "encdisk /create encdisk.img 8M\n");
    fprintf(stderr, "  create a new empty disk image\n");
    fprintf(stderr, "encdisk /newkey newkey.bin 9\n");
    fprintf(stderr, "  create new key\n");
    fprintf(stderr, "encdisk /encrypt encdisk.img key.bin\n");
    fprintf(stderr, "  encrypt disk image with key.bin\n");
    fprintf(stderr, "encdisk /decrypt encdisk.img key.bin\n");
    fprintf(stderr, "  decrypt disk image with key.bin\n");
    fprintf(stderr, "encdisk /rekey encdisk.img oldkey.bin newkey.bin\n");
    fprintf(stderr, "  change key of disk image\n");
    fprintf(stderr, "encdisk /mount encdisk.img key.bin 0 Z:\n");
    fprintf(stderr, "  mount image to Z:\n");
    fprintf(stderr, "encdisk /umount Z:\n");
    fprintf(stderr, "  unmount Z:\n");

    return -1;
}

static BOOL FullPath(const CHAR * src, SIZE_T dst_size, CHAR * dst)
{
    DWORD n = (DWORD)GetFullPathName(src, (DWORD)dst_size, dst, NULL);
    if(n == 0 || n > dst_size) return FALSE;
    dst[n] = 0;
    return TRUE;
}

INT __cdecl main(INT argc, CHAR* argv[])
{
    CHAR*                   Command;
    INT                     DeviceNumber;
    CHAR*                   FileName;
    CHAR*                   NewPrivateKey;
    CHAR*                   OldPrivateKey;
    CHAR*                   Option;
    CHAR                    DriveLetter;
    LARGE_INTEGER           RealFileSize;
    INT                     HardLevel = 9;
    CRYPT_XFUN              xfun;
    CHAR                    Path1[MAX_PATH];
    CHAR                    Path2[MAX_PATH];
    CHAR                    Path3[MAX_PATH];

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
    else if(argc == 5 && !strcmp(Command, "/rekey"))
    {
        FileName = argv[2];
        OldPrivateKey = argv[3];
        NewPrivateKey = argv[4];

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

        return EncDiskRekey(Path1, Path2, Path3);
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
    else if(argc == 4 && !strcmp(Command, "/encrypt"))
    {
        FileName = argv[2];
        NewPrivateKey = argv[3];
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        if(!FullPath(NewPrivateKey, sizeof(Path2), Path2)) 
        {
            return EncDiskSyntax();
        }
        return EncDiskEncrypt(Path1, Path2);
    }
    else if(argc == 4 && !strcmp(Command, "/decrypt"))
    {
        FileName = argv[2];
        NewPrivateKey = argv[3];
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        if(!FullPath(NewPrivateKey, sizeof(Path2), Path2)) 
        {
            return EncDiskSyntax();
        }
        return EncDiskDecrypt(Path1, Path2);
    }
    else if(argc == 6 && !strcmp(Command, "/mount"))
    {
        FileName = argv[2];
        NewPrivateKey = argv[3];
        DeviceNumber = atoi(argv[4]);
        DriveLetter = argv[5][0];
        if(!FullPath(FileName, sizeof(Path1), Path1)) 
        {
            return EncDiskSyntax();
        }

        if(!FullPath(NewPrivateKey, sizeof(Path2), Path2)) 
        {
            return EncDiskSyntax();
        }
        return EncDiskMount(Path1, Path2, DeviceNumber, DriveLetter);
    }
    else if(argc == 3 && !strcmp(Command, "/unmount"))
    {
        DriveLetter = argv[2][0];
        return EncDiskUmount(DriveLetter);
    }
    else if(argc == 3 && !strcmp(Command, "/status"))
    {
        DriveLetter = argv[2][0];
        return EncDiskStatus(DriveLetter);
    }
    else
    {
        return EncDiskSyntax();
    }
}
