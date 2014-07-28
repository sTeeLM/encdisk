#include "control.h"

void DumpKey(PCRYPT_KEY key)
{
    INT i;
    PrintMessage("signature: ");
    for(i = 0 ; i < sizeof(key->signature); i ++) {
        PrintMessage("%02X", key->signature[i]);
    }
    PrintMessage("\n");
    PrintMessage("algorithm:\n");
    for(i = 0 ; i < _countof(key->algo); i ++) {
        PrintMessage("  %s\n", CryptAlgoName(key->algo[i]));
    }
}

INT EncDiskStatus(CHAR DriveLetter)
{
    CHAR                    VolumeName[] = "\\\\.\\ :";
    HANDLE                  Device;
    POPEN_FILE_INFORMATION  OpenFileInformation;
    DWORD                   BytesReturned;

    VolumeName[4] = DriveLetter;

    Device = CreateFile(
        VolumeName,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL
        );

    if (Device == INVALID_HANDLE_VALUE)
    {
        PrintLastError(&VolumeName[4]);
        return -1;
    }

    OpenFileInformation = malloc(sizeof(OPEN_FILE_INFORMATION) + MAX_PATH);

    if (!DeviceIoControl(
        Device,
        IOCTL_ENC_DISK_QUERY_FILE,
        NULL,
        0,
        OpenFileInformation,
        sizeof(OPEN_FILE_INFORMATION) + MAX_PATH,
        &BytesReturned,
        NULL
        ))
    {
        PrintLastError(&VolumeName[4]);
        CloseHandle(Device);
        free(OpenFileInformation);
        return -1;
    }

    if (BytesReturned < sizeof(OPEN_FILE_INFORMATION))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        PrintLastError(&VolumeName[4]);
        CloseHandle(Device);
        free(OpenFileInformation);
        return -1;
    }

    CloseHandle(Device);

    PrintMessage("%c: %.*s %I64u bytes\n",
        DriveLetter,
        OpenFileInformation->FileNameLength,
        OpenFileInformation->FileName,
        OpenFileInformation->RealFileSize
        );

    DumpKey(&OpenFileInformation->Key);

    free(OpenFileInformation);

    PrintMessage("%s\n", "EncDiskStatus: success!");

    return 0;
}