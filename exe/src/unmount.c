#include "control.h"

INT EncDiskUmount(CHAR DriveLetter, BOOLEAN Force)
{
    CHAR    VolumeName[] = "\\\\.\\ :";
    CHAR    DriveName[] = " :\\";
    HANDLE  Device = INVALID_HANDLE_VALUE;
    DWORD   BytesReturned;

    VolumeName[4] = DriveLetter;
    DriveName[0] = DriveLetter;

    Device = CreateFile(
        VolumeName,
        GENERIC_READ | GENERIC_WRITE,
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

    if (!DeviceIoControl(
        Device,
        FSCTL_LOCK_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ) && !Force)
    {
        PrintLastError(&VolumeName[4]);
        CloseHandle(Device);
        return -1;
    }

    if(!FlushFileBuffers(Device)) {
        PrintLastError(&VolumeName[4]);
        CloseHandle(Device);
        return -1;
    }

    if (!DeviceIoControl(
        Device,
        IOCTL_ENC_DISK_CLOSE_FILE,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        PrintLastError("EncDiskUmount:");
        CloseHandle(Device);
        return -1;
    }

    if (!DeviceIoControl(
        Device,
        FSCTL_DISMOUNT_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        PrintLastError(&VolumeName[4]);
        CloseHandle(Device);
        return -1;
    }

    if (!DeviceIoControl(
        Device,
        FSCTL_UNLOCK_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ) && !Force)
    {
        PrintLastError(&VolumeName[4]);
        CloseHandle(Device);
        return -1;
    }

    CloseHandle(Device);

    if (!DefineDosDevice(
        DDD_REMOVE_DEFINITION,
        &VolumeName[4],
        NULL
        ) && !Force)
    {
        PrintLastError(&VolumeName[4]);
        return -1;
    }

    SHChangeNotify(SHCNE_DRIVEREMOVED, SHCNF_PATH, DriveName, NULL);

    PrintMessage("%s\n", "EncDiskUmount: success!");

    return 0;
}