#include "control.h"

INT EncDiskStatus(PDEVICE_NUMBER DeviceNumber)
{
    HANDLE Device = INVALID_HANDLE_VALUE;
    INT Ret = -1;

    if((Device = EncOpenDevice()) == INVALID_HANDLE_VALUE) {
        PrintLastError("EncDiskStatus:");
        goto err;
    }

    if(DumpDiskInfo(Device, DeviceNumber, TRUE) != 0) {
        goto err;
    }

    PrintMessage("%s\n", "EncDiskStatus: success!");

    Ret = 0;
err:
    if(Device != INVALID_HANDLE_VALUE) 
    {
        CloseHandle(Device);
        Device = INVALID_HANDLE_VALUE;
    }
    return Ret;
}