#include "control.h"

INT EncDiskUmount(PDEVICE_NUMBER DeviceNumber)
{
    HANDLE Device = INVALID_HANDLE_VALUE;
    INT Ret = -1;
    SRB_IMSCSI_REMOVE_DEVICE SrbData;
    INT SrbDataLen;
    DWORD Error;


    if((Device = EncOpenDevice()) == INVALID_HANDLE_VALUE) {
        PrintLastError("EncDiskMount:");
        goto err;
    }    

    memset(&SrbData, 0, sizeof(SrbData));

    SrbDataLen = sizeof(SrbData);

    SrbData.SrbIoControl.HeaderLength = sizeof(SRB_IO_CONTROL);
    memcpy(SrbData.SrbIoControl.Signature, FUNCTION_SIGNATURE, strlen(FUNCTION_SIGNATURE));
    SrbData.SrbIoControl.Timeout = 0;
    SrbData.SrbIoControl.ControlCode = SMP_IMSCSI_REMOVE_DEVICE;
    SrbData.SrbIoControl.ReturnCode = 0;
    SrbData.SrbIoControl.Length = SrbDataLen - sizeof(SRB_IO_CONTROL);

    SrbData.DeviceNumber.LongNumber = DeviceNumber->LongNumber;

    if(EncCallSrb(Device, (PSRB_IO_CONTROL)&SrbData, SrbDataLen, &Error) != 0) {
        SetLastError(Error);
        PrintLastError("EncDiskUmount:");
        goto err;
    }

    PrintMessage("%s\n", "EncDiskUmount: success!");

    Ret = 0;
err:
    if(Device != INVALID_HANDLE_VALUE) 
    {
        CloseHandle(Device);
        Device = INVALID_HANDLE_VALUE;
    }
    return Ret;
}