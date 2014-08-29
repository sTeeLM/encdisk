#include "control.h"

INT EncDiskList()
{
    HANDLE Device = INVALID_HANDLE_VALUE;
    INT Ret = -1;
    PSRB_IMSCSI_QUERY_ADAPTER SrbData;
    INT SrbDataLen;
    DWORD Error;
    ULONG Index;


    if((Device = EncOpenDevice()) == INVALID_HANDLE_VALUE) {
        PrintLastError("EncDiskList:");
        goto err;
    }    

    SrbDataLen = sizeof(SRB_IMSCSI_QUERY_ADAPTER) + sizeof(DEVICE_NUMBER) * ENC_MAX_DEVICE_CNT;

    if((SrbData = malloc(SrbDataLen)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("EncDiskList:");
        goto err;   
    }

    memset(SrbData, 0, sizeof(SrbData));

    SrbData->SrbIoControl.HeaderLength = sizeof(SRB_IO_CONTROL);
    memcpy(SrbData->SrbIoControl.Signature, FUNCTION_SIGNATURE, strlen(FUNCTION_SIGNATURE));
    SrbData->SrbIoControl.Timeout = 0;
    SrbData->SrbIoControl.ControlCode = SMP_IMSCSI_QUERY_ADAPTER;
    SrbData->SrbIoControl.ReturnCode = 0;
    SrbData->SrbIoControl.Length = SrbDataLen - sizeof(SRB_IO_CONTROL);

    SrbData->NumberOfDevices = ENC_MAX_DEVICE_CNT;

    if(EncCallSrb(Device, (PSRB_IO_CONTROL)SrbData, SrbDataLen, &Error) != 0) {
        SetLastError(Error);
        PrintLastError("EncDiskList:");
        goto err;
    }

    for(Index = 0 ; Index < SrbData->NumberOfDevices; Index ++) {
        DumpDiskInfo(Device, &SrbData->DeviceList[Index], FALSE);
    }

    PrintMessage("%s\n", "EncDiskUmount: success!");

    Ret = 0;
err:
    if(Device != INVALID_HANDLE_VALUE) 
    {
        CloseHandle(Device);
        Device = INVALID_HANDLE_VALUE;
    }
    if(NULL != SrbData)
    {
        free(SrbData);
        SrbData = NULL;
    }
    return Ret;
}