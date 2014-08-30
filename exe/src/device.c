#include "control.h"
#include <stdio.h> 


ULONG
  RtlNtStatusToDosError(
    IN ULONG  Status
    ); 

HANDLE EncOpenDevice()
{
    HANDLE Device = INVALID_HANDLE_VALUE;
    CHAR DosDevice[MAX_PATH];
    CHAR Target[MAX_PATH];
    BOOL Found = FALSE;
    INT i;

    for(i = 0 ; i < ENC_MAX_DEVICE_CNT ; i ++) {
        _snprintf(DosDevice, sizeof(DosDevice), "Scsi%d:", i);
        if(QueryDosDevice(DosDevice, Target, sizeof(Target)) != 0) {
            if(!strncmp(Target, "\\Device\\Scsi\\phdskmnt", strlen("\\Device\\Scsi\\phdskmnt"))
                || !strncmp(Target, "\\Device\\RaidPort", strlen("\\Device\\RaidPort"))) {
                Found = TRUE;
                break;
            }
        }
    }

    if(Found) {
        _snprintf(DosDevice, sizeof(DosDevice), "\\\\?\\Scsi%d:", i);
        Device = CreateFile(
            DosDevice,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            NULL
            ); 
    }
    return Device;
}

BOOL GetDeviceNumber(const CHAR * arg, PDEVICE_NUMBER DeviceNumber)
{
    CHAR Buffer[10] = {0};


    if(!arg || strlen(arg) != 8)
        return FALSE;
    
    memcpy(Buffer, arg, 8);
    
    if(sscanf(Buffer, "%02x:%02x:%02x", 
        &DeviceNumber->Lun, 
        &DeviceNumber->TargetId, 
        &DeviceNumber->PathId) == 3) {
        return TRUE;
    }

    return FALSE;
}

INT DumpDiskInfo(HANDLE Device, PDEVICE_NUMBER DeviceNumber, BOOL Detail)
{
    PSRB_IMSCSI_CREATE_DATA SrbData = NULL;
    INT SrbDataLen;
    DWORD Error;
    INT Ret = -1;
    CHAR FileName[MAX_PATH + 64] = {0};

    SrbDataLen = sizeof(SRB_IMSCSI_CREATE_DATA) + (MAX_PATH + 64) * 2;

    if((SrbData = malloc(SrbDataLen)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("DumpDiskInfo:");
        goto err;   
    }

    memset(SrbData, 0, SrbDataLen);
    
    SrbData->SrbIoControl.HeaderLength = sizeof(SRB_IO_CONTROL);
    memcpy(SrbData->SrbIoControl.Signature, FUNCTION_SIGNATURE, strlen(FUNCTION_SIGNATURE));
    SrbData->SrbIoControl.Timeout = 0;
    SrbData->SrbIoControl.ControlCode = SMP_IMSCSI_QUERY_DEVICE;
    SrbData->SrbIoControl.ReturnCode = 0;
    SrbData->SrbIoControl.Length = SrbDataLen - sizeof(SRB_IO_CONTROL);

    if(EncCallSrb(Device, (PSRB_IO_CONTROL)SrbData, SrbDataLen, &Error) != 0) {
        SetLastError(Error);
        PrintLastError("EncDiskMount:");
        goto err;
    }

    if(WideToAscii(SrbData->FileName, FileName, sizeof(FileName)) != 0) {
        SetLastError(ERROR_INTERNAL_ERROR);
        PrintLastError("EncDiskMount:");
    }

    PrintMessage("%02x:%02x:%02x --> %s\n", 
        DeviceNumber->Lun, 
        DeviceNumber->TargetId,
        DeviceNumber->PathId,
        FileName
        );
    
    if(Detail) {
        PrintMessage("size:\n  %I64u\n", SrbData->DiskSize);
        PrintMessage("type:\n  %s\n", IMSCSI_ENCRYPT(SrbData->Flags) ? "encrypt disk" : "normal disk");
        PrintMessage("rw/ro:\n  %s\n", IMSCSI_READONLY(SrbData->Flags) ? "ro" : "rw");
        if(IMSCSI_ENCRYPT(SrbData->Flags)) {
            DumpKey(&SrbData->EncKey);
        }

    }

    Ret = 0;
 err:
    if(NULL != SrbData)
    {
        free(SrbData);
        SrbData = NULL;
    }
    return Ret;
}

INT EncCallSrb(HANDLE Device, PSRB_IO_CONTROL SrbData, DWORD SrbDataLen, DWORD * Error)
{
    DWORD BytesReturned;
    if (!DeviceIoControl(
        Device,
        IOCTL_SCSI_MINIPORT,
        SrbData,
        SrbDataLen,
        SrbData,
        SrbDataLen,
        &BytesReturned,
        NULL
        ))
    {
        *Error = GetLastError();
        return -1;
    }
    
    *Error = RtlNtStatusToDosError(SrbData->ReturnCode);
    return *Error == ERROR_SUCCESS ? 0 : -1;
}