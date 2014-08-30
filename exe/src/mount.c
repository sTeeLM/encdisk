#include "control.h"




INT
EncDiskMount(
    const CHAR* FileName,
    const CHAR* PrivateKey,
    BOOL        RO
)
{
    CHAR * Pass = NULL;
    PCRYPT_CONTEXT Context = NULL;
    HANDLE Device = INVALID_HANDLE_VALUE;
    PSRB_IMSCSI_CREATE_DATA SrbData = NULL;
    CHAR FileNameBuffer[MAX_PATH + 64];
    INT SrbDataLen;
    INT Ret = -1;
    DWORD  Error;


    if(NULL != PrivateKey) {
        // ask pass
        if((Pass = AskPass(CHECK_PASS, "Enter the password for the key:", NULL)) == NULL) {
            goto err;
        }

        if((Context = ReadKeyFile(PrivateKey, Pass)) == NULL) {
            goto err;
        }

    }

    if (FileName[0] == '\\' && FileName[1] == '\\') 
    {
        strcpy(FileNameBuffer, FileName);
    }
    else
    {
        strcpy(FileNameBuffer, "\\??\\");
        strcat(FileNameBuffer, FileName);
    }

    SrbDataLen = GetWideLength(FileNameBuffer);
    
    if(SrbDataLen <= 0) {
        SetLastError(ERROR_INTERNAL_ERROR);
        PrintLastError("EncDiskMount:");
        goto err;
    }

    SrbDataLen = sizeof(SRB_IMSCSI_CREATE_DATA) + SrbDataLen * sizeof(WCHAR);

    if((SrbData = malloc(SrbDataLen + sizeof(WCHAR))) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("EncDiskMount:");
        goto err;   
    }

    memset(SrbData, 0, SrbDataLen);
    
    SrbData->SrbIoControl.HeaderLength = sizeof(SRB_IO_CONTROL);
    memcpy(SrbData->SrbIoControl.Signature, FUNCTION_SIGNATURE, strlen(FUNCTION_SIGNATURE));
    SrbData->SrbIoControl.Timeout = 0;
    SrbData->SrbIoControl.ControlCode = SMP_IMSCSI_CREATE_DEVICE;
    SrbData->SrbIoControl.ReturnCode = 0;
    SrbData->SrbIoControl.Length = SrbDataLen - sizeof(SRB_IO_CONTROL);

    SrbData->DeviceNumber.LongNumber = IMSCSI_AUTO_DEVICE_NUMBER;
    SrbData->DiskSize.QuadPart = 0;
    SrbData->BytesPerSector = CRYPT_SECTOR_SIZE;
    SrbData->ImageOffset.QuadPart = 0;
    SrbData->Flags = IMSCSI_TYPE_FILE | IMSCSI_DEVICE_TYPE_HD;
    SrbData->FileNameLength = GetWideLength(FileNameBuffer) * sizeof(WCHAR);

    if(AsciiToWide(FileNameBuffer, SrbData->FileName, SrbData->FileNameLength / sizeof(WCHAR) + 1) != 0) {
        SetLastError(ERROR_INTERNAL_ERROR);
        PrintLastError("EncDiskMount:");
        goto err;
    }


    if(Context) {
        SrbData->Flags |= IMSCSI_OPTION_ENCRYPT;
        memcpy(&SrbData->EncKey, &Context->key, sizeof(SrbData->EncKey));
    }

    if(RO) {
        SrbData->Flags |= IMSCSI_OPTION_RO;
    }


    if((Device = EncOpenDevice()) == INVALID_HANDLE_VALUE) {
        PrintLastError("EncDiskMount:");
        goto err;
    }

    if(EncCallSrb(Device, (PSRB_IO_CONTROL)SrbData, SrbDataLen, &Error) != 0) {
        SetLastError(Error);
        PrintLastError("EncDiskMount:");
        goto err;
    }
    

    PrintMessage("%s\n", "EncDiskMount: success!");

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
    if(NULL != Pass)
    {
        free(Pass);
        Pass = NULL;
    }
    if(NULL != Context)
    {
        free(Context);
        Context = NULL;
    }
    return Ret;
}