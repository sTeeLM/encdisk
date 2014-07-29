#include "control.h"

INT
EncDiskMount(
    const CHAR*                   FileName,
    const CHAR*                   PrivateKey,
    INT                     DeviceNumber,
    CHAR                    DriveLetter
)
{
    CHAR    VolumeName[] = "\\\\.\\ :";
    CHAR    DriveName[] = " :\\";
    CHAR    DeviceName[255];
    HANDLE  Device = INVALID_HANDLE_VALUE;
    DWORD   BytesReturned;
    POPEN_FILE_INFORMATION  OpenFileInformation = NULL;
    PCRYPT_CONTEXT Context = NULL;
    INT     Ret = -1;
    CHAR*   Pass = NULL;

    OpenFileInformation = 
            malloc(sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7);

    if(NULL == OpenFileInformation) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("EncDiskMount:");
        goto err;
    }

    memset(
        OpenFileInformation,
        0,
        sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7
    );

    if(NULL != PrivateKey) {
        // ask pass
        if((Pass = AskPass(CHECK_PASS, "Enter the password for the key:", NULL)) == NULL) {
            goto err;
        }

        if((Context = ReadKeyFile(PrivateKey, Pass)) == NULL) {
            goto err;
        }
        OpenFileInformation->IsEncrypt = TRUE;
    } else {
        OpenFileInformation->IsEncrypt = FALSE;
    }

    // \Device\Harddisk0\Partition1\path\filedisk.img
    if (FileName[0] == '\\' && FileName[1] == '\\') 
    {
        strcpy(OpenFileInformation->FileName, FileName);
    }
    else
    {
        strcpy(OpenFileInformation->FileName, "\\??\\");
        strcat(OpenFileInformation->FileName, FileName);
    }
    OpenFileInformation->DriveLetter = DriveLetter;

    VolumeName[4] = OpenFileInformation->DriveLetter;
    DriveName[0] = OpenFileInformation->DriveLetter;

    OpenFileInformation->FileNameLength = (USHORT)strlen(OpenFileInformation->FileName);

    if(NULL != PrivateKey) {
        memcpy(&OpenFileInformation->Key, &Context->key, sizeof(OpenFileInformation->Key));
    }

    Device = CreateFile(
        VolumeName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL
        );

    if (Device != INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_BUSY);
        PrintLastError(&VolumeName[4]);
        goto err;
    }

    sprintf(DeviceName, DEVICE_NAME_PREFIX "%u", DeviceNumber);

    if (!DefineDosDevice(
        DDD_RAW_TARGET_PATH,
        &VolumeName[4],
        DeviceName
        ))
    {
        PrintLastError(&VolumeName[4]);
        goto err;
    }

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
        DefineDosDevice(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
        goto err;
    }

    if (!DeviceIoControl(
        Device,
        IOCTL_ENC_DISK_OPEN_FILE,
        OpenFileInformation,
        sizeof(OPEN_FILE_INFORMATION) + OpenFileInformation->FileNameLength - 1,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        PrintLastError("EncDiskMount:");
        DefineDosDevice(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
        goto err;
    }

    SHChangeNotify(SHCNE_DRIVEADD, SHCNF_PATH, DriveName, NULL);

    PrintMessage("%s\n", "EncDiskMount: success!");

    Ret = 0;

err:
    if(Device != INVALID_HANDLE_VALUE) 
    {
        CloseHandle(Device);
        Device = INVALID_HANDLE_VALUE;
    }
    if(NULL != OpenFileInformation)
    {
        free(OpenFileInformation);
        OpenFileInformation = NULL;
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