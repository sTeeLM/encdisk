#include "service.h"

#include <winioctl.h>
#include <setupapi.h>

typedef struct _ENC_DEVICE_INFO
{
	CHAR	Volume;
	CHAR	FriendName[256];
	ULONG   DeviceNumber;
    ULONG   PartitionNumber;
}ENC_DEVICE_INFO, *PENC_DEVICE_INFO;

//53F56307-B6BF-11D0-94F2-00 A0 C9 1E FB 8B
GUID MY_GUID_DEVINTERFACE_DISK = 
{0x53f56307,0xb6bf,0x11d0,{0x94,0xf2,0x00,0xa0,0xc9,0x1e,0xfb,0x8b}};

static INT EncGetDeviceList(PENC_DEVICE_INFO DeviceList, INT ListSize)
{
	INT DeviceCnt = 0;

    CHAR DiskPath[5] = {0}; 
    CHAR DevicePath[10] = {0};        
	DWORD AllDisk = GetLogicalDrives();
	
	INT i = 0;
	DWORD BytesReturned = 0;
	STORAGE_DEVICE_NUMBER DeviceNum;
    UINT DriveType;

    memset(DeviceList, 0, sizeof(ENC_DEVICE_INFO) * ListSize);


	while (AllDisk && DeviceCnt < ListSize)
	{
		if ((AllDisk & 0x1) == 1)             
		{       
			_snprintf(DiskPath, sizeof(DiskPath) - 1, "%c:", 'A' + i);
			_snprintf(DevicePath,sizeof(DevicePath) - 1, "\\\\.\\%s", DiskPath);
            DriveType = GetDriveType(DiskPath);
            EncMonLog(ENC_LOG_DBG, "EncGetDeviceList: testing Disk %s, DriveType is %d\n", DiskPath, DriveType);
			if (DriveType == DRIVE_FIXED)                 
			{       
				// get this device id
				HANDLE hDevice = CreateFile(DevicePath, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                if(hDevice != INVALID_HANDLE_VALUE) {
                    if (DeviceIoControl(hDevice, IOCTL_STORAGE_GET_DEVICE_NUMBER, 
                                        NULL, 0, 
                                        &DeviceNum, sizeof(DeviceNum), 
                                        &BytesReturned, (LPOVERLAPPED) NULL))
                    {
                        DeviceList[DeviceCnt].Volume = 'A' + i;
                        DeviceList[DeviceCnt].DeviceNumber = DeviceNum.DeviceNumber;
                        DeviceList[DeviceCnt].PartitionNumber = DeviceNum.PartitionNumber;
                        EncMonLog(ENC_LOG_DBG, "EncGetDeviceList: Disk %s, DeviceNumber is %d, PartitionNumber is %d\n",
                            DiskPath, DeviceList[DeviceCnt].DeviceNumber, DeviceList[DeviceCnt].PartitionNumber);
                        DeviceCnt++;
                    } else {
                         EncMonLog(ENC_LOG_ERR, "DeviceIoControl: error on Disk %s error %d\n", DiskPath, GetLastError());
                    }
                    CloseHandle(hDevice);
                    hDevice = NULL;
                } else {
                    EncMonLog(ENC_LOG_ERR, "DeviceIoControl: CreateFile on Disk %s error %d\n", DiskPath, GetLastError());
                }
			}			
		}
		AllDisk = AllDisk >> 1;
		i++;
	}
	
	return DeviceCnt;
}

INT static EncGetDeviceFriendName(PENC_DEVICE_INFO DeviceList, INT ListSize)
{	
	INT i = 0;
	DWORD Res = 0;
	INT Ret = 0;
	HDEVINFO hDevInfo;  
	SP_DEVINFO_DATA DeviceInfoData = {sizeof(DeviceInfoData)}; 
    DWORD RequiredSize = 0;

	// get device class information handle
	hDevInfo = SetupDiGetClassDevs(&MY_GUID_DEVINTERFACE_DISK,0, 0, DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);       
	if (hDevInfo == INVALID_HANDLE_VALUE)     
	{         
		Res = GetLastError(); 
        EncMonLog(ENC_LOG_ERR, "EncGetDeviceFriendName: SetupDiGetClassDevs error %d\n", Res);
		return Ret;
	}  

	// enumerute device information
	
	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++)
	{		
		DWORD DataT;         
		CHAR FriendlyName[2046] = {0};         
		DWORD BufferSize = 2046;        
		DWORD ReqBufSize = 2046;  
        INT Index = 0;
        INT DeviceIndex = 0;
		SP_DEVICE_INTERFACE_DATA Did = {sizeof(Did)};
		PSP_DEVICE_INTERFACE_DETAIL_DATA Pdd = NULL;
	    DWORD BytesReturned = 0;
		STORAGE_DEVICE_NUMBER DeviceNum;
        HANDLE hDevice = NULL;

		// get device friendly name
		if (!SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_FRIENDLYNAME, &DataT, (LPBYTE)FriendlyName, BufferSize, &ReqBufSize))
		{
            EncMonLog(ENC_LOG_ERR, "EncGetDeviceFriendName: SetupDiGetDeviceRegistryProperty error %d\n", GetLastError());
			continue;
		}

		while(1)
		{
			// get device interface data
			if (!SetupDiEnumDeviceInterfaces(hDevInfo, &DeviceInfoData, &MY_GUID_DEVINTERFACE_DISK, Index ++, &Did))
			{
				Res = GetLastError();
				if( ERROR_NO_MORE_DEVICES == Res || ERROR_NO_MORE_ITEMS == Res) {
                    EncMonLog(ENC_LOG_DBG, "EncGetDeviceFriendName: SetupDiEnumDeviceInterfaces no more data\n");
					break;
                }
			}

			// get device interface detail size
			if (!SetupDiGetDeviceInterfaceDetail(hDevInfo, &Did, NULL, 0, &RequiredSize, NULL))
			{
				Res = GetLastError();
				if(ERROR_INSUFFICIENT_BUFFER == Res)
				{
					Pdd = (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(LPTR, RequiredSize);
					Pdd->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
				}
				else {
                    EncMonLog(ENC_LOG_ERR, "EncGetDeviceFriendName: SetupDiGetDeviceInterfaceDetail error %d\n", GetLastError());
					break;
                }
			}

			// get device interface detail
			if (!SetupDiGetDeviceInterfaceDetail(hDevInfo, &Did, Pdd, RequiredSize, NULL, NULL))
			{
				Res = GetLastError();
				LocalFree(Pdd);
				Pdd = NULL;
                EncMonLog(ENC_LOG_ERR, "EncGetDeviceFriendName: SetupDiGetDeviceInterfaceDetail error %d\n", GetLastError());
				break;
			}
			
			// test device number
            EncMonLog(ENC_LOG_DBG, "EncGetDeviceFriendName: testing on Device %s\n", Pdd->DevicePath);
			hDevice = CreateFile(Pdd->DevicePath, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (DeviceIoControl(hDevice, IOCTL_STORAGE_GET_DEVICE_NUMBER, 
								NULL, 0, 
								&DeviceNum, sizeof(DeviceNum), 
								&BytesReturned, (LPOVERLAPPED) NULL))
			{
				for (DeviceIndex = 0; DeviceIndex < ListSize; DeviceIndex++)
				{
					if (DeviceNum.DeviceNumber == DeviceList[DeviceIndex].DeviceNumber)
					{
                        strncpy(DeviceList[DeviceIndex].FriendName, FriendlyName, sizeof(DeviceList[DeviceIndex].FriendName) - 1);
						Ret ++;	
					}
				}
			}
			CloseHandle(hDevice);
			LocalFree(Pdd);
			Pdd = NULL;
		}
	}
	
	SetupDiDestroyDeviceInfoList(hDevInfo);
	return Ret;
}

static BOOL UnmountDisk(CHAR Volume, BOOL Forced)
{
    CHAR DiskPath[5] = {0};
    CHAR DevicePath[10] = {0};
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    DWORD   BytesReturned;
    BOOL    Locked = FALSE;
    BOOL    Ret = FALSE;

    _snprintf(DiskPath, sizeof(DiskPath) - 1, "%c:", Volume);
    _snprintf(DevicePath,sizeof(DevicePath) - 1, "\\\\.\\%s", DiskPath);

    EncMonLog(ENC_LOG_INF, "Unmounting Disk %c:, Forced = %d\n", Volume, Forced);

    hDevice = CreateFile(
        DevicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL);

    if(INVALID_HANDLE_VALUE == hDevice) {
        EncMonLog(ENC_LOG_ERR, "Disk %c: CreateFile error %x\n", Volume, GetLastError());
        goto err;
    }

    EncMonLog(ENC_LOG_DBG, "Flushing Disk %c:\n", Volume);

    if(!FlushFileBuffers(hDevice)) {
        EncMonLog(ENC_LOG_ERR, "Disk %c: FlushFileBuffers error %x\n", Volume, GetLastError());
        goto err;
    }

    EncMonLog(ENC_LOG_DBG, "Locking Disk %c:\n", Volume);
    if(!DeviceIoControl(
        hDevice,
        FSCTL_LOCK_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        EncMonLog(ENC_LOG_ERR, "Disk %c: FSCTL_LOCK_VOLUME error %x\n", Volume, GetLastError());
        if(!Forced) {
            goto err;
        }
    } else {
        Locked = TRUE;
    }


    EncMonLog(ENC_LOG_DBG, "Unmounting Disk %c:\n", Volume);
    if (!DeviceIoControl(
        hDevice,
        FSCTL_DISMOUNT_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        EncMonLog(ENC_LOG_ERR, "Disk %c: FSCTL_DISMOUNT_VOLUME error %x\n", Volume, GetLastError());
        goto err;
    }

    if(Locked) {
        EncMonLog(ENC_LOG_DBG, "Unlocking Disk %c:\n", Volume);
        if (!DeviceIoControl(
            hDevice,
            FSCTL_UNLOCK_VOLUME,
            NULL,
            0,
            NULL,
            0,
            &BytesReturned,
            NULL
            ))
        {
            EncMonLog(ENC_LOG_ERR, "Disk %c: FSCTL_UNLOCK_VOLUME error %x\n", Volume, GetLastError());
            goto err;
        }
    }

    EncMonLog(ENC_LOG_INF, "Unmounting Disk %c: complete!\n", Volume);
    Ret = TRUE;
err:
    if(INVALID_HANDLE_VALUE != hDevice) {
        CloseHandle(hDevice);
        hDevice = INVALID_HANDLE_VALUE;
    }
    return Ret;
}

ULONG
  RtlNtStatusToDosError(
    IN ULONG  Status
    );

static INT EncCallSrb(HANDLE Device, PSRB_IO_CONTROL SrbData, DWORD SrbDataLen, DWORD * Error)
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

static BOOL EncCheckDevice(HANDLE Device)
{
    SRB_IMSCSI_CHECK SrbData;
    INT SrbDataLen = sizeof(SrbData);
    DWORD Error;

    memset(&SrbData, 0, SrbDataLen);
    
    SrbData.SrbIoControl.HeaderLength = sizeof(SRB_IO_CONTROL);
    memcpy(SrbData.SrbIoControl.Signature, FUNCTION_SIGNATURE, strlen(FUNCTION_SIGNATURE));
    SrbData.SrbIoControl.Timeout = 0;
    SrbData.SrbIoControl.ControlCode = SMP_IMSCSI_CHECK;
    SrbData.SrbIoControl.ReturnCode = 0;
    SrbData.SrbIoControl.Length = SrbDataLen - sizeof(SRB_IO_CONTROL);

    if(EncCallSrb(Device, (PSRB_IO_CONTROL)&SrbData, SrbDataLen, &Error) != 0) {
       return FALSE;
    }

    return TRUE;
}

#define ENC_MAX_DEVICE_CNT 256

static HANDLE EncOpenDevice()
{
    HANDLE Device = INVALID_HANDLE_VALUE;
    CHAR DosDevice[MAX_PATH];
    CHAR Target[MAX_PATH];

    INT i;

    for(i = 0 ; i < ENC_MAX_DEVICE_CNT ; i ++) {
        _snprintf(DosDevice, sizeof(DosDevice), "Scsi%d:", i);
        if(QueryDosDevice(DosDevice, Target, sizeof(Target)) != 0) {
            if(!strncmp(Target, "\\Device\\Scsi\\phdskmnt", strlen("\\Device\\Scsi\\phdskmnt"))
                || !strncmp(Target, "\\Device\\RaidPort", strlen("\\Device\\RaidPort"))) {
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
                if(EncCheckDevice(Device)) {
                    break;
                } else {
                    CloseHandle(Device);
                    Device = INVALID_HANDLE_VALUE;
                }
            }
        }
    }

    return Device;
}



static VOID UnconnectAllDevice()
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    SRB_IMSCSI_REMOVE_DEVICE SrbData;
    INT SrbDataLen;
    DWORD Error;

    EncMonLog(ENC_LOG_DBG, "UnconnectAllDevice.\n"); 

    hDevice = EncOpenDevice();
    if(hDevice == INVALID_HANDLE_VALUE) {
        EncMonLog(ENC_LOG_ERR, "EncOpenDevice error %s.\n", GetLastError());
        goto err;
    }
    
    SrbDataLen = sizeof(SrbData);
    memset(&SrbData, 0, SrbDataLen);

    SrbData.SrbIoControl.HeaderLength = sizeof(SRB_IO_CONTROL);
    memcpy(SrbData.SrbIoControl.Signature, FUNCTION_SIGNATURE, strlen(FUNCTION_SIGNATURE));
    SrbData.SrbIoControl.Timeout = 0;
    SrbData.SrbIoControl.ControlCode = SMP_IMSCSI_REMOVE_DEVICE;
    SrbData.SrbIoControl.ReturnCode = 0;
    SrbData.SrbIoControl.Length = SrbDataLen - sizeof(SRB_IO_CONTROL);

    SrbData.DeviceNumber.LongNumber = IMSCSI_ALL_DEVICES;

    if(EncCallSrb(hDevice, (PSRB_IO_CONTROL)&SrbData, SrbDataLen, &Error) != 0) {
        SetLastError(Error);
        EncMonLog(ENC_LOG_ERR, "EncCallSrb error %s.\n", GetLastError());
        goto err;
    }
    EncMonLog(ENC_LOG_DBG, "UnconnectAllDevice complete.\n"); 
err:
    if(hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        hDevice = INVALID_HANDLE_VALUE;
    }
    return;
}

BOOL EncUnmountDisk(BOOL Forced)
{
    ENC_DEVICE_INFO DeviceList[256];
    INT DeviceCnt = 256;
    INT Index;
    BOOL Ret = TRUE;

    DeviceCnt = EncGetDeviceList(DeviceList, DeviceCnt);
    EncMonLog(ENC_LOG_DBG, "EncGetDeviceList return %d\n", DeviceCnt);

    DeviceCnt = EncGetDeviceFriendName(DeviceList, DeviceCnt);
    EncMonLog(ENC_LOG_DBG, "EncGetDeviceFriendName return %d\n", DeviceCnt);
    
    
    for(Index = 0 ; Index < DeviceCnt; Index ++) {
        EncMonLog(ENC_LOG_DBG, "Disk %c %d [%s]\n", 
            DeviceList[Index].Volume,
            DeviceList[Index].DeviceNumber,
            DeviceList[Index].FriendName
            );
        if(!strncmp(DeviceList[Index].FriendName, "Mad Cat", 7)) {
            if(!UnmountDisk(DeviceList[Index].Volume, Forced)) {
                Ret = FALSE;
            }
        }
    }

    if(Ret) {
        UnconnectAllDevice();
    }

    return Ret;
}
