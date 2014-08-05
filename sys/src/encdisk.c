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

#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <mountmgr.h>
#include <ntverp.h>
#include <wdmsec.h>
#include <limits.h>
//
// We include some stuff from newer DDK:s here so that one
// version of the driver for all versions of Windows can
// be compiled with the Windows NT 4.0 DDK.
//

#ifndef INVALID_HANDLE_VALUE
    #define INVALID_HANDLE_VALUE (HANDLE)(-1)
#endif

#if (VER_PRODUCTBUILD < 2195)

#define FILE_DEVICE_MASS_STORAGE            0x0000002d
#define IOCTL_STORAGE_CHECK_VERIFY2         CTL_CODE(IOCTL_STORAGE_BASE, 0x0200, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000

#endif

#if (VER_PRODUCTBUILD < 2600)

#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_GET_LENGTH_INFO          CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)



typedef enum _PARTITION_STYLE {
    PARTITION_STYLE_MBR,
    PARTITION_STYLE_GPT
} PARTITION_STYLE;

typedef unsigned __int64 ULONG64, *PULONG64;

typedef struct _PARTITION_INFORMATION_MBR {
    UCHAR   PartitionType;
    BOOLEAN BootIndicator;
    BOOLEAN RecognizedPartition;
    ULONG   HiddenSectors;
} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;

typedef struct _PARTITION_INFORMATION_GPT {
    GUID    PartitionType;
    GUID    PartitionId;
    ULONG64 Attributes;
    WCHAR   Name[36];
} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;

typedef struct _PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    LARGE_INTEGER   StartingOffset;
    LARGE_INTEGER   PartitionLength;
    ULONG           PartitionNumber;
    BOOLEAN         RewritePartition;
    union {
        PARTITION_INFORMATION_MBR Mbr;
        PARTITION_INFORMATION_GPT Gpt;
    };
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;

typedef struct _GET_LENGTH_INFORMATION {
    LARGE_INTEGER Length;
} GET_LENGTH_INFORMATION, *PGET_LENGTH_INFORMATION;

#endif // (VER_PRODUCTBUILD < 2600)

//
// We include some stuff from ntifs.h here so that
// the driver can be compiled with only the DDK.
//

#define TOKEN_SOURCE_LENGTH 8

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE;

typedef struct _TOKEN_SOURCE {
    CCHAR   SourceName[TOKEN_SOURCE_LENGTH];
    LUID    SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

typedef struct _TOKEN_CONTROL {
    LUID            TokenId;
    LUID            AuthenticationId;
    LUID            ModifiedId;
    TOKEN_SOURCE    TokenSource;
} TOKEN_CONTROL, *PTOKEN_CONTROL;

typedef struct _SECURITY_CLIENT_CONTEXT {
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    PACCESS_TOKEN               ClientToken;
    BOOLEAN                     DirectlyAccessClientToken;
    BOOLEAN                     DirectAccessEffectiveOnly;
    BOOLEAN                     ServerIsRemote;
    TOKEN_CONTROL               ClientTokenControl;
} SECURITY_CLIENT_CONTEXT, *PSECURITY_CLIENT_CONTEXT;

#define PsDereferenceImpersonationToken(T)  \
            {if (ARGUMENT_PRESENT(T)) {     \
                (ObDereferenceObject((T))); \
            } else {                        \
                ;                           \
            }                               \
}

#define PsDereferencePrimaryToken(T) (ObDereferenceObject((T)))

NTKERNELAPI
VOID
PsRevertToSelf (
    VOID
);

NTKERNELAPI
NTSTATUS
SeCreateClientSecurity (
    IN PETHREAD                     Thread,
    IN PSECURITY_QUALITY_OF_SERVICE QualityOfService,
    IN BOOLEAN                      RemoteClient,
    OUT PSECURITY_CLIENT_CONTEXT    ClientContext
);

#define SeDeleteClientSecurity(C)  {                                           \
            if (SeTokenType((C)->ClientToken) == TokenPrimary) {               \
                PsDereferencePrimaryToken( (C)->ClientToken );                 \
            } else {                                                           \
                PsDereferenceImpersonationToken( (C)->ClientToken );           \
            }                                                                  \
}

NTKERNELAPI
VOID
SeImpersonateClient (
    IN PSECURITY_CLIENT_CONTEXT ClientContext,
    IN PETHREAD                 ServerThread OPTIONAL
);

NTKERNELAPI
TOKEN_TYPE
SeTokenType (
    IN PACCESS_TOKEN Token
);

#ifndef SE_IMPERSONATE_PRIVILEGE
#define SE_IMPERSONATE_PRIVILEGE        (29L)
#endif

#define TOKEN_ASSIGN_PRIMARY            (0x0001)
#define TOKEN_DUPLICATE                 (0x0002)
#define TOKEN_IMPERSONATE               (0x0004)
#define TOKEN_QUERY                     (0x0008)
#define TOKEN_QUERY_SOURCE              (0x0010)
#define TOKEN_ADJUST_PRIVILEGES         (0x0020)
#define TOKEN_ADJUST_GROUPS             (0x0040)
#define TOKEN_ADJUST_DEFAULT            (0x0080)

#define TOKEN_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED |\
                          TOKEN_ASSIGN_PRIMARY     |\
                          TOKEN_DUPLICATE          |\
                          TOKEN_IMPERSONATE        |\
                          TOKEN_QUERY              |\
                          TOKEN_QUERY_SOURCE       |\
                          TOKEN_ADJUST_PRIVILEGES  |\
                          TOKEN_ADJUST_GROUPS      |\
                          TOKEN_ADJUST_DEFAULT)

typedef struct _TOKEN_PRIVILEGES {
    ULONG               PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcessToken (
    IN HANDLE       ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    OUT PHANDLE     TokenHandle
);

NTSYSAPI
NTSTATUS
NTAPI
NtAdjustPrivilegesToken (
    IN HANDLE               TokenHandle,
    IN BOOLEAN              DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES    NewState,
    IN ULONG                BufferLength,
    OUT PTOKEN_PRIVILEGES   PreviousState OPTIONAL,
    OUT PULONG              ReturnLength
);

#define FSCTL_SET_SPARSE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

NTSYSAPI
NTSTATUS
NTAPI
ZwFsControlFile (
    IN HANDLE               FileHandle,
    IN HANDLE               Event OPTIONAL,
    IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
    IN PVOID                ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    IN ULONG                FsControlCode,
    IN PVOID                InputBuffer OPTIONAL,
    IN ULONG                InputBufferLength,
    OUT PVOID               OutputBuffer OPTIONAL,
    IN ULONG                OutputBufferLength
);

//
// For backward compatibility with Windows NT 4.0 by Bruce Engle.
//
#ifndef MmGetSystemAddressForMdlSafe
#define MmGetSystemAddressForMdlSafe(MDL, PRIORITY) MmGetSystemAddressForMdlPrettySafe(MDL)

PVOID
MmGetSystemAddressForMdlPrettySafe (
    PMDL Mdl
    )
{
    CSHORT  MdlMappingCanFail;
    PVOID   MappedSystemVa;

    MdlMappingCanFail = Mdl->MdlFlags & MDL_MAPPING_CAN_FAIL;

    Mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

    MappedSystemVa = MmGetSystemAddressForMdl(Mdl);

    if (MdlMappingCanFail == 0)
    {
        Mdl->MdlFlags &= ~MDL_MAPPING_CAN_FAIL;
    }

    return MappedSystemVa;
}
#endif

#include "encdisk.h"

#define PARAMETER_KEY           L"\\Parameters"

#define NUMBEROFDEVICES_VALUE   L"NumberOfDevices"

#define DEFAULT_NUMBEROFDEVICES 4

#define SECTOR_SIZE             512

#define TOC_DATA_TRACK          0x04

HANDLE dir_handle;


typedef struct _CLUSTER_BUFFER{
    UCHAR                       plain[CRYPT_CLUSTER_SIZE];
    UCHAR                       cipher[CRYPT_CLUSTER_SIZE];
    BOOLEAN                     dirty;
    BOOLEAN                     valid;
    ULONGLONG                   index;
}CLUSTER_BUFFER, *PCLUSTER_BUFFER;

typedef struct _DEVICE_EXTENSION {
    BOOLEAN                     media_in_device;
    BOOLEAN                     is_encrypt;
    HANDLE                      file_handle;
    ANSI_STRING                 file_name;
    LARGE_INTEGER               file_size;
    PSECURITY_CLIENT_CONTEXT    security_client_context;
    LIST_ENTRY                  list_head;
    KSPIN_LOCK                  list_lock;
    KEVENT                      request_event;
    PVOID                       thread_pointer;
    BOOLEAN                     terminate_thread;
    CRYPT_CONTEXT               context;
    CLUSTER_BUFFER              cache;
    ULONG                       number;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS
DriverEntry (
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath
);

NTSTATUS
EncDiskCreateDevice (
    IN PDRIVER_OBJECT   DriverObject,
    IN ULONG            Number,
    IN DEVICE_TYPE      DeviceType
);

VOID
EncDiskUnload (
    IN PDRIVER_OBJECT   DriverObject
);

PDEVICE_OBJECT
EncDiskDeleteDevice (
    IN PDEVICE_OBJECT   DeviceObject
);

NTSTATUS
EncDiskCreateClose (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
EncDiskReadWrite (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
EncDiskDeviceControl (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

VOID
EncDiskThread (
    IN PVOID            Context
);

NTSTATUS
EncDiskOpenFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
EncDiskCloseFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
EncDiskAdjustPrivilege (
    IN ULONG            Privilege,
    IN BOOLEAN          Enable
);

int swprintf(wchar_t *, const wchar_t *, ...);

VOID 
MyRtlFillMemory(
    IN VOID * s, 
    IN INT c,
    IN SIZE_T n
);
VOID 
  MyRtlZeroMemory(
    IN VOID  *Destination,
    IN SIZE_T  Length
    );

VOID 
  MyRtlCopyMemory(
    IN VOID  *Destination,
    IN CONST VOID  *Source,
    IN SIZE_T  Length
    );

INT 
  MyRtlCompareMemory(
    IN CONST VOID  *Source1,
    IN CONST VOID  *Source2,
    IN SIZE_T  Length
    );

#pragma code_seg("INIT")

NTSTATUS
DriverEntry (
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath
    )
{
    UNICODE_STRING              parameter_path;
    RTL_QUERY_REGISTRY_TABLE    query_table[2];
    ULONG                       n_devices;
    NTSTATUS                    status;
    UNICODE_STRING              device_dir_name;
    OBJECT_ATTRIBUTES           object_attributes;
    ULONG                       n;
    USHORT                      n_created_devices;
    CRYPT_XFUN                  xfun;
    /* initialize encrypt */

    KdPrint(("EncDisk: DriverEntry, version %s\n", ENC_DISK_VERSION_STR));

    RtlZeroMemory(&xfun, sizeof(xfun));

    xfun.xzeromem = MyRtlZeroMemory;
    xfun.xmemcpy  = MyRtlCopyMemory;
    xfun.xmemcmp  = MyRtlCompareMemory;
    xfun.xmemset  = MyRtlFillMemory;

    if(CryptInitialize(&xfun) != CRYPT_OK)
    {
        KdPrint(("EncDisk: DriverEntry, CryptInitialize error\n"));
        return STATUS_INTERNAL_ERROR;
    }

    parameter_path.Length = 0;

    parameter_path.MaximumLength = RegistryPath->Length + sizeof(PARAMETER_KEY);

    parameter_path.Buffer = (PWSTR) ExAllocatePool(PagedPool, parameter_path.MaximumLength);

    if (parameter_path.Buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(&parameter_path, RegistryPath);

    RtlAppendUnicodeToString(&parameter_path, PARAMETER_KEY);

    RtlZeroMemory(&query_table[0], sizeof(query_table));

    query_table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
    query_table[0].Name = NUMBEROFDEVICES_VALUE;
    query_table[0].EntryContext = &n_devices;

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        parameter_path.Buffer,
        &query_table[0],
        NULL,
        NULL
        );

    ExFreePool(parameter_path.Buffer);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("EncDisk: Query registry failed, using default values.\n"));
        n_devices = DEFAULT_NUMBEROFDEVICES;
    }

    KdPrint(("EncDisk: DriverEntry n_devices is %u\n", n_devices));

    RtlInitUnicodeString(&device_dir_name, DEVICE_DIR_NAME);

    InitializeObjectAttributes(
        &object_attributes,
        &device_dir_name,
        OBJ_PERMANENT,
        NULL,
        NULL
        );

    status = ZwCreateDirectoryObject(
        &dir_handle,
        DIRECTORY_ALL_ACCESS,
        &object_attributes
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ZwMakeTemporaryObject(dir_handle);

    for (n = 0, n_created_devices = 0; n < n_devices; n++)
    {
        status = EncDiskCreateDevice(DriverObject, n, FILE_DEVICE_DISK);

        if (NT_SUCCESS(status))
        {
            KdPrint(("EncDisk: DriverEntry device %u create success \n", n));
            n_created_devices++;
        }
    }

    if (n_created_devices == 0)
    {
        ZwClose(dir_handle);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = EncDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = EncDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = EncDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = EncDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EncDiskDeviceControl;

    DriverObject->DriverUnload = EncDiskUnload;

    return STATUS_SUCCESS;
}

NTSTATUS
EncDiskCreateDevice (
    IN PDRIVER_OBJECT   DriverObject,
    IN ULONG            Number,
    IN DEVICE_TYPE      DeviceType
    )
{
    WCHAR               device_name_buffer[MAXIMUM_FILENAME_LENGTH];
    UNICODE_STRING      device_name;
    NTSTATUS            status;
    PDEVICE_OBJECT      device_object;
    PDEVICE_EXTENSION   device_extension;
    HANDLE              thread_handle;
    UNICODE_STRING      sddl;

    ASSERT(DriverObject != NULL);

    KdPrint(("EncDisk: EncDiskCreateDevice device %u\n", Number));

    swprintf(
        device_name_buffer,
        DEVICE_NAME_PREFIX L"%u",
        Number);

    RtlInitUnicodeString(&device_name, device_name_buffer);

    RtlInitUnicodeString(&sddl, _T("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)"));

    status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        &device_name,
        DeviceType,
        0,
        FALSE,
        &sddl,
        NULL,
        &device_object
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    device_object->Flags |= DO_DIRECT_IO;

    device_extension = (PDEVICE_EXTENSION) device_object->DeviceExtension;

    RtlZeroMemory(device_extension, sizeof(DEVICE_EXTENSION));

    device_extension->media_in_device = FALSE;

    device_extension->is_encrypt = FALSE;

    device_extension->number = Number;

    device_extension->file_handle = INVALID_HANDLE_VALUE;

    InitializeListHead(&device_extension->list_head);

    KeInitializeSpinLock(&device_extension->list_lock);

    KeInitializeEvent(
        &device_extension->request_event,
        SynchronizationEvent,
        FALSE
        );

    device_extension->terminate_thread = FALSE;

    status = PsCreateSystemThread(
        &thread_handle,
        (ACCESS_MASK) 0L,
        NULL,
        NULL,
        NULL,
        EncDiskThread,
        device_object
        );

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(device_object);
        return status;
    }

    status = ObReferenceObjectByHandle(
        thread_handle,
        THREAD_ALL_ACCESS,
        NULL,
        KernelMode,
        &device_extension->thread_pointer,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        ZwClose(thread_handle);

        device_extension->terminate_thread = TRUE;

        KeSetEvent(
            &device_extension->request_event,
            (KPRIORITY) 0,
            FALSE
            );

        IoDeleteDevice(device_object);

        return status;
    }

    ZwClose(thread_handle);

    return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")

VOID
EncDiskUnload (
    IN PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT device_object;

    PAGED_CODE();

    KdPrint(("EncDisk: EncDiskUnload\n"));

    device_object = DriverObject->DeviceObject;

    while (device_object)
    {
        device_object = EncDiskDeleteDevice(device_object);
    }

    CryptCleanup();

    ZwClose(dir_handle);
}

PDEVICE_OBJECT
EncDiskDeleteDevice (
    IN PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_EXTENSION   device_extension;
    PDEVICE_OBJECT      next_device_object;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    KdPrint(("EncDisk: EncDiskDeleteDevice %u\n", device_extension->number));

    device_extension->terminate_thread = TRUE;

    KeSetEvent(
        &device_extension->request_event,
        (KPRIORITY) 0,
        FALSE
        );

    KeWaitForSingleObject(
        device_extension->thread_pointer,
        Executive,
        KernelMode,
        FALSE,
        NULL
        );

    ObDereferenceObject(device_extension->thread_pointer);

    if (device_extension->security_client_context != NULL)
    {
        SeDeleteClientSecurity(device_extension->security_client_context);
        ExFreePool(device_extension->security_client_context);
    }

    next_device_object = DeviceObject->NextDevice;

    IoDeleteDevice(DeviceObject);

    return next_device_object;
}

NTSTATUS
EncDiskCreateClose (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION   device_extension;
    PAGED_CODE();

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    KdPrint(("EncDiskCreateClose called on device %u\n", device_extension->number));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

#pragma code_seg()
VOID 
MyRtlFillMemory(
    IN VOID * s, 
    IN INT c,
    IN SIZE_T n
)
{
    RtlFillMemory(s, n, c);
}

VOID 
  MyRtlZeroMemory(
    IN VOID  *Destination,
    IN SIZE_T  Length
    )
{
    RtlZeroMemory(Destination, Length);
}

VOID 
  MyRtlCopyMemory(
    IN VOID  *Destination,
    IN CONST VOID  *Source,
    IN SIZE_T  Length
    )
{
    RtlCopyMemory(Destination, Source, Length);
}

INT 
  MyRtlCompareMemory(
    IN CONST VOID  *Source1,
    IN CONST VOID  *Source2,
    IN SIZE_T  Length
    )
{
    return (INT)RtlCompareMemory(Source1, Source2, Length);
}

NTSTATUS
EncDiskReadWrite (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION   device_extension;
    PIO_STACK_LOCATION  io_stack;

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    KdPrint(("EncDiskReadWrite called on device %u\n", device_extension->number));

    if (!device_extension->media_in_device)
    {
        Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_NO_MEDIA_IN_DEVICE;
    }

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    if (io_stack->Parameters.Read.Length == 0)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    IoMarkIrpPending(Irp);

    ExInterlockedInsertTailList(
        &device_extension->list_head,
        &Irp->Tail.Overlay.ListEntry,
        &device_extension->list_lock
        );

    KeSetEvent(
        &device_extension->request_event,
        (KPRIORITY) 0,
        FALSE
        );

    return STATUS_PENDING;
}

NTSTATUS
EncDiskDeviceControl (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION   device_extension;
    PIO_STACK_LOCATION  io_stack;
    NTSTATUS            status;

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    if (!device_extension->media_in_device &&
        io_stack->Parameters.DeviceIoControl.IoControlCode !=
        IOCTL_ENC_DISK_OPEN_FILE)
    {
        Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_NO_MEDIA_IN_DEVICE;
    }

    switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ENC_DISK_OPEN_FILE:
        {
            SECURITY_QUALITY_OF_SERVICE security_quality_of_service;

            if (device_extension->media_in_device)
            {
                KdPrint(("EncDisk: IOCTL_ENC_DISK_OPEN_FILE: Media already opened\n"));

                status = STATUS_INVALID_DEVICE_REQUEST;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(OPEN_FILE_INFORMATION))
            {
                KdPrint(("EncDisk: IOCTL_ENC_DISK_OPEN_FILE: InputBufferLength 1\n"));
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(OPEN_FILE_INFORMATION) +
                ((POPEN_FILE_INFORMATION)Irp->AssociatedIrp.SystemBuffer)->FileNameLength -
                sizeof(UCHAR))
            {
                KdPrint(("EncDisk: IOCTL_ENC_DISK_OPEN_FILE: InputBufferLength 2\n"));
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (device_extension->security_client_context != NULL)
            {
                SeDeleteClientSecurity(device_extension->security_client_context);
            }
            else
            {
                device_extension->security_client_context =
                    ExAllocatePool(NonPagedPool, sizeof(SECURITY_CLIENT_CONTEXT));
            }

            RtlZeroMemory(&security_quality_of_service, sizeof(SECURITY_QUALITY_OF_SERVICE));

            security_quality_of_service.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
            security_quality_of_service.ImpersonationLevel = SecurityImpersonation;
            security_quality_of_service.ContextTrackingMode = SECURITY_STATIC_TRACKING;
            security_quality_of_service.EffectiveOnly = FALSE;

            SeCreateClientSecurity(
                PsGetCurrentThread(),
                &security_quality_of_service,
                FALSE,
                device_extension->security_client_context
                );

            IoMarkIrpPending(Irp);

            ExInterlockedInsertTailList(
                &device_extension->list_head,
                &Irp->Tail.Overlay.ListEntry,
                &device_extension->list_lock
                );

            KeSetEvent(
                &device_extension->request_event,
                (KPRIORITY) 0,
                FALSE
                );

            status = STATUS_PENDING;

            break;
        }

    case IOCTL_ENC_DISK_CLOSE_FILE:
        {
            IoMarkIrpPending(Irp);

            ExInterlockedInsertTailList(
                &device_extension->list_head,
                &Irp->Tail.Overlay.ListEntry,
                &device_extension->list_lock
                );

            KeSetEvent(
                &device_extension->request_event,
                (KPRIORITY) 0,
                FALSE
                );

            status = STATUS_PENDING;

            break;
        }

    case IOCTL_ENC_DISK_QUERY_FILE:
        {
            POPEN_FILE_INFORMATION open_file_information;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(OPEN_FILE_INFORMATION) + device_extension->file_name.Length - sizeof(UCHAR))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            open_file_information = (POPEN_FILE_INFORMATION) Irp->AssociatedIrp.SystemBuffer;
            open_file_information->RealFileSize.QuadPart = device_extension->file_size.QuadPart;
            open_file_information->FileNameLength = device_extension->file_name.Length;
            open_file_information->IsEncrypt = device_extension->is_encrypt;
            RtlCopyMemory(
                &open_file_information->Key,
                &device_extension->context.key,
                sizeof(open_file_information->Key)
                );

            RtlCopyMemory(
                open_file_information->FileName,
                device_extension->file_name.Buffer,
                device_extension->file_name.Length
                );

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(OPEN_FILE_INFORMATION) +
                open_file_information->FileNameLength - sizeof(UCHAR);

            break;
        }

    case IOCTL_DISK_CHECK_VERIFY:
    case IOCTL_CDROM_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY2:
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;
        }

    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
        {
            PDISK_GEOMETRY  disk_geometry;
            ULONGLONG       length;
            ULONG           sector_size;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(DISK_GEOMETRY))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            disk_geometry = (PDISK_GEOMETRY) Irp->AssociatedIrp.SystemBuffer;
            length = device_extension->file_size.QuadPart;
            sector_size = SECTOR_SIZE;
            disk_geometry->Cylinders.QuadPart = length / sector_size / 32 / 2;
            disk_geometry->MediaType = FixedMedia;
            disk_geometry->TracksPerCylinder = 2;
            disk_geometry->SectorsPerTrack = 32;
            disk_geometry->BytesPerSector = sector_size;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);

            break;
        }

    case IOCTL_DISK_GET_LENGTH_INFO:
        {
            PGET_LENGTH_INFORMATION get_length_information;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(GET_LENGTH_INFORMATION))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            get_length_information = (PGET_LENGTH_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            get_length_information->Length.QuadPart = device_extension->file_size.QuadPart;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

        break;
        }

    case IOCTL_DISK_GET_PARTITION_INFO:
        {
            PPARTITION_INFORMATION  partition_information;
            ULONGLONG               length;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(PARTITION_INFORMATION))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            partition_information = (PPARTITION_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            partition_information->StartingOffset.QuadPart = SECTOR_SIZE;
            partition_information->PartitionLength.QuadPart = length - SECTOR_SIZE;
            partition_information->HiddenSectors = 1;
            partition_information->PartitionNumber = 0;
            partition_information->PartitionType = 0;
            partition_information->BootIndicator = FALSE;
            partition_information->RecognizedPartition = FALSE;
            partition_information->RewritePartition = FALSE;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);

            break;
        }

    case IOCTL_DISK_GET_PARTITION_INFO_EX:
        {
            PPARTITION_INFORMATION_EX   partition_information_ex;
            ULONGLONG                   length;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(PARTITION_INFORMATION_EX))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            partition_information_ex = (PPARTITION_INFORMATION_EX) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            partition_information_ex->PartitionStyle = PARTITION_STYLE_MBR;
            partition_information_ex->StartingOffset.QuadPart = SECTOR_SIZE;
            partition_information_ex->PartitionLength.QuadPart = length - SECTOR_SIZE;
            partition_information_ex->PartitionNumber = 0;
            partition_information_ex->RewritePartition = FALSE;
            partition_information_ex->Mbr.PartitionType = 0;
            partition_information_ex->Mbr.BootIndicator = FALSE;
            partition_information_ex->Mbr.RecognizedPartition = FALSE;
            partition_information_ex->Mbr.HiddenSectors = 1;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);

            break;
        }
    case IOCTL_DISK_IS_WRITABLE:
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;
        }

    case IOCTL_DISK_MEDIA_REMOVAL:
    case IOCTL_STORAGE_MEDIA_REMOVAL:
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;
        }
    case IOCTL_DISK_SET_PARTITION_INFO:
        {

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(SET_PARTITION_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;

            break;
        }

    case IOCTL_DISK_VERIFY:
        {
            PVERIFY_INFORMATION verify_information;

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(VERIFY_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            verify_information = (PVERIFY_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = verify_information->Length;

            break;
        }

    default:
        {
            KdPrint((
                "EncDisk: Unknown IoControlCode %#x\n",
                io_stack->Parameters.DeviceIoControl.IoControlCode
                ));

            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
        }
    }

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return status;
}


NTSTATUS
FlushBuffer(
    PDEVICE_EXTENSION Extension
    )
{
    PCLUSTER_BUFFER cbf = &Extension->cache;
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER  ByteOffset;

    KdPrint(("EncDisk: FlushBuffer request %d %d %I64u\n", cbf->valid, cbf->dirty, cbf->index));

    IoStatus.Status = STATUS_SUCCESS;
    if(cbf->valid && cbf->dirty) 
    {
        KdPrint(("EncDisk: FlushBuffer cluster index %I64u flushed\n", cbf->index));
  
        /* encrypt cbf */
        if(CryptEncryptCluster(&Extension->context, cbf->plain, cbf->cipher, cbf->index) != CRYPT_OK)
        {
            return STATUS_INTERNAL_ERROR;
        }

        /* raw write disk */
        ByteOffset.QuadPart = cbf->index * CRYPT_CLUSTER_SIZE;
        ZwWriteFile(
            Extension->file_handle,
            NULL,
            NULL,
            NULL,
            &IoStatus,
            cbf->cipher,
            CRYPT_CLUSTER_SIZE,
            &ByteOffset,
            NULL
            );
        
        if(!NT_SUCCESS(IoStatus.Status)) 
        {
            KdPrint(("EncDisk: FlushBuffer ZwWriteFile error %u\n", IoStatus.Status));
            return IoStatus.Status;
        }
        if(IoStatus.Information != CRYPT_CLUSTER_SIZE) 
        {
            KdPrint(("EncDisk: FlushBuffer ZwWriteFile length error %u != %u\n", CRYPT_CLUSTER_SIZE, IoStatus.Information));
            IoStatus.Status = STATUS_INTERNAL_ERROR;
            return IoStatus.Status;
        }

        cbf->dirty = FALSE;
    }

    return IoStatus.Status;
}

NTSTATUS
EncryptWriteCluster(
    PDEVICE_EXTENSION Extension,
    PUCHAR Buffer,
    ULONGLONG ClusterIndex,
    ULONG Offset, /* offset in cluster */
    ULONG Length /* length, should <= cluster size - offset */
    )
{
    PCLUSTER_BUFFER cbf = &Extension->cache;
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER  ByteOffset;

    KdPrint(("EncDisk: EncryptWriteCluster(%I64u) Offset %u Length %u, cache %d %d %I64u\n", 
        ClusterIndex, Offset, Length,
        cbf->valid, cbf->dirty, cbf->index));


    /* does we have a valid cache ?*/
    if(cbf->valid && ClusterIndex == cbf->index) 
    {
        KdPrint(("EncDisk: EncryptWriteCluster hit cache\n"));
        RtlCopyMemory(&cbf->plain[Offset], Buffer, Length);
        cbf->dirty = TRUE;
    }
    else /* !cbf->valid || ClusterIndex != cbf->index */
    {
        KdPrint(("EncDisk: EncryptWriteCluster miss cache request %I64u, we have %d %d %I64u\n", 
            ClusterIndex, cbf->valid, cbf->dirty, cbf->index));
        /* we need load cache , flush old cache first */
        if(ClusterIndex != cbf->index) 
        {
            IoStatus.Status = FlushBuffer(Extension);
            if(!NT_SUCCESS(IoStatus.Status)) 
            {
                return IoStatus.Status;
            }
            cbf->valid = FALSE;
        }

        /* if it is partial write, load cache , and modify it */
        if(Length != CRYPT_CLUSTER_SIZE) 
        {
            KdPrint(("EncDisk: EncryptWriteCluster partial write, load cache\n"));
            /* raw read one cluster from disk */
            KdPrint(("EncDisk: EncryptWriteCluster load cache clust index %I64u\n", ClusterIndex));
            ByteOffset.QuadPart = ClusterIndex * CRYPT_CLUSTER_SIZE;
            ZwReadFile(
                Extension->file_handle,
                NULL,
                NULL,
                NULL,
                &IoStatus,
                cbf->cipher,
                CRYPT_CLUSTER_SIZE,
                &ByteOffset,
                NULL
                );
            if(!NT_SUCCESS(IoStatus.Status)) 
            {
                KdPrint(("EncDisk: EncryptWriteCluster ZwReadFile error %u\n", IoStatus.Status));
                return IoStatus.Status;
            }
            if(IoStatus.Information != CRYPT_CLUSTER_SIZE) 
            {
                KdPrint(("EncDisk: EncryptWriteCluster ZwReadFile length error %u != %u\n", CRYPT_CLUSTER_SIZE, IoStatus.Information));
                IoStatus.Status = STATUS_INTERNAL_ERROR;
                return IoStatus.Status;
            }

            /* decrypt it! */
            if(CryptDecryptCluster(&Extension->context, cbf->cipher, cbf->plain, ClusterIndex) != CRYPT_OK) 
            {
                KdPrint(("EncDisk: EncryptWriteCluster CryptDecryptCluster error"));
                return STATUS_INTERNAL_ERROR;
            }
        }
        /* modify cbf */
        RtlCopyMemory(&cbf->plain[Offset], Buffer, Length);
        cbf->valid = TRUE;
        cbf->dirty = TRUE;
        cbf->index = ClusterIndex;
    }

   
    return STATUS_SUCCESS;
}

NTSTATUS
DecryptReadCluster(
    PDEVICE_EXTENSION Extension,
    PUCHAR Buffer,
    ULONGLONG ClusterIndex,
    ULONG Offset, /* byte offset in cluster */
    ULONG Length /* byte length, should <= cluster size - offset */
    )
{
    PCLUSTER_BUFFER cbf = &Extension->cache;
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER  ByteOffset;

    KdPrint(("EncDisk: DecryptReadCluster(%I64u) Offset %u Length %u, cache %d %d %I64u\n", 
        ClusterIndex, Offset, Length,
        cbf->valid, cbf->dirty, cbf->index));

    /* does we have a valid cache ?*/
    if(cbf->valid && ClusterIndex == cbf->index) 
    {
        KdPrint(("EncDisk: DecryptReadCluster hit cache\n"));
        RtlCopyMemory(Buffer, &cbf->plain[Offset], Length);
    }
    else /* !cbf->valid || ClusterIndex != cbf->index */
    {
        KdPrint(("EncDisk: DecryptReadCluster miss cache request %I64u, we have %d %d %I64u\n", 
            ClusterIndex, cbf->valid, cbf->dirty, cbf->index));
        /* we need load cache , flush old cache first */
        if(ClusterIndex != cbf->index) 
        {
            IoStatus.Status = FlushBuffer(Extension);
            if(!NT_SUCCESS(IoStatus.Status)) 
            {
                return IoStatus.Status;
            }
            cbf->valid = FALSE;
        }
        
        KdPrint(("EncDisk: EncryptReadCluster load cache clust index %I64u\n", ClusterIndex));
        /* raw read one cluster from disk */
        ByteOffset.QuadPart = ClusterIndex * CRYPT_CLUSTER_SIZE;
        ZwReadFile(
            Extension->file_handle,
            NULL,
            NULL,
            NULL,
            &IoStatus,
            cbf->cipher,
            CRYPT_CLUSTER_SIZE,
            &ByteOffset,
            NULL
            );
        if(!NT_SUCCESS(IoStatus.Status)) 
        {
            KdPrint(("EncDisk: EncryptReadCluster ZwReadFile error %u\n", IoStatus.Status));
            return IoStatus.Status;
        }
        if(IoStatus.Information != CRYPT_CLUSTER_SIZE) 
        {
            KdPrint(("EncDisk: EncryptReadCluster ZwReadFile length error %u != %u\n", CRYPT_CLUSTER_SIZE, IoStatus.Information));
            IoStatus.Status = STATUS_INTERNAL_ERROR;
            return IoStatus.Status;
        }

        /* decrypt it! */
        if(CryptDecryptCluster(&Extension->context, cbf->cipher, cbf->plain, ClusterIndex) != CRYPT_OK) 
        {
            KdPrint(("EncDisk: DecryptReadCluster CryptDecryptCluster error"));
            return STATUS_INTERNAL_ERROR;
        }

        cbf->valid = TRUE;
        cbf->dirty = FALSE;
        cbf->index = ClusterIndex;
        RtlCopyMemory(Buffer, &cbf->plain[Offset], Length);
    }

    return STATUS_SUCCESS;
}

VOID 
DecryptRead(
    PDEVICE_EXTENSION Extension,
    PUCHAR Buffer,
    LONGLONG Offset,
    ULONG Length,
    PIO_STATUS_BLOCK Status
    )
{
    PUCHAR P = Buffer;
    ULONGLONG  ClusterIndex = (Offset / CRYPT_CLUSTER_SIZE);
    ULONG Begin = (ULONG)(Offset - (ClusterIndex * CRYPT_CLUSTER_SIZE));
    ULONG ToRead;

    Status->Information = 0;
    while(Length > 0) 
    {
        ToRead = Length > CRYPT_CLUSTER_SIZE ? CRYPT_CLUSTER_SIZE : Length;
        if(ToRead + Begin > CRYPT_CLUSTER_SIZE) {
            ToRead = CRYPT_CLUSTER_SIZE - Begin;
        }
        KdPrint(("EncDisk: DecryptRead ClusterIndex=%I64u Begin=%u ToRead=%u Length=%u\n",
            ClusterIndex, Begin, ToRead, Length));
        
        Status->Status = DecryptReadCluster(Extension, P, ClusterIndex, Begin, ToRead);
        if(!NT_SUCCESS(Status->Status)) 
        {
            KdPrint(("EncDisk: DecryptReadCluster error %u\n", Status->Status));
            return;
        }

        Length -= ToRead;
        P += ToRead;
        ClusterIndex ++;
        Begin = 0;
        Status->Information += ToRead;
    }
    return;
}

VOID 
EncryptWrite(
    PDEVICE_EXTENSION Extension,
    PUCHAR Buffer,
    LONGLONG Offset,
    ULONG Length,
    PIO_STATUS_BLOCK Status
    )
{
    PUCHAR P = Buffer;
    ULONGLONG ClusterIndex = (Offset / CRYPT_CLUSTER_SIZE);
    ULONG Begin = (ULONG)(Offset - (ClusterIndex * CRYPT_CLUSTER_SIZE));
    ULONG ToWrite;

    Status->Information = 0;
    while(Length > 0) 
    {
        ToWrite = Length > CRYPT_CLUSTER_SIZE ? CRYPT_CLUSTER_SIZE : Length;
        if(ToWrite + Begin > CRYPT_CLUSTER_SIZE) {
            ToWrite = CRYPT_CLUSTER_SIZE - Begin;
        }
        KdPrint(("EncDisk: EncryptWrite ClusterIndex=%I64u Begin=%u ToWrite=%u Length=%u\n",
            ClusterIndex, Begin, ToWrite, Length));

        Status->Status = EncryptWriteCluster(Extension, P, ClusterIndex, Begin, ToWrite);
        if(!NT_SUCCESS(Status->Status)) 
        {
            KdPrint(("EncDisk: EncryptWriteCluster error %u\n", Status->Status));
            return ;
        }
        Length -= ToWrite;
        P += ToWrite;
        ClusterIndex ++;
        Begin = 0;
        Status->Information += ToWrite;
    }
    return;
}

VOID
EncDiskThread (
    IN PVOID Context
    )
{
    PDEVICE_OBJECT      device_object;
    PDEVICE_EXTENSION   device_extension;
    PLIST_ENTRY         request;
    PIRP                irp;
    PIO_STACK_LOCATION  io_stack;
    PUCHAR              system_buffer;
    PUCHAR              buffer;
    LARGE_INTEGER       time_out;
    NTSTATUS            wait_ret;

    ASSERT(Context != NULL);

    device_object = (PDEVICE_OBJECT) Context;

    device_extension = (PDEVICE_EXTENSION) device_object->DeviceExtension;

    KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

    EncDiskAdjustPrivilege(SE_IMPERSONATE_PRIVILEGE, TRUE);

    /* A negative value specifies an interval relative to the current time, in 100 nanosecond units (1/1,000,000,000 sec)*/
    /* 10 sec */
    time_out.QuadPart = -10 * 10000000L;

    for (;;)
    {
        wait_ret = KeWaitForSingleObject(
            &device_extension->request_event,
            Executive,
            KernelMode,
            FALSE,
            &time_out
            );
        /* if time out, flush cache */
        if(STATUS_TIMEOUT == wait_ret 
            && device_extension->media_in_device 
            && device_extension->is_encrypt) {
            KdPrint(("EncDisk: time out, flush cache"));
            FlushBuffer(device_extension);
        } 

        if (device_extension->terminate_thread)
        {
            if(device_extension->media_in_device) 
            {
                EncDiskCloseFile(device_object, NULL);
            }
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        while (request = ExInterlockedRemoveHeadList(
            &device_extension->list_head,
            &device_extension->list_lock
            ))
        {
            irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

            io_stack = IoGetCurrentIrpStackLocation(irp);

            switch (io_stack->MajorFunction)
            {
            case IRP_MJ_READ:
                KdPrint(("EncDisk: EncDiskThread RD offset=%I64u length=%u\n", 
                    io_stack->Parameters.Read.ByteOffset.QuadPart,
                    io_stack->Parameters.Read.Length));
                system_buffer = (PUCHAR) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
                if (system_buffer == NULL)
                {
                    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    irp->IoStatus.Information = 0;
                    KdPrint(("EncDisk: EncDiskThread RD system_buffer STATUS_INSUFFICIENT_RESOURCES\n"));
                    break;
                }
                /*
                If the preceding call to ZwCreateFile set the FILE_NO_INTERMEDIATE_BUFFERING flag 
                in the CreateOptions parameter to ZwCreateFile, the Length and ByteOffset parameters 
                to ZwReadFile must be multiples of the sector size.
                */
                if(device_extension->is_encrypt) {
                    DecryptRead(
                        device_extension,
                        system_buffer, 
                        io_stack->Parameters.Read.ByteOffset.QuadPart, 
                        io_stack->Parameters.Read.Length,
                        &irp->IoStatus
                        );
                } else {
                    ZwReadFile(
                        device_extension->file_handle,
                        NULL,
                        NULL,
                        NULL,
                        &irp->IoStatus,
                        system_buffer,
                        io_stack->Parameters.Read.Length,
                        &io_stack->Parameters.Read.ByteOffset,
                        NULL
                        );
                }
                /*
                RtlCopyMemory(system_buffer, buffer, io_stack->Parameters.Read.Length);
                ExFreePool(buffer);
                */
                break;

            case IRP_MJ_WRITE:
                KdPrint(("EncDisk: EncDiskThread WT offset=%I64u length=%u\n", 
                    io_stack->Parameters.Write.ByteOffset.QuadPart,
                    io_stack->Parameters.Write.Length));
                if ((io_stack->Parameters.Write.ByteOffset.QuadPart +
                     io_stack->Parameters.Write.Length) >
                     device_extension->file_size.QuadPart)
                {
                    irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    irp->IoStatus.Information = 0;
                    KdPrint(("EncDisk: EncDiskThread WT INVALID PARAM\n"));
                    break;
                }
                
                system_buffer = (PUCHAR) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
                if (system_buffer == NULL)
                {
                    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    irp->IoStatus.Information = 0;
                    KdPrint(("EncDisk: EncDiskThread RD system_buffer STATUS_INSUFFICIENT_RESOURCES\n"));
                    break;
                }

                /*
                If the preceding call to ZwCreateFile set the CreateOptions flag FILE_NO_INTERMEDIATE_BUFFERING, 
                the Length and ByteOffset parameters to ZwWriteFile must be an integral of the sector size
                */
                if(device_extension->is_encrypt) {
                    EncryptWrite(
                        device_extension,
                        system_buffer, 
                        io_stack->Parameters.Write.ByteOffset.QuadPart,
                        io_stack->Parameters.Write.Length,
                        &irp->IoStatus
                        );
                } else {
                    ZwWriteFile(
                        device_extension->file_handle,
                        NULL,
                        NULL,
                        NULL,
                        &irp->IoStatus,
                        system_buffer,
                        io_stack->Parameters.Write.Length,
                        &io_stack->Parameters.Write.ByteOffset,
                        NULL
                        );
                }
  
                break;

            case IRP_MJ_DEVICE_CONTROL:
                switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
                {
                case IOCTL_ENC_DISK_OPEN_FILE:

                    SeImpersonateClient(device_extension->security_client_context, NULL);

                    irp->IoStatus.Status = EncDiskOpenFile(device_object, irp);

                    PsRevertToSelf();

                    break;

                case IOCTL_ENC_DISK_CLOSE_FILE:
                    irp->IoStatus.Status = EncDiskCloseFile(device_object, irp);
                    break;

                default:
                    KdPrint(("EncDisk: EncDiskThread Unknown Control Code for IRP_MJ_DEVICE_CONTROL %#x\n",
                    io_stack->Parameters.DeviceIoControl.IoControlCode));
                    irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
                }
                break;

            default:
                KdPrint(("EncDisk: EncDiskThread Unknown MajorFunction %#x\n",io_stack->MajorFunction));
                irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
            }

            IoCompleteRequest(
                irp,
                (CCHAR) (NT_SUCCESS(irp->IoStatus.Status) ?
                IO_DISK_INCREMENT : IO_NO_INCREMENT)
                );
        }
    }
}

#pragma code_seg("PAGE")

NTSTATUS
EncDiskOpenFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION               device_extension;
    POPEN_FILE_INFORMATION          open_file_information;
    UNICODE_STRING                  ufile_name;
    NTSTATUS                        status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES               object_attributes;
    FILE_END_OF_FILE_INFORMATION    file_eof;
    FILE_BASIC_INFORMATION          file_basic;
    FILE_STANDARD_INFORMATION       file_standard;
    FILE_ALIGNMENT_INFORMATION      file_alignment;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(Irp != NULL);

    RtlZeroMemory(&ufile_name, sizeof(ufile_name));

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    KdPrint(("EncDisk: EncDiskOpenFile %u\n", device_extension->number));

    open_file_information = (POPEN_FILE_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

    device_extension->file_name.Length = open_file_information->FileNameLength;
    device_extension->file_name.MaximumLength = open_file_information->FileNameLength;
    device_extension->file_name.Buffer = ExAllocatePool(NonPagedPool, open_file_information->FileNameLength);

    device_extension->cache.dirty = FALSE;
    device_extension->cache.valid = FALSE;
    device_extension->is_encrypt = open_file_information->IsEncrypt;

    if(NULL == device_extension->file_name.Buffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    RtlCopyMemory(
        &device_extension->context.key,
        &open_file_information->Key,
        sizeof(open_file_information->Key)
        );
    if(device_extension->is_encrypt) {
        if(CryptRestoreContext(&device_extension->context) != CRYPT_OK) {
            status = STATUS_INTERNAL_ERROR;
            goto err;
        }
    }

    RtlCopyMemory(
        device_extension->file_name.Buffer,
        open_file_information->FileName,
        open_file_information->FileNameLength
        );

    status = RtlAnsiStringToUnicodeString(
        &ufile_name,
        &device_extension->file_name,
        TRUE
        );

    if (!NT_SUCCESS(status))
    {
        goto err;
    }

    InitializeObjectAttributes(
        &object_attributes,
        &ufile_name,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
        );

    status = ZwCreateFile(
        &device_extension->file_handle,
        GENERIC_READ | GENERIC_WRITE,
        &object_attributes,
        &Irp->IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_RANDOM_ACCESS |
        FILE_NO_INTERMEDIATE_BUFFERING |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
        );

    if (!NT_SUCCESS(status))
    {
        goto err;
    }

    status = ZwQueryInformationFile(
        device_extension->file_handle,
        &Irp->IoStatus,
        &file_basic,
        sizeof(FILE_BASIC_INFORMATION),
        FileBasicInformation
        );

    if (!NT_SUCCESS(status))
    {
        goto err;
    }


    //
    // The NT cache manager can deadlock if a filesystem that is using the cache
    // manager is used in a virtual disk that stores its file on a filesystem
    // that is also using the cache manager, this is why we open the file with
    // FILE_NO_INTERMEDIATE_BUFFERING above, however if the file is compressed
    // or encrypted NT will not honor this request and cache it anyway since it
    // need to store the decompressed/unencrypted data somewhere, therefor we put
    // an extra check here and don't alow disk images to be compressed/encrypted.
    //
    if (file_basic.FileAttributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED))
    {
        status = STATUS_ACCESS_DENIED;
        goto err;
    }


    status = ZwQueryInformationFile(
        device_extension->file_handle,
        &Irp->IoStatus,
        &file_standard,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation
        );

    if (!NT_SUCCESS(status))
    {
        goto err;
    }

    device_extension->file_size.QuadPart = file_standard.EndOfFile.QuadPart;

    status = ZwQueryInformationFile(
        device_extension->file_handle,
        &Irp->IoStatus,
        &file_alignment,
        sizeof(FILE_ALIGNMENT_INFORMATION),
        FileAlignmentInformation
        );

    if (!NT_SUCCESS(status))
    {
        goto err;
    }

    DeviceObject->AlignmentRequirement = file_alignment.AlignmentRequirement;

    DeviceObject->Characteristics &= ~FILE_READ_ONLY_DEVICE;

    device_extension->media_in_device = TRUE;

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;

err:
    if(ufile_name.Buffer != NULL) {
        RtlFreeUnicodeString(&ufile_name);
    }
    if(!NT_SUCCESS(status)) {
        if(device_extension->file_handle != INVALID_HANDLE_VALUE) {
            ZwClose(device_extension->file_handle);
            device_extension->file_handle = INVALID_HANDLE_VALUE;
        }
        device_extension->file_name.Length = 0;
        device_extension->file_name.MaximumLength = 0;
        if(!device_extension->file_name.Buffer) {
            ExFreePool(device_extension->file_name.Buffer);
            device_extension->file_name.Buffer = NULL;
        }
        RtlZeroMemory(&device_extension->context.key, 
            sizeof(&device_extension->context.key));
        if(device_extension->is_encrypt) {
            CryptCleanupContext(&device_extension->context);
        }
        device_extension->media_in_device = FALSE;
        device_extension->is_encrypt = FALSE;
    }
    return status;
}

NTSTATUS
EncDiskCloseFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION device_extension;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    KdPrint(("EncDisk: EncDiskCloseFile %u\n", device_extension->number));

    FlushBuffer(device_extension);

    CryptCleanupContext(&device_extension->context);

    RtlZeroMemory(&device_extension->cache, sizeof(device_extension->cache));

    if(NULL != device_extension->file_name.Buffer) {
        ExFreePool(device_extension->file_name.Buffer);
        device_extension->file_name.Buffer = NULL;
    }

    if(device_extension->file_handle != INVALID_HANDLE_VALUE) {
        ZwClose(device_extension->file_handle);
        device_extension->file_handle = INVALID_HANDLE_VALUE;
    }

    device_extension->media_in_device = FALSE;

    device_extension->is_encrypt = FALSE;
    
    if(NULL != Irp)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
EncDiskAdjustPrivilege (
    IN ULONG    Privilege,
    IN BOOLEAN  Enable
    )
{
    NTSTATUS            status;
    HANDLE              token_handle;
    TOKEN_PRIVILEGES    token_privileges;

    PAGED_CODE();

    status = ZwOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ALL_ACCESS,
        &token_handle
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
    token_privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

    //
    // Normaly one would use ZwAdjustPrivilegesToken but it is only available
    // on Windows 2000 and later versions, however since we are in a system
    // thread does ExGetPreviousMode always return KernelMode and therefore
    // can NtAdjustPrivilegesToken be used directly.
    //
    status = NtAdjustPrivilegesToken(
        token_handle,
        FALSE,
        &token_privileges,
        sizeof(token_privileges),
        NULL,
        NULL
        );

    ZwClose(token_handle);

    return status;
}
