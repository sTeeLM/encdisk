#include "service.h"

static BOOL GetBinaryPath(CHAR * Buffer, SIZE_T BufferSize)
{
    DWORD dwRet = 0;
    if(strlen(" /run") + MAX_PATH < BufferSize) {
        dwRet = GetModuleFileName(NULL, Buffer, BufferSize - strlen(" /run"));
        if( dwRet != 0 ) {
            dwRet += _snprintf(Buffer + dwRet, BufferSize - dwRet - 1, "%s", " /run");
        }
    }
    return dwRet != 0;
}


INT EncServiceInstall()
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_DESCRIPTION ServiceDescription;
    SERVICE_PRESHUTDOWN_INFO ServicePreshutdownInfo;
    CHAR BinaryPath[MAX_PATH + 64];
    INT Ret = -1;

    if(!GetBinaryPath(BinaryPath, sizeof(BinaryPath))) {
        PrintLastError("EncServiceInstall:");
        goto err;
    }

    hSCManager = OpenSCManager(
        NULL,
        SERVICES_ACTIVE_DATABASE,
        SC_MANAGER_ALL_ACCESS
        );
    if(NULL == hSCManager) {
        PrintLastError("EncServiceInstall:");
        goto err;
    }

    hService = CreateService(
        hSCManager,
        ENC_MON_SERVICE_NAME,
        ENC_MON_SERVICE_DISPLAY_NAME,
        SC_MANAGER_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        BinaryPath,
        NULL,
        NULL,
        ENC_DISK_SERVICE_NAME,
        NULL,
        NULL
        );

    if(NULL == hService) {
        PrintLastError("EncServiceInstall:");
        goto err;
    }

    ServiceDescription.lpDescription = ENC_MON_SERVICE_DESCRIPTION;
    if(!ChangeServiceConfig2(
        hService,
        SERVICE_CONFIG_DESCRIPTION,
        &ServiceDescription
        )) {
        PrintLastError("EncServiceInstall:");
        goto err;
    }

    ServicePreshutdownInfo.dwPreshutdownTimeout = ENC_MON_SERVICE_MAX_WAIT_MS;
    if(!ChangeServiceConfig2(
        hService,
        SERVICE_CONFIG_PRESHUTDOWN_INFO,
        &ServicePreshutdownInfo
        )) {
        PrintLastError("EncServiceInstall:");
        goto err;
    }

    Ret = 0;
err:
    if(NULL != hService) {
        CloseServiceHandle(hService);
        hService = NULL;
    }
    if(NULL != hSCManager) {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }
    return Ret;
}

