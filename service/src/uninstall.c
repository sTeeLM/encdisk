#include "service.h"
INT EncServiceUninstall()
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;

    INT Ret = -1;

    hSCManager = OpenSCManager(
        NULL,
        SERVICES_ACTIVE_DATABASE,
        SC_MANAGER_ALL_ACCESS
        );
    if(NULL == hSCManager) {
        PrintLastError("EncServiceUninstall:");
        goto err;
    }

    hService = OpenService(
        hSCManager,
        ENC_MON_SERVICE_NAME,
        SC_MANAGER_ALL_ACCESS
        );
    if(NULL == hService) {
        PrintLastError("EncServiceUninstall:");
        goto err;
    }

    if(!DeleteService(
        hService)) {
        PrintLastError("EncServiceUninstall:");
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

