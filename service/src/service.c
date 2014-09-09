#include "service.h"

static SERVICE_STATUS ServiceStatus = {0};
static SERVICE_STATUS_HANDLE hStatus = NULL;
static BOOL bIsShutdown;

// Service initialization
static BOOL EncInitService() 
{ 
    BOOL Ret = TRUE;
    bIsShutdown = FALSE;
    EncMonLog(ENC_LOG_DBG, "EncInitService return %d.\n", Ret);
    return Ret;
} 

static VOID EncCleanService()
{
    EncMonLog(ENC_LOG_DBG, "EncCleanService.\n");
}

VOID WINAPI EncServiceMain(DWORD dwArgc, LPSTR* lpszArgv)
{ 
    INT Error; 
    BOOL ForceUnmount = FALSE;

    ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN ;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandlerEx(
		ENC_MON_SERVICE_NAME, 
		(LPHANDLER_FUNCTION_EX)EncControlHandler, 
        NULL); 
    if (hStatus == NULL) 
    { 
        EncMonLog(ENC_LOG_ERR, "RegisterServiceCtrlHandlerEx error %x.\n", GetLastError());
        return; 
    }  
    // Initialize Service 
    if(!EncInitService()) {
		// Initialization failed
        EncMonLog(ENC_LOG_ERR, "EncInitService failed.\n");
        ServiceStatus.dwCurrentState       = SERVICE_STOPPED; 
        ServiceStatus.dwWin32ExitCode      = -1; 
        SetServiceStatus(hStatus, &ServiceStatus); 
        return; 
    } 
    // We report the running status to SCM. 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    SetServiceStatus (hStatus, &ServiceStatus);
 
    while(1) {
        if(ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
            Sleep(1000);
        } else if(ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING 
            && bIsShutdown) {
            if(ServiceStatus.dwCheckPoint > ENC_MON_MAX_CHECK_POINT) {
                ForceUnmount = TRUE;
            }
            EncMonLog(ENC_LOG_INF, "Shutdowning down..., ForceUnmount is %d\n", ForceUnmount);
            if(EncUnmountDisk(ForceUnmount)) {
                EncMonLog(ENC_LOG_INF, "Unmount complete!\n");
                ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
                SetServiceStatus (hStatus, &ServiceStatus);
                break;
            } else {
                EncMonLog(ENC_LOG_INF, "Unmount pending!\n");
                ServiceStatus.dwCheckPoint ++;
                SetServiceStatus (hStatus, &ServiceStatus);
                Sleep(100);
            }
        } else if(ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING && !bIsShutdown) {
            EncMonLog(ENC_LOG_INF, "Stop\n");
            ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            break;
        }
    }

    EncCleanService();

    return; 
}


// Control handler function
DWORD WINAPI EncControlHandler(
    DWORD dwControl,
    DWORD dwEventType,
    LPVOID lpEventData,
    LPVOID lpContext
)
{
    switch(dwControl) 
    { 
        case SERVICE_CONTROL_STOP: 

            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOP_PENDING; 
            SetServiceStatus (hStatus, &ServiceStatus);
            EncMonLog(ENC_LOG_INF, "EncControlHandler ctl SERVICE_CONTROL_STOP.\n");
            return NO_ERROR; 
 
        case SERVICE_CONTROL_SHUTDOWN: 
            EncMonLog(ENC_LOG_INF, "EncControlHandler ctl SERVICE_CONTROL_SHUTDOWN.\n");
            ServiceStatus.dwCurrentState  = SERVICE_STOP_PENDING; 
            SetServiceStatus (hStatus, &ServiceStatus);
            bIsShutdown = TRUE;
            return NO_ERROR;
        case SERVICE_CONTROL_PRESHUTDOWN:
            EncMonLog(ENC_LOG_INF, "EncControlHandler ctl SERVICE_CONTROL_PRESHUTDOWN.\n");
            ServiceStatus.dwCurrentState  = SERVICE_STOP_PENDING; 
            SetServiceStatus (hStatus, &ServiceStatus);
            bIsShutdown = TRUE;
            return NO_ERROR; 
        case SERVICE_CONTROL_INTERROGATE:
            EncMonLog(ENC_LOG_INF, "EncControlHandler ctl SERVICE_CONTROL_INTERROGATE.\n");
            return NO_ERROR; 
        default:
            EncMonLog(ENC_LOG_WAN, "UNKNWON EncControlHandler ctl %x\n.", dwControl);
            break;
    } 
 
    // Report current status
    SetServiceStatus (hStatus,  &ServiceStatus);
 
    return NO_ERROR; 
} 