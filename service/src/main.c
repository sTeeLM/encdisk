#include "service.h"

static INT EncServiceSyntax(void)
{
    fprintf(stderr, "Encrypt Disk Monitor Service, Version %s\n", ENC_DISK_VERSION_STR);
    fprintf(stderr, "encservice /install\n");
    fprintf(stderr, "encservice /uninstall\n");
    return 1;
}

INT __cdecl main(INT argc, CHAR* argv[])
{ 
    SERVICE_TABLE_ENTRY ServiceTable[2];

    if(argc == 2 && !strcmp(argv[1], "/run")){ // run service

        ServiceTable[0].lpServiceName = ENC_MON_SERVICE_NAME;
        ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)EncServiceMain;

        ServiceTable[1].lpServiceName = NULL;
        ServiceTable[1].lpServiceProc = NULL;
        // Start the control dispatcher thread for our service

        StartServiceCtrlDispatcher(ServiceTable);

        return 0;
    } else if(argc == 2 && !strcmp(argv[1], "/install")) {
        return EncServiceInstall();
    } else if(argc == 2 && !strcmp(argv[1], "/uninstall")) {
        return EncServiceUninstall();
    } else {
        return EncServiceSyntax();
    }
}

