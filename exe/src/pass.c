#include "control.h"

CHAR * AskPass(INT Type, const CHAR * Prompt1, const CHAR * Prompt2)
{
    CHAR * Pass = NULL;
    CHAR * Check = NULL;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    INT Ret = -1;
    INT i;

    /* close echo */
    GetConsoleMode(hStdin, &mode);
    mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(hStdin, mode );

    if((Pass = malloc(MAX_PASS_LEN)) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("AskPass:");
        goto err;
    }

    memset(Pass, 0, MAX_PASS_LEN);

    if(ASK_NEW_PASS == Type) { // new password
        if((Check = malloc(MAX_PASS_LEN)) == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            PrintLastError("AskPass:");
            goto err;
        }
        memset(Check, 0, MAX_PASS_LEN);
        PrintMessage("%s", Prompt1);
        fgets(Pass, MAX_PASS_LEN - 1, stdin);
        PrintMessage("\n%s", Prompt2);
        fgets(Check, MAX_PASS_LEN - 1, stdin);
        PrintMessage("\n");
        if(strcmp(Pass, Check)) {
            PrintMessage("Password does not match!");
            goto err;
        }
    } else {
        PrintMessage("%s", Prompt1);
        fgets(Pass, MAX_PASS_LEN - 1, stdin);
        PrintMessage("\n");
    }
    for(i = 0 ; i < MAX_PASS_LEN; i ++) {
        if(Pass[i] == '\r' || Pass[i] == '\n')
            Pass[i] = 0;
    }
    if(!strlen(Pass)) {
        PrintMessage("Empty password not allowed!");
        goto err;
    }

    Ret = 0;
err:
    mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(hStdin, mode );
    if(NULL != Pass && Ret != 0) {
        free(Pass);
        Pass = NULL;
    }
    if(NULL != Check) {
        free(Check);
        Check = NULL;
    }
    return Pass;
}
