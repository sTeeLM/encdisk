#include "control.h"
INT EncDiskNewKey(const CHAR * PrivateKey, INT HardLevel)
{
    CHAR * Pass = NULL;
    PCRYPT_CONTEXT Context = NULL;
    INT Ret = -1;
    
    if((Context = malloc(sizeof(CRYPT_CONTEXT))) == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        PrintLastError("EncDiskNewKey:");
        goto err; 
    }

    if(CryptGenContext(HardLevel, Context) != CRYPT_OK) {
        SetLastError(ERROR_INTERNAL_ERROR);
        PrintLastError("EncDiskNewKey:");
        goto err; 
    }

    if((Pass = AskPass(ASK_NEW_PASS, "Enter the password for the key:", "Retype the password for the key:")) == NULL)
        goto err;

    if(WriteKeyFile(&Context->key, PrivateKey, Pass) != 0) {
        goto err;
    }

    Ret = 0;
    PrintMessage("%s\n", "EncDiskNewKey: success!");
err:
    if(NULL != Pass) {
        free(Pass);
        Pass = NULL;
    }
    if(NULL != Context) {
        free(Context);
        Context = NULL;
    }
    return Ret;
}