#include "control.h"

INT EncKeyInfo(
    const CHAR * PrivateKey
)
{
    CHAR * Pass = NULL;
    PCRYPT_CONTEXT Context = NULL;
    INT Ret = -1;

    if((Pass = AskPass(CHECK_PASS, "Enter the password for the key:", NULL)) == NULL)
        goto err;

    if((Context = ReadKeyFile(PrivateKey, Pass)) == NULL) {
        goto err;
    }

    DumpKey(&Context->key);

    PrintMessage("%s\n", "KeyInfo: success!");
    Ret = 0;
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
