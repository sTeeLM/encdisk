#include "control.h"

INT EncKeyPass(
    const CHAR * PrivateKey
)
{
    CHAR * OldPass = NULL, * NewPass = NULL;
    PCRYPT_CONTEXT Context = NULL;
    INT Ret = -1;

    if((OldPass = AskPass(CHECK_PASS, "Enter the old password for the key:", NULL)) == NULL)
        goto err;

    if((Context = ReadKeyFile(PrivateKey, OldPass)) == NULL) {
        goto err;
    }

    if((NewPass = AskPass(ASK_NEW_PASS, "Enter the new password for the key:", "Retype the new password for the key:")) == NULL)
        goto err;
    
    if(WriteKeyFile(&Context->key, PrivateKey, NewPass) != 0) {
        goto err;
    }

    PrintMessage("%s\n", "EncKeyPass: success!");
    Ret = 0;
err:
    if(NULL != OldPass) {
        free(OldPass);
        OldPass = NULL;
    }
    if(NULL != NewPass) {
        free(NewPass);
        NewPass = NULL;
    }
    if(NULL != Context) {
        free(Context);
        Context = NULL;
    }

    return Ret;
}
