signtool sign /v /s MY /n "Mad Cat Stdio" /t http://timestamp.verisign.com/scripts/timstamp.dll bin\win7\i386\encdisk.sys
signtool sign /v /s MY /n "Mad Cat Stdio" /t http://timestamp.verisign.com/scripts/timstamp.dll bin\win7\i386\encdisk-ctl.exe
signtool sign /v /s MY /n "Mad Cat Stdio" /t http://timestamp.verisign.com/scripts/timstamp.dll bin\win7\i386\encdisk-service.exe

signtool sign /v /s MY /n "Mad Cat Stdio" /t http://timestamp.verisign.com/scripts/timstamp.dll bin\win7\amd64\encdisk.sys
signtool sign /v /s MY /n "Mad Cat Stdio" /t http://timestamp.verisign.com/scripts/timstamp.dll bin\win7\amd64\encdisk-ctl.exe
signtool sign /v /s MY /n "Mad Cat Stdio" /t http://timestamp.verisign.com/scripts/timstamp.dll bin\win7\amd64\encdisk-service.exe