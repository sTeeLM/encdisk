rmdir /s /q test\src\obj%BUILD_ALT_DIR%
rmdir /s /q libcrypt\src\obj%BUILD_ALT_DIR%
rmdir /s /q exe\src\obj%BUILD_ALT_DIR%
rmdir /s /q sys\src\obj%BUILD_ALT_DIR%
rmdir /s /q service\src\obj%BUILD_ALT_DIR%

rmdir /s /q test\obj
rmdir /s /q libcrypt\obj
rmdir /s /q exe\obj
rmdir /s /q sys\obj
rmdir /s /q service\obj
del *.log *.wrn *.err