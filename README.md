encdisk
=======

Encrypt Virtual File Disk
强加密虚拟硬盘（将文件当作硬盘使用）

Copy the driver (encdisk.sys) to %systemroot%\system32\drivers\.
将驱动（encdisk.sys）复制到%systemroot%\system32\drivers\

Optionally edit encdisk.reg for automatic or manual start and
number of devices.
（可选）编辑encdisk.reg文件，选择手动启动（开机后使用net start 
encdisk命令启动）还是自动启动（随操作系统一起启动）

Import encdisk.reg to the Registry.
将encdisk.reg导入注册表

Reboot. If using an unsigned driver and running on the 64-bit version
of Windows press F8 and select "Disable enforce driver signing".
重启，64位系统需要关闭“强制驱动签名”，对于Win 7，启动时按F8，选择
“Disable enforce driver signing”，对于Win8，请自己百度一下

Use the program encdisk.exe to mount and umount disk images.
使用encdisk.exe操作虚拟硬盘

