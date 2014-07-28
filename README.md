encdisk
=======

Encrypt Virtual File Disk

Copy the driver (encdisk.sys) to %systemroot%\system32\drivers\.

Optionally edit encdisk.reg for automatic or manual start and
number of devices.

Import filedisk.reg to the Registry.

Reboot. If using an unsigned driver and running on the 64-bit version
of Windows press F8 and select "Disable enforce driver signing".

Use the program encdisk.exe to mount and umount disk images.
