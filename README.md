Kernel RPM/WPM with Driver Destroyer
---------------------------------------------------------------------------------------------------------

There is a sample of a Kernel Driver used for Reading and Writing to user-space memory from Kernel Mode.
It uses MmCopyVirtualMemory to transfer the data UM<->KM.
The driver allows remove himself from a PC while stays loaded (that's bypassing Win10 func to block deleting loaded drivers - PatchGuard safe!)
For now this should be UD on almost every non-bootloaded ACs (that's for sure detected on FaceIT/ESEA - you have to use another method to transfer data and bootload your driver and probably not using any UM apps at all (do everything from Kernel instead))

For UserMode AC's (VAC etc...)
---------------------------------------------------------------------------------------------------------

1. Just load your Windows in Test-Mode and normally load this driver

For Kernel AC's (EAC/BattlEye/ESPORTAL/ESL Wire)
---------------------------------------------------------------------------------------------------------

1. Find any public blacklisted certs and sign this driver.
2. Upload this driver to a host/server.
3. From your UM app: download this driver from server, load it using SCManager/NtLoadDriver and delete driver file after that (using DeleteFileA or it's Kernel equivalent ZwDeleteFile).

TODO:
---------------------------------------------------------------------------------------------------------
Code a UM app which will do the following things:
1. Send a pID of target process using following IOCTL: IO_GET_ID_REQUEST
2. Recieve a BaseAddress of target process using following IOCTL: IO_GET_MODULE_REQUEST
3. After that, you're able to read/write memory.
