# hook_and_inject_detours
### Description:
Hook and inject using Microsoft Detours library. Inject performed by CreateRemoteThread() function. 

/DLL directory contain files for building dll.

/Monitor_and_inject directory contain files for building monitor.exe.

Program can monitor calls to FindFirstFile(),  FindNextFile(), CreateFile(), CloseHandle() functions or hide files from these functions. Admin access is required. Recommend to use it on virtual machine.
Monitor have console output. Monitor and dll communicates via sockets For debugging DLL, there are DBGPRINT() function. To see output from DBGPRINT(), you can use DebugView utility from Microsoft. To get PID of process, you can use Process Hacker utility. To view API calls of target application (for example, CreateFileW() from KERNEL32.DLL), you can use "API Monitor" utility.

### Usage:
1) Create VS project with DLL template, put there files from /DLL directory. Build DLL for x64 systems.
2) Create VS empty project, put there files from /Monitor_and_inject directory. Change value of global variable "injectLibraryPath" in Monitor.cpp to path to compiled DLL from 1). Build project for x64 systems.
3) Run console with admin rights, or open Monitor VS project with admin rights and use terminal there. Type command there.

### Command structure:
1) monitor.exe --pid <pid> --func <func_name> // monitor function func_name in process with passed pid
2) monitor.exe --pid <pid> --hide <path_to_file> // hide file from process with passed pid
3) monitor.exe --name <proc_name> --func <func_name> // monitor function func_name in process with passed name
4) monitor.exe --name <proc_name> --hide <path_to_file> // hide file from process with passed pid
Note: if several processes with proc_name are running, than process with least PID will be injected.

### Examles:
1) Run mspaint.exe. Execute [monitor.exe --name mspaint.exe --hide "C:\Users\user\Desktop\image.bmp"].
  Now, if you try to open file image.bmp in mspaint.exe, you get error, mspaint.exe can't open file.
![image](https://github.com/Grizzzlyy/hook_and_inject_detours/assets/96661760/e9535c80-8769-4b67-bf55-9c05d36a5b94)
![image](https://github.com/Grizzzlyy/hook_and_inject_detours/assets/96661760/825bbc52-abac-4375-a98e-ca0add08bc2d)
2) Run notepad.exe. Assuming it has PID 8104. Execute [monitor.exe --pid 8104 --func FindFirstFile].
   Now, if you try to open some file in notepad.exe, you'll see in monitor console calls and timestamps.
   
   ![image](https://github.com/Grizzzlyy/hook_and_inject_detours/assets/96661760/dfefd4d7-cfe1-46a0-893f-f6b4869399af)

### Notes:
1) If you runned monitor.exe and didn't do anything in injected app for about 5 minutes, monitor.exe will not intercept calls and will close connection.
2) If app is already injected with dll, and you run monitor.exe for a second time, it wouldn't work. Solution: close target app and run it again.
3) You can't recieve messages faster than 200ms, because it may crush app. So, if function is called faster then 1 time per 200 seconds, you will not recieve message about it.
