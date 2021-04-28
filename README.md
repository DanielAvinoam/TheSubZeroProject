# The SubZero Project  

SubZero is a multi-staged malware that contains a kernel mode rootkit and a remote system shell. Part of the malware capabilities are remote kernel mode shellcode execution and reflective DLL loading, which should grant full control over a compromised system.  
  
# Disclamer  
  
**This repository does not promote any hacking related activity. All the information in this repository is for educational purposes only.**  
  
I take **NO** responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files, you acknowledge that **you are using at your own risk**.  
  
In addition, this repository also contain a use of Microsoft's undocumented functions and structures. Using those is extremely dangerous and not recommended. **I do not promote this kind of code in any way**.  
  
# Introduction & Goal  
  
As a security researcher, I have encountered and analyzed various user-mode malwares in recent times. While some of them were more challenging than others, they were all designed with the same common ground in mind - **User Mode**.  
My colleagues and I wanted to put our forensics skills to the test in an unknown environment like the kernel space. We started by fully [reverse-engineering an APT driver]([https://github.com/DanielAvinoam/BlackEnergyV2-Driver-Reverse-Engineering](https://github.com/DanielAvinoam/BlackEnergyV2-Driver-Reverse-Engineering)) from 2008 - A pretty good start, but still far from a modern day kernel mode threat.  
Instead of searching for a modern malicious driver to disassemble, which are extremely rare anyway, I figured it would be more beneficial to challenge my kernel programming skills and write the driver myself (After all, you should always "know your enemy")  
This driver will accompany a few other user-mode modules that together will create a complete attack vector from start to finish. The researchers will receive a memory image of a compromised system and will need to form an accurate status report of what happened as fast as possible.  
 
This project's main component is it's driver - meaning the rest of the user-mode modules might have some compromises and will not take every scenario into account.  
The code is written in `C++ 17` and all of its features. The user mode components designed with OOP in mind, In future versions the driver should be updated as well.  
  
  
# The Gameplan  
  
Before starting to write any code, the general flow of the attack should be decided.  
When I started this project I had a vision of a user-mode process that would be able communicate with a remote server, while a driver will cover its tracks and make it look as legitimate as possible. 
What process can be found in almost every computer today and connects to the internet regularly? **chrome.exe**.

So my initial plan went like this - load a driver. the driver will load a malicious library into a chrome process. this library will connect to a remote server. sounds easy, right? well, it turns out it is way more complicated than this.
Loading a user-mode library from kernel mode is more than just a call to `LoadLibrary`. It requires alot of work with undocumented functions and structures, and in a gental enviourment like the kernel space this far from ideal - a different approach should be taken. 

A solution driver programmers found is to execute a user-mode shellcode using an APC, simillar to a malware. Many anti-virus programs work like this in order to load their DLLs into every opened process on the system.
How can a driver know when a new process is created? The kernel provides an API of callback function registration for various events, one of them is the `PsSetCreateProcessNotifyRoutineEx` function: 
```cpp
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  BOOLEAN                           Remove
);
```
The `NotifyRoutine` will be invoked whenever a new process is created. In this function the driver needs to save the PID of the created process, and capture its first thread - This can be done using another callback registration function named  `PsSetCreateThreadNotifyRoutineEx` that works simillarly to the one prior. Before a new thread executes, it calls the `TestAlert` function, that flushes its APC queue. This guarantee us that our shellcode will be executed before the process' main thread.
Prior to the APC queueing, the shellcode should be allocated to the process' address spaces. This is possible only from the context of that process and since callback functions are executing by an arbitrary thread, another APC should be queued - this time a kernel one.
The following graph demonstrates the flow of events:

![Driver Flow](https://github.com/DanielAvinoam/TheSubZeroProject/blob/main/Images/DriverFlow.JPG "Driver Flow")

There is a crutial problem in this plan though - The malicious DLL execution is dependent on the execution of its host chrome process. We need to create a chrome process of our own and protect it from being killed. Creation of a chrome process can be done using the same afromentioned method ( starting from an explorer.exe thread, since explorer.exe is singular and will already run when our driver will be loaded). 
For protecting this process the kernel generously offers us another callback registration function named `ObRegisterCallbacks`, which can give us a notification before an object handle create/open/duplicate operation - All there's left for us to do is to remove the `PROCESS_TERMINATE` access from the user-returned handle.
This solution is not perfect though, According to [@zodiacon](https://github.com/zodiacon)'s Windows Kernel Programming book:

> Even with this protection, clicking on a window's close button or selecting a termination option from within the application's interface would terminate the process. This is because it's being done internally by calling `ExitProcess`, Which does not involve any handles. 
This means that the protection mechanism is essentially good for processes without user interface.

This leads us to our second problem - chrome's GUI window. The suddenly-popped window will be visable for the system's user and can be closed using the window's X button. My first solution was creating the process with the `CreateProcess` function and a `CREATE_NO_WINDOW` flag sent to it. Unfortunately either this or using chrome's CMD arguments for hidden it's windows did not work. Starting the process suspended and manipulate it's memory space would might work but also be loud and will defeat the point of having a stealthy driver in the first place. 

That's where I had an idea - what if my library's `DllMain` will never return to the caller, thus blocking the APC function and the initial call to `TestAlert`? As I suspected, this means the initial chrome thread will not start, and the chrome window will not be created - perfect.

To fully take advantage of the kernel module, It should provide its user-mode clients exlusive access to the system resources and structures. I tried to demonstarte these capabilities with it's 3 IOCTL's - changing a process PPID, setting a process' token to the system's one and most importantly, executing a position independent kernel shellcode - which basically makes the entire system under the attacker's control.

## User Mode





 

  
# Code Walkthrough  
  
## Driver  
  
## Launcher  
  
## DLL  
  
## Cleanup  
  
## Server  
  
# Executing  
  
# Special Thanks and Sources
