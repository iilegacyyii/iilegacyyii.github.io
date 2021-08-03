---
layout: post
title:  "Introduction to Windows Process Injection"
date:   2021-08-3 10:56:00 +0000
categories: red-teaming windows
---

So, what is process injection? I personally believe the folk at MITRE have the perfect summary:

*"Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges."* ~ [attack.mitre.org](https://attack.mitre.org/techniques/T1055)

### Contents
1. [Benefits of Process Injection](#benefits-of-process-injection)
2. [Fundamental Theory](#fundamental-theory)
    - [Processes Threads and Win32 API](#processes-threads-and-win32-api)
3. [Writing a Process Injection POC](#process-injection-in-c#)
4. [Summary](#summary)

## Benefits of Process Injection

**What's the point in process injection if I already have RCE?**

When obtaining a reverse shell, be it a cobalt strike beacon, meterpreter, or some other arbitrary reverse shell, it must execute within a process. A typical shellcode runner executes the shellcode within its own process. 

However, there are issues with this approach - the victim may close the process which may shut down your reverse shell. The more pressing matter is that security software may detect network communication from an unrecognised process and terminate your implant. One solution to this of course, among many, is process injection/migration, thus helping to extend the longevity of your implant.

Process injection can also help your implant blend in to a victim's environment. For example injecting into an svchost.exe process if it's making network traffic, or within notepad.exe if it is reading files. As a result the blue team and accompanying security software have to be that bit more sophisticated in order to detect your implant.

## Fundamental Theory

#### 
According to [this piece of Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/procthread/about-processes-and-threads), the definition to a process on windows is as follows:

*"A process has a virtual address space, executable code, open handles to system objects, a security context, a unique process identifier, environment variables, a priority class, minimum and maximum working set sizes, and at least one thread of execution. Each process is started with a single thread, often called the primary thread, but can create additional threads from any of its threads."* ~ [Microsoft](https://docs.microsoft.com/en-us/windows/win32/procthread/about-processes-and-threads)

On the other hand, a thread executes the compiled assembly code of its parent Process. A process may have multiple threads executing code at any given time to allow for simultaneous execution of code. An important property to keep in mind is that each thread will have its own stack, whilst *sharing* the virtual memory address space of the parent process!

As previously mentioned, each process has its own seperate virtual address space, and although these spaces are not meant to interact with one another it is possible to accomplish this by taking advantage of the Win32 API. The general idea is to initiate process injection by opening a communication channel from one process to another through the Win32 API's `OpenProcess` API. This allows you to modify its memory space through the use of `VirtualAllocEx` and `WriteProcessMemory` APIs. Finally creating a new execution thread inside the remote process via `CreateRemoteThread`.