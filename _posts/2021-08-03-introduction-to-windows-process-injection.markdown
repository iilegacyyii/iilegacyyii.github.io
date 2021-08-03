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
    - [OpenProcess API](#openprocess-api)
    - [Selecting a Target](#selecting-a-target)
3. [Writing a Process Injection POC](#process-injection-in-c#)
4. [Summary](#summary)

## Benefits of Process Injection

**What's the point in process injection if I already have RCE?**

When obtaining a reverse shell, be it a cobalt strike beacon, meterpreter, or some other arbitrary reverse shell, it must execute within a process. A typical shellcode runner executes the shellcode within its own process. 

However, there are issues with this approach - the victim may close the process which may shut down your reverse shell. The more pressing matter is that security software may detect network communication from an unrecognised process and terminate your implant. One solution to this of course, among many, is process injection/migration, thus helping to extend the longevity of your implant.

Process injection can also help your implant blend in to a victim's environment. For example injecting into an svchost.exe process if it's making network traffic, or within notepad.exe if it is reading files. As a result the blue team and accompanying security software have to be that bit more sophisticated in order to detect your implant.

## Fundamental Theory

#### Processes Threads and Win32 API

According to [this piece of Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/procthread/about-processes-and-threads), the definition to a process on windows is as follows:

*"A process has a virtual address space, executable code, open handles to system objects, a security context, a unique process identifier, environment variables, a priority class, minimum and maximum working set sizes, and at least one thread of execution. Each process is started with a single thread, often called the primary thread, but can create additional threads from any of its threads."* ~ [Microsoft](https://docs.microsoft.com/en-us/windows/win32/procthread/about-processes-and-threads)

On the other hand, a thread executes the compiled assembly code of its parent Process. A process may have multiple threads executing code at any given time to allow for simultaneous execution of code. An important property to keep in mind is that each thread will have its own stack, whilst *sharing* the virtual memory address space of the parent process!

As previously mentioned, each process has its own seperate virtual address space, and although these spaces are not meant to interact with one another it is possible to accomplish this by taking advantage of the Win32 API. The general idea is to initiate process injection by opening a communication channel from one process to another through the Win32 API's `OpenProcess` API. This allows you to modify its memory space through the use of `VirtualAllocEx` and `WriteProcessMemory` APIs. Finally creating a new execution thread inside the remote process via `CreateRemoteThread`.

#### OpenProcess API

**What does it do and how do I use it?**

The [`OpenProcess` API](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) opens an existing local process object for interaction and returns a process handle to the user. A total of three parameters are required when being called, and are as follows.

1. `dwDesiredAccess`
    - The access to the process object.
    - This access right is checked against the security descriptor for the process, and its value can be one or more of the [process access rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
2. `bInheritHandle`
    - If this value is `TRUE`, processes created by this process will inherit the handle. Otherwise the processes do not inherit this handle.
    - For the sake of process injection, this is not required and thus `false` will be passed to the call.
3. `dwProcessId`
    - The process identifier (pid) of the local process to be opened.
    - If this specified process is the `System Idle` process (0x0), the API call will fail with an error code `ERROR_INVALID_PARAMETER`.
    - If the specified process is the `System` process or one of the `Client Server Run-Time Subsystem` (CSRSS) processes, this call again will fail with the error code `ERROR_ACCESS_DENIED` because their access restrictions prevent user-level code from opening them.

**What processes is it possible to inject in to?**

In order to call `OpenProcess` successfully, your current process must possess the appropriate security descriptor. Every process has a Security Descriptor that specifies the file permissions of the executable and access rights of a user or group which originates from the creator of said process. This aims to block privilege escalation.

In addition to this, all processes also have an integrity level that restricts access to them. This works by blocking access from one process to another that has a higher integrity level, however accessing a process with a lower or equal integrity level is generally possible.

A great example of this is when trying to inject into a process such as `notepad.exe`. If you were to run notepad as a normal user you would see that the process runs at a medium integrity level (normal for most processes), and thus you should be able to inject into it. However, if you were to run `notepad.exe` as an administrator, it would run as a high integrity level process and thus unless you have attained administrator / system privileges prior to injection, it will not be possible.

#### Selecing a Target