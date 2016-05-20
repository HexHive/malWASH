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
**  ** The splitting engine ** - Version 2.0
**
**	heap.cpp
**
**	This file contains code for dealing with heap manipulayion. Most of the job is also done on executer,
**  but the basic setup is done here. The general idea, is to totally replace heap management functions,
**	with calls to shared management functions. Let's focus on the most important categories:
**
**	[A]. heap allocation: we replace that call with a another call that creates a shared memory region at a 
**		 known address. Then we inform other processes to attach that shared region at the same address. 
**		 Note that it's very important for all processes to access the shared region at the same virtual 
**		 address (otherwise a valid heap pointer at process A, will be invalid at process B). Note that
**		 because we're in shared regions, the only argument that we're insterested in, is the size (we
**		 ignore other arguments).
**
**	[B]. heap deallocation: we release the shared region, and we inform other processes to detach from
**		 that region.
**	
**	[C]. heap reallocation: this can be done with the silly way: 
**		 [1]. Copy all the contents of the shared region
**		 [2]. Deallocate the shared region, and allocate a new one with the requested size at the same
**			  virtual address.
**		 [3]. Copy the contents back to the new (maybe larger) shared region.
**
**	[D]. heap size: we keep a table in shared control region, that contains pairs: (virtual_address, size).
**		 when a size requested, we do a lookup in that table.
**	
**	[E]. lock/unlock: These functions doesn't really make any sense to implement them in our "shared" fashion.
**
**	[F]. Other types, like LocalHandle, GlobalHandle, etc. are not considered too.
**
**	From the above categories, [A], [B] are the most common. Other types are really rare. Although it's not 
**	really hard to implement [C] and [D] we won't implement them in this version. Taking everything into 
**	account let's see the function we're going to replace:
**
**		HGLOBAL WINAPI GlobalAlloc (UINT uFlags, SIZE_T dwBytes);
**		HGLOBAL WINAPI GlobalFree  (HGLOBAL hMem);
**		LPVOID	WINAPI HeapAlloc   (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);	
**		BOOL	WINAPI HeapFree    (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
**		HLOCAL	WINAPI LocalAlloc  (UINT uFlags, SIZE_T uBytes);
**		HLOCAL	WINAPI LocalFree   (HLOCAL hMem);
**		LPVOID  WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
**		BOOL    WINAPI VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
**		void*	__cdelc malloc     (size_t size);
**		void	__cdelc free       (void* ptr);
**
** And these are most of the function that we do NOT replace:
**		HGLOBAL WINAPI GlobalReAlloc (HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
**		SIZE_T  WINAPI GlobalSize    (HGLOBAL hMem);
**		LPVOID  WINAPI GlobalLock	 (HGLOBAL hMem);
**		BOOL	WINAPI GlobalUnlock  (HGLOBAL hMem);
**		HGLOBAL WINAPI GlobalHandle  (LPCVOID pMem);
**		LPVOID	WINAPI HeapReAlloc   (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
**		SIZE_T	WINAPI HeapSize      (HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);	
**		BOOL    WINAPI HeapLock      (HANDLE hHeap);
**		BOOL    WINAPI HeapUnlock    (HANDLE hHeap);
**		HLOCAL	WINAPI LocalReAlloc  (HLOCAL hMem, SIZE_T uBytes, UINT uFlags);
**		UINT	WINAPI LocalSize     (HLOCAL hMem);
**		LPVOID	WINAPI LocalLock     (HLOCAL hMem);
**		BOOL	WINAPI LocalUnlock   (HLOCAL hMem);
**		HLOCAL  WINAPI LocalHandle	 (LPCVOID pMem);
**		BOOL    WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
**		SIZE_T  WINAPI VirtualQuery  (LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
**		void*	__cdelc calloc		 (size_t num, size_t size);
**		void*	__cdelc	realloc		 (void* ptr, size_t size);
**
** NOTE: Virtual**Ex() function family is not a problem as it already deals with different process address
**		 space.
**
** WARNING: Note the different calling convention in malloc/free (__cdecl) from others (WINAPI = __stdcall)
**
** WARNING: Another type of functions that we do NOT handle, is the indirect memory allocation through
**	CreateFileMapping() and MapViewOfFile() (that's 1 example). In other words, if process A allocates
**	a shared region, this region, won't be available in other processes. (we can also replace these
**	functions, but not in this version).
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"										// all includes are here


//-----------------------------------------------------------------------------------------------------------
/*
**	heaprepl(): Create a hook function (detour) for a heap manipulation function.
**
**	NOTE: We can avoid hooks and insert extra code in the middle of block instead. This solution will work
**		when we have a basic block split (as there are no relative jumps within blocks). However if we use 
**		a different splitting mode and each block consist of many basic blocks, this approach won't work.
**
**	Arguments:  blk       (uchar*)     : Block opcodes
**              blkcnt    (uint)       : Block size
**              heaptab    (dup_t*)    : A pointer to heap table
**              heapcnt    (uint)      : # of heaptab entries
**              funcrel   (funcrel_t*) : A pointer to funcrel
**              funrelcnt (uint)       : # of funcrel entries
**
**	Return Value: Function returns constant SUCCESS. If an error occured, it returns -1
*/
uint heaprepl( uchar blk[], uint *blkcnt, heap_t heaptab[], uint heapcnt, funcrel_t funcrel[], uint *funrelcnt )
{
	// redefine these MACROS
#define PBYTE1(b)          (blk[(*blkcnt)++] = (b) & 0xff)	// append a single byte to blk array
#define PLONG(l)           *(uint*)(blk + *blkcnt) = (l); *blkcnt += 4	// append a 4 byte integer to blk array
#define PBYTE2(a, b)	   PBYTE1(a); PBYTE1(b)				// append 2 bytes to blk array
#define PBYTE3(a, b, c)	   PBYTE2(a, b); PBYTE1(c)			// append 3 bytes to blk array
#define PBYTE4(a, b, c, d) PBYTE3(a, b, c); PBYTE1(d)		// append 4 bytes to blk array
#define SET_EBX(target)    PBYTE1(0xBB); PLONG(target)		// write the instruction mov ebx, _long_


	ushort	jmpoff = *blkcnt,								// store current block size
			heaprepl;										// offset of the unknonw internal heap* function
	uint arg, narg, callconv, op;							// argument location, number of arguments,
															// calling convention and heap operation


	if( heapcnt == 0 ) return SUCCESS;						// if there are no heap functions, exit
	
	// reserve 5 bytes for adding a relative far jump to skip function definitions.
	// (we can add a relative near jump (1 byte offset) but it's dangerous)
	*blkcnt += 5;

	for(uint h=0; h<heapcnt; h++ )							// for each entry in heaptab
	{
		if( blk[heaptab[h].boff + 1] != 0x15 )				// we consider only indirect calls
		{
			// we have an indirect jump to imported library.
			// we can handle it by doing exactly the same thing with indirect jumps in patchblk().
			// however because we'll end up with large code snippets, we won't handle in this version
			fatal( "Current version cannot replace trampoline heap manipulation functions" );

			return ERROR;									// abort
		}

		//
		// We have 3 cases: One very common and 2 very rare. We can have a call to heap manipulation function
		// or an indirect jump through a trampoline function. Let's start with the 1st case:
		// .text:00411629 68 00 04 00 00        push    400h                        ; uBytes
		// .text:0041162E 6A 00                 push    0                           ; uFlags
		// .text:00411630 FF 15 FC 92 41 00     call    ds:__imp__LocalAlloc@8      ; LocalAlloc(x,x)
		//
		// The idea here is to totally replace call to LocalAlloc(). The information we need here, is the
		// size of the memory that we need to allocate (or the address of memory that we want to release)
		// and then we can call an internal function in executer (we don't know its address at compile time).
		// This internal function will allocate (or deallocate) a shared region and will inform the other
		// processes to perform the right actions. Note that if we have stdcall convention we have to adjust
		// the stack. The above example will be:
		//
		// seg000:00000052 68 00 04 00 00        push    400h
		// seg000:00000057 6A 00                 push    0
		// seg000:00000059 90                    nop
		// seg000:0000005A E9 87 00 00 00        jmp     loc_E6
		// seg000:0000005F                   loc_5F: 
		// seg000:0000005F 89 85 38 FE FF FF     mov     [ebp-1C8h], eax
		//
		// seg000:000000E6                   loc_E6: 
		// seg000:000000E6 51                    push    ecx
		// seg000:000000E7 8B 4C 24 04           mov     ecx, [esp+4]
		// seg000:000000EB E8 90 90 90 90        call    near ptr 90909180h
		// seg000:000000F0 59                    pop     ecx
		// seg000:000000F1 83 C4 08              add     esp, 8
		// seg000:000000F4 E9 66 FF FF FF        jmp     loc_5F
		//
		// We get the right argument at ecx and we call (fastcall) the internal function (we don't know its 
		// address yet). then we adjust the stack and we jump back. In case of cdecl convention we omit the
		// last instruction (add esp, ??).
		// 
		// NOTE: we can also do the hook with call/ret instead of 2 jmp. It's the same.
		//
		// Let's see a cdelc example:
		//		.text:00411636 6A 0A                 push    0Ah                         ; Size
		//		.text:00411638 FF 15 B0 93 41 00     call    ds:__imp__malloc
		//		.text:0041163E 83 C4 04              add     esp, 4
		//
		// As long as caller cleans the arguments we don't need to do anything.
		//
		// In case of indirect jumps to heap* functions, we have to find the next block from the return
		// address. We can do the same trick that we did in patchblk() to handle indirect calls. However
		// we won't implement this in current version.
		//
		// The last case is when a process calls MapViewOfFile(Ex)(). This is not exactly a heap operation, 
		// but our response is pretty similar. First of all the mapping should be done in the same address
		// for all processes. Otherwise we are going to raise an SIGSEGV. The only difference with the other
		// heap operation is that we have to initialize the contents of the empty memory with the contents
		// of the mapping object. The idea here is to totally replace MapViewOfFile() and MapViewOfFileEx()
		// with a function that does the following:
		//	[1]. It calls MapViewOfFileEx() to map the file object in the next emply slot in the heap. Note
		//		 that we ignore the other arguments and we map it with the default. A more subtle impleme-
		//		 ntation may take care of them.
		//	[2]. It send a memory allocation message to the other processes.
		//
		msg( "        [+] Creating a hook function for replacing heap* function at offset %d\n", heaptab[h].boff);
		

		arg      = (heaptab[h].info & 0x000000ff);			// get important argument
		narg     = (heaptab[h].info & 0x0000ff00) >> 8;		// get number of arguments
		op       = (heaptab[h].info & 0x00ff0000) >> 16;	// get operation (alloc/free)
		callconv = (heaptab[h].info & 0xff000000) >> 24;	// get calling convention
		
		heaptab[h].info = op;								// the only information that executer needs to know

		// overwrite heap function. Do not do any actuall call to heap
		blk[ heaptab[h].boff ] = 0x90;						// nop
		blk[heaptab[h].boff+1] = 0xe9;						// jump + find the offset
		*(uint*)(blk + heaptab[h].boff + 2) = (*blkcnt - heaptab[h].boff - 6);
			
		heaprepl = *blkcnt + 6;								// get offset of heap* function call


		PBYTE1( 0x51 );										// push ecx
		
		// get the important agrument (if it's the 1st arg, we can use a 3 byte instruction also)
		// remember that you push a backup of ecx, so the 1st argument will be at [esp + 4]
		//    8b 4c 24 04             mov    ecx,DWORD PTR [esp+0x4]
		//	  8b 0c 24                mov    ecx,DWORD PTR [esp] 
		PBYTE4( 0x8b, 0x4c, 0x24, (((arg&0x7f)+1)<<2)&0xff);// mov ecx, dword ptr[esp + ??]		
		
		if( arg & 0x80 ) 									// if we have 2 arguments 
		{
			PBYTE1( 0x52 );									// push edx
			PBYTE4( 0x8b, 0x54, 0x24, 8 );					// mov edx, dword ptr[esp + ??]	(we did 2 push)

			heaprepl += 5;									// we add 5 more bytes
		}
		
		PBYTE1( 0xe8 );										// call
		PLONG( 0x90909090 );								// we can use this space to store info

		if( arg & 0x80 ) PBYTE1( 0x5a );					// pop edx (if needed)
		PBYTE1( 0x59 );										// pop ecx

		if( callconv == STDCALL ) {							// we have to clear args in STDCALL
			PBYTE3( 0x83, 0xc4, (narg << 2) & 0xff);		// (83 c4 ??) add esp, ?? 
		}

		PBYTE1( 0xe9 );										// jump back to the instruction after hook
		PLONG( -(int)(*blkcnt - heaptab[h].boff - 2) );		// 

		for(uint i=0; i<*funrelcnt; i++ )					// search through function relocation table
			if( funcrel[i].boff == heaptab[h].boff + 2 )	// if you find the relocation to our heap function
			{												// delete it
				// remove that entry from function table 
				// we don't want to relocate a function that doesn't exist
				funcrel[i].boff		 = funcrel[*funrelcnt-1].boff;
				funcrel[i].funtaboff = funcrel[--(*funrelcnt)].funtaboff;
				break;
			} 

		heaptab[h].boff = heaprepl;							// update function offset that we must relocate
	}

	// we insert hooks at the end of basic block. We have to finish basic block with a jump to skip hooks:
	blk[ jmpoff ] = 0xe9;									// jump
	*(uint*)(blk + jmpoff + 1) = (*blkcnt - jmpoff - 5);	// find offset (5 = jump size)


	return SUCCESS;											// success!

#undef SET_EBX												// undefine MACROS
#undef PBYTE4
#undef PBYTE3
#undef PBYTE2
#undef PLONG
#undef PBYTE1
}
//-----------------------------------------------------------------------------------------------------------
/*
**	heapchk(): This function checks whether an imported function from a module is dynamic memory allocation
**		or deallocation function (as noted above, we don't consider other types of memory management 
**		functions).
**		The only important thing here, is a that all processes must load the shared "heap" region at the 
**		same virtual address. Otherwise a valid pointer to heap at process A will be invalid at process B.
**
**	Arguments:  iaddr (ea_t) : Address of the instruction that transfers control to the imported module
**
**	Return Value: If any errors occured, the return value is -1. Otherwise function returns a 32bit number
**		The 8 LSBits of this number denote the location of the argument. The next 8 bits denote the number
**		of function arguments. The next 8 bits denote heap operation (alloc and free currently support). 
**		The last 8 bits show the calling convention (cdecl, or stdcall).
*/
uint heapchk( ea_t iaddr )
{
	const char *forbidden[] =								// a list of all functions that we don't replace 
	{
		"GlobalReAlloc" , "GlobalSize"  , "GlobalLock", "GlobalUnlock", "GlobalHandle",
		"HeapReAlloc"   , /*"HeapSize"  ,*/ "HeapLock"  , "HeapUnlock"  ,
		"LocalReAlloc"  , "LocalSize"   , "LocalLock" , "LocalUnlock" , "LocalHandle",
		/*"VirtualProtect", "VirtualQuery", */
		"calloc"        , "realloc"     , 0
	};
	char	func   [MAXFUNAMELEN];							// function name	
	uint arg, narg, callconv, op;							// argument location, number of arguments,
															// calling convention and heap operation


	// get address of function entry in IAT (always an imported function; relocfun() can guarantee this)
	// get name of address from .idata
	get_name(BADADDR, get_first_dref_from(iaddr), func, MAXFUNAMELEN);		
	 
	for( uint i=0; forbidden[i]!=NULL; i++ )				// for each forbidden function
		if( strstr(func, forbidden[i] ) )					// check if it matches with imported function
		{
			fatal("Current version cannot replace %s()", forbidden[i]);
			return ERROR;
		}

	// fuction is not on the black list, check if needs to be replaced
		 if( strstr(func, "malloc")         ) {callconv = CDECL;   op = ALLOC;  arg = 0; narg = 1;}
	else if( strstr(func, "free")           ) {callconv = CDECL;   op = FREE;   arg = 0; narg = 1;}
	else if( strstr(func, "GlobalAlloc")    ) {callconv = STDCALL; op = ALLOC;  arg = 1; narg = 2;}
	else if( strstr(func, "GlobalFree")     ) {callconv = STDCALL; op = FREE;   arg = 0; narg = 1;}
	else if( strstr(func, "HeapAlloc")      ) {callconv = STDCALL; op = ALLOC;  arg = 2; narg = 3;}
	else if( strstr(func, "HeapFree")       ) {callconv = STDCALL; op = FREE;   arg = 2; narg = 3;}
	else if( strstr(func, "LocalAlloc")     ) {callconv = STDCALL; op = ALLOC;  arg = 1; narg = 2;}
	else if( strstr(func, "LocalFree")      ) {callconv = STDCALL; op = FREE;   arg = 0; narg = 1;}
	else if( strstr(func, "VirtualAlloc") && 
		    !strstr(func, "VirtualAllocEx") ) {callconv = STDCALL; op = ALLOC;  arg = 1; narg = 4;}
	else if( strstr(func, "VirtualFree")  &&
			!strstr(func, "VirtualFreeEx")  ) {callconv = STDCALL; op = FREE;   arg = 0; narg = 3;}
	else if( strstr(func, "MapViewOfFileEx")) {callconv = STDCALL; op = MMAP;   arg = 0x84; narg = 6;}
	else if( strstr(func, "UnmapViewOfFile")) {callconv = STDCALL; op = FREERWD;arg = 0x0;  narg = 1;}
	else if( strstr(func, "MapViewOfFile")  ) {callconv = STDCALL; op = MMAP;   arg = 0x84; narg = 5;}
	else return ANY;

	// pack information
	return (callconv << 24) | (op << 16) | (narg << 8) | arg;
}
//-----------------------------------------------------------------------------------------------------------
