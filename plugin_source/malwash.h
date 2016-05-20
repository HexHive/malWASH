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
**	malWASH - The malware engine for evading ETW and dynamic analysis - ** The splitting engine **
**
**	Version 2.0
**
**	malwash.h
**
**	This file has all definitions and declarations of global variables, functions and types.
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015
*/
//-----------------------------------------------------------------------------------------------------------
#include <ida.hpp>											// ida sdk includes
#include <idp.hpp>
#include <area.hpp>
#include <auto.hpp>
#include <allins.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <pro.h>
#include <search.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <stdlib.h>											// standard C includes
#include <string.h>
#include <stdarg.h>     /* va_list, va_start, va_arg, va_end */
//-----------------------------------------------------------------------------------------------------------
// define some usuful MACROs
#define PACK(a,b,c,d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define UNPACK_1(a)    ((a) >> 24)
#define UNPACK_2(a)   (((a) >> 16) & 0x000000ff)
#define UNPACK_3(a)   (((a) >>  8) & 0x000000ff)
#define UNPACK_4(a)    ((a)        & 0x000000ff)
//-----------------------------------------------------------------------------------------------------------
/* type definitions */
typedef unsigned long int	addr;							
typedef unsigned int		uint;
typedef unsigned char		uchar, byte;
typedef unsigned short int	ushort;
//-----------------------------------------------------------------------------------------------------------
/* enum definitions */
enum debugmode  { NONE=1, VERBOSE, VERY_VERBOSE };			// info verbosity
enum splitmode  { BBS=1, BAST, PARANOID };					// splitting algorithms		
enum mainstyle  { MAIN=1, WINMAIN, NOTHING };				// main function style
enum duptype    { DUPNONE=0xff,								// duplicated type
				  DUPHANDLE=0x01, DUPHANDLE2=0x02, CLOSEHANDLE=0x05, 
				  DUPSOCK  =0x03, DUPSOCK2  =0x04, CLOSESOCK  =0x06,

				  DUPPTRHANDLE=0x81, DUPPTRHANDLE_2=0x82
				}; 

enum convention { CDECL=1, STDCALL };						// calling convention
enum heapoper	{ ALLOC=1, FREE, MMAP, FREERWD };			// heap operation
//-----------------------------------------------------------------------------------------------------------
/* structure definitions */

struct funcrel_t {											// function table entry
	// reserve msbit for function call type
	ushort	boff,											// offset in block
			funtaboff;										// offset in function table
};

struct segmrel_t {											// segment table entry
	ushort	boff,											// offset in block
			segtaboff;										// offset in function table
};

struct initptr_t {											// initialized pointer to other segment table entry
	ea_t	src_seg, dst_seg;								// source and dest segment start EA
	uint	seg_off;										// offset in segment
};

struct dup_t {												// duplicated SOCKET/HANDLE entry
	ushort	boff,											// offset in block
			nargs;											// number of function's arguments
	uint	loc;											// location that need to be duplicated
															// (0 for return address, i>0 for i-th argument)
															// also MSBit denotes duplication type
};

struct heap_t {												// heap entry
	ushort	boff;											// offset in block
	uint	info;											// heap info (location of argument + calling 
															// convention + alloc/free type)
};
//-----------------------------------------------------------------------------------------------------------
/* MACRO definitions */
// Everything is static, so please don't overflow me :)
#define MSBIT				0x80000000						// MSBit mask
#define MSBIT2				0x40000000						// 2nd MSBit mask
#define NOTMSBIT			0x7FFFFFFF						// ~MSbit mask
#define NOTMSBIT2			0xBFFFFFFF						// ~ 2nd MSbit mask
#define ERROR				0xffffffff						// error value
#define ANY					0x0000ff7f						// this is for special cases only
#define SUCCESS				0x0								// success value
#define SHORT				0x0000ffff						// mask for casting to short int
#define MAXBUFLEN			256								// max buffer length
#define MAXFUNAMELEN		128								// max function name length
#define MAXSEGNAMELEN		16								// max segment name length
#define MAXMODNAMELEN		64								// max imported module name length
#define MAXCONCURNPROC		16								// max number of injected processes
#define FUNTBLSIZE			4096							// max function table size
#define MODTBLSIZE			128								// max module table size
#define SEGTBLSIZE			256								// max segment table size
#define MAXBLKSIZE			2048							// max block size
#define MAXFUNCRELOC		32								// max function relocation table size
#define MAXSEGMRELOC		128								// max segment relocation table size
#define MAXINITPTRTBLSIZE	64								// intialized pointer table size
#define MAXDUPTABSZ			8								// max duplicate table size
#define MAXHEAPTABSZ		16								// max heap table size
#define MAXMNEMLEN			128								// max instruction mnemonic length
#define MAXCACHESIZE		1048576							// maximum cache size for transfers (aux)
#define DUPUNIQUESIG		0x1337beef						// a unique signature before the start of a dup* hook
#define DUPDETOURADDR		0x19700000						// predefined-known address of dup* detour
#define EOSCHAR				"\x0a"							// a non-printable ASCII character for End Of String
#define EOSCHAR_CH			'\x0a'							// and its signle character version
#define	AVSIGTHRESHOLD		16								// Anti Virus minimum signature threshold
#define STACKBASEADDR		0x19900000						// stack virtual base address
#define STACKSIZE			0x20000							// stack size
#define STACKBASEADDR2		0x19900040						// different call caches for different dependencies
#define SEGMBASEADDR		0x1bb00000						// 1st segment virtual base address
#define SEGMNXTOFF			0x20000							// virtual offset between segment base address
#define HEAPBASEADDR		0x1cc00000						// heap starts from here
#define ARGVBASEOFF			0x200							// base address of argv table
#define ARGVPTRBASEOFF		0x240							// base address of argv pointers 
#define ARGVNXTOFF			0x40							// offset between argv pointers
#define MAXIMPFUNDECLLEN	384								// max imported function declaration name length
#define MAXCONSTARRAYSIZE	12288							// max allowed size for constant arrays (compiler limitations)
															// functions like CreateWindowEx can have length > 200
#define OUTFILENAME			"malWASH_final.cpp"				// output file name
#define OUTFILENAME_PART1	"..\\malWASH_intr\\code_1"		// first part of malWASH source
#define OUTFILENAME_PART2	"..\\malWASH_intr\\code_2"		// second part of malWASH source
#define MIN(a,b)			((a) < (b) ? (a) : (b))			// min of 2 values
//-----------------------------------------------------------------------------------------------------------
/* global variables */
extern netnode		edge,									// edges between blocks
					visited,								// mark visited insturctions
					segment,								// segment information
					invbid,									// inverse search (bid -> address)
					thdtab,									// thread routines
					indfunc;								// indirect function relations


extern segment_t	*idata;									// import segment pointer
	
extern char			funtab[ FUNTBLSIZE ];					// function table
extern uint			funtablen;								// function table size
extern char			modtab[ FUNTBLSIZE ];					// module table
extern uint			modtablen;								// module table size
extern char			segtab[ FUNTBLSIZE ];					// segment table
extern uint			segtablen;								// segment table size
extern initptr_t	initptr[MAXINITPTRTBLSIZE];				// store initialized pointers that need relocation
extern uint			initptrcnt;								// initptr table counter
extern uint			nblks, nsegms, nprocs;					// total number of blocks, segments and processes
extern qstrvec_t	funclist;								// a list of all available functions
extern long long int perfcount;								// performance counter
//-----------------------------------------------------------------------------------------------------------
/* functions declarations */
func_t *locmain(char *);									// locate main

void	addedge(ea_t, ea_t, debugmode);						// add an edge between 2 blocks
uint	funcsplit(func_t*, splitmode, debugmode);			// split a function

void	printbbstat(debugmode);								// print basic block statistics
uint	relocblks();										// relocate basic blocks
void	initptrchk( ea_t );									// check for initialized pointers to other segments
void	fatal( const char*, ...);							// fatal errors

uint	stintsegrange(ea_t, ea_t, char*);					// store internal segment range: Store a range of 
															// a segment to a file

uint	storeblk(uint, uchar*, uint, segmrel_t*, uint,		// store a block to a file
					funcrel_t*, uint, dup_t*, uint, heap_t*, uint);

uint	storefuntab();										// store function table
uint	storesegtab();										// store segment table
uint	storemodtab();										// store segment table
uint	storesegms();										// store segments from segment table
uint	storethdtab();										// store thread table
uint	storeinitptrs();									// store initialized pointer table

uint	dupchk(ea_t, ushort*);								// check for SOCKET/HANDLE arguments
uint	heapchk(ea_t);										// check for heap memory management
uint	crthook(byte *, uint *, dup_t*, uint,				// create a hook for dealing with arguments that
					funcrel_t*, uint);						// needs duplication

uint	heaprepl(uchar*, uint *, heap_t*, uint,
					funcrel_t*, uint*);						// replace heap manipulation functions

uint	pack(char*, bool, mainstyle, char*);

void __stdcall IDAP_term(void);								// plugin "destructor" (called upon exit)
//-----------------------------------------------------------------------------------------------------------
