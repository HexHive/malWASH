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
**  ** The splitting engine ** - Version 2.0
**
**
**	core.cpp
**
**	This file is the core of the plugin. It's responsible for splitting the executablle into multiple
**	pieces. We assume that there are no anti dissasembly protections, or any code obfuscation. Every
**	instruction and jump target must be known at compile time. We support 3 splitting modes:
**		[1]. BBS - Basic Block split - Split binary into its basic blocks
**		[2]. BAST - Below AV Signature Threshold - Every piece is smaller that the number of bytes used by 
**				AV for signature detection (usually it's 16 bytes)
**		[3]. Paranoid - Every instruction belongs to a different block - Huge performance impact. This mode
**				it's not really realistic
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"										// all includes are here


netnode edge,												// store the relations between basic blocks
		visited,											// store the bid for each address
		thdtab,												// store thread entry points
		indfunc;											// store indirect function relations
//-----------------------------------------------------------------------------------------------------------
/*
**  fatal(): This function is called when fatal error are occured. fatal() prints the error description and
**		terminates execution of plugin
**
**	Arguments: fmstring (char*) : A format string, containing the error description
**              ...             : maybe more arguments follow
**
**  Return Value: None.
*/
void fatal( const char *fmstring, ... )
{
	va_list args;											// our arguments
	qstring	fsbuf;											// our format string buffer


	va_start( args, fmstring );								// start using variable argument list
	fsbuf.vsprnt( fmstring, args );							// load error message in fsbuf
	va_end( args );                                         // stop using variable argument list

	msg("\n[ERROR]: %s. \n[+] Aborting Execution.\n\n", qstrdup(fsbuf.c_str()) );
//	warning("[ERROR]: %s. ", qstrdup(fsbuf.c_str()) );

	visited.kill();											// delete netnodes from database
	segment.kill();
	invbid.kill();
	edge.kill();

	// error("%s. Aborting Execution\n\n", qstrdup(fsbuf.c_str()) );
	// qexit(ERROR);

}
//-----------------------------------------------------------------------------------------------------------
/*
** locmain(): Search for a function and returns a pointer to it.
**
**	Arguments: name (char*): A pointer to a string containing function name
**
**	Return Value: A pointer to the requested function. If function doesn't exist, a NULL is returned.
*/
func_t *locmain(char *name)
{
	char fname[256];										// plz don't overflow me :)

	for(uint idx=0; idx<get_func_qty(); idx++) {			// iterate over functions

		get_func_name(getn_func(idx)->startEA, fname, sizeof(fname));

		if( strcmp(fname, name) == 0 )						// match found?
			return getn_func(idx);							// if so, return pointer
	}

	return NULL;											// failure. Return null
}
//-----------------------------------------------------------------------------------------------------------
/*
**	addedge(): This function adds an edge between 2 basic blocks.
**	
**	Arguments:	from (ea_t)	     : Effective address of source basic block
**				to   (ea_t)	     : Effective address of target basic block
**              dm   (debugmode) : The level of information will be printed
**
**	Return Value: None.
*/
void addedge(ea_t from, ea_t to, debugmode dm)
{
	uchar	edglst[256] = { 0 };							// store here edge list
	size_t 	len;											// list length
	uint	bfrom, bto;										// block ids


	bfrom = visited.altval(from) & NOTMSBIT;				// get bids from addresses
	bto   = visited.altval(to)   & NOTMSBIT;
	

	if( from == to ) return;								//  do not add edges to the same address

	// for ret instructions, it's possible to have a return address in instruction that is not belong 
	// to any basic block (e.g. a function can be called in init() before main(), so retn instruction 
	// can go to instruction inside init(), which we have split it). In such cases we set next block 
	// to -1, to avoid conflicts with NULL terminating byte in edge list.
	if( bto == 0 ) bto = 0xffff;

	if( (len=edge.supval(bfrom, NULL, 0, 'E')) == -1 )		// empty list ?
		len = 0; 
	else edge.supval(bfrom, edglst, len, 'E');				// if not get it

	((ushort*)edglst)[len>>1] = bto & SHORT;				// store 2 byte bid (look edglst as ushort[128])
	
	edge.supset(bfrom, edglst, len+2, 'E');					// store list back to netnode
	

	if( dm != NONE )										// print detailed information?
	{
		ushort *e;											// edge list pointer
		uint	i;											// iterator

		edge.supval(bfrom, edglst, len+2, 'E');				// update edge list

		msg( "    [*] Block targets from %3d: ", bfrom )	;
		
		for( i=0, e=(ushort*)edglst; i<=len>>1; ++i, ++e )	// print each element
			msg( "%3d, ", *e );
		
		msg( "\n" );					
	}
}
//-----------------------------------------------------------------------------------------------------------
/*
**	basicblksplit(): This function does splits a function into basic blocks. It uses a simple Depth-First
**		Search (DFS) algorithm. We treat current function that we're splitting as a tree, with the nodes 
**		being the basic blocks and the edges the xrefs from. Note that function is recursive.
**
**	Arguments:	cfun (func_t*)	: A pointer to the current function
**				curr (ea_t)		: The current address to start spliting
**              cm  (splitmode) : The splitting algorithm 
**              dm   (debugmode) : The level of information will be printed
**
**	Return Value: The number of instructions that the last basic block had (it's usefull only for internal
**		function operations).
*/
uint basicblksplit(func_t *cfun, ea_t curr, splitmode sm, debugmode dm)
{
	static uint bid = 1;									// set block ID (start from 1, 0 is a special case)
	char		temp[MAXBUFLEN];							// auxilary buffers
	uint		binst;										// total number of instructions
	ea_t		prev = curr;								// instruction before current instruction	
	insn_t		loccmd;										// backup of cmd global variable (we need it to avoid
															// problems during recursion).
	uint		nxref;										// number of xrefs from
	ea_t		nxt;										// next possible instruction
	uint		bast_len = 0;								// total block length in BAST mode;
	ea_t		psbthdrtn = 0;								// possible thread entry point
	static bool	crtthreadlast = false;						// was the last instruction CreateThread() call?
															// it's static to be persistent between recusrions
	// PROBLEM: if prev declared after loccmd, we get an exception of corrupted stack near loccmd.


	// parsing instructions one after another, until one of these occur:
	//   [1]. Reach the end of the function
	//   [2]. Visit an instruction that already belongs to another block
	for(binst=0; !(visited.altval(curr) >> 31) && curr<cfun->endEA; curr+=loccmd.size )
	{
		segment_t	*text;									// our .text segment
		char		name[ MAXBUFLEN ];						// store name here


		decode_insn(curr);									// decode current instruction
		loccmd = cmd;										// cmd is global (in ua.hpp). Make a local copy of it
	
		visited.altset(curr, (ulong)(MSBIT | bid));			// assign a block ID
		++binst;											// we want to increase AFTER we verify that the
															// loop condition is true

		_ltoa_s(bid, temp, MAXBUFLEN, 10);					// DEBUG: comment instructionns with block IDs
		set_cmt(curr, temp, false);							// (use the safe version of ltoa)

		if( dm == VERY_VERBOSE )							// print more information ?
			msg( "    [-] Visiting block %3d. Current Address:%x\n", bid, curr );
	
		
		/*-------------------------------------------------------------------------------
		** Special Case: CreateThread()
		-------------------------------------------------------------------------------*/		
		text  = get_segm_by_name(".text") == NULL ? get_segm_by_name("CODE") : get_segm_by_name(".text");
		idata = get_segm_by_name(".idata");					// find .idata (import) segment
				

		// Instructions after CreateThread() should be on the same block with it. However
		// they're not because we fist split thread routines. In such case we have to
		// add the missing edge
		if( crtthreadlast )									// add the missing edge
			addedge( prev, curr, dm );

		if( (loccmd.itype == NN_callni || loccmd.itype == NN_callfi  ||
			(loccmd.itype == NN_jmpni && get_first_dref_from(curr) != BADADDR))  &&	
				idata && idata->startEA <= get_first_dref_from(curr) &&							
										get_first_dref_from(curr) <= idata->endEA )
		{
					
			// for call: the first code xref is to the instruction below. the next is function address 
			// for jmp: there's only 1 data xref from, which is the function address
			get_name(BADADDR,						
					(loccmd.itype == NN_jmpni) ? get_first_dref_from(curr) :
							 					 get_next_cref_from (curr, get_first_cref_from(curr) ), 
					name, MAXFUNAMELEN);					// get name of address from .idata
					
			if( strstr(name, "CreateThread\x00") )			// CreateThread() found ?
			{
				msg( "    [-] CreateThread() function call found at %x. Looking for thread entry point\n", curr );
						

				// We'll use a simply and silly method for identifying the thread routines:
				//	Every time we meet a push of a .text address we remember this address.
				//  If the first call that follows this push is a call to CreateThread(), then
				//	we can say that this is the Thread Routine. It's not very accurate, but it
				//	works well. Otherwise, we let the user to find the real entry point.
				if( psbthdrtn ) {							// do we have an entry point ?
					msg( "    [*] Entry point found at %x. Start splitting...\n", psbthdrtn );

					bid++;									// new block (there's no reason to change though)
					binst = 0;								// clear block counter 
						
					thdtab.altset(psbthdrtn, bid, 'T');		// make a pair of entry point and block 
					thdtab.altset(curr, bid, 'R');			// we need this to relocate CreateThread() later

					// split thread function
					if( funcsplit(get_func(psbthdrtn), sm, dm) > 0 ) {	
						bid += sm == PARANOID ? 0 : 1;		// new block
						binst = 0;							// clear block counter 
					}
					else if( sm == PARANOID ) bid--;		// adjust blocks

					nodeidx_t addr;
					// enumerate all different basic blocks
					for( addr=visited.alt1st(); addr!=BADNODE; addr=visited.altnxt(addr))
						if( visited.altval(addr) == bid )
							break;

					
					//if( addr == BADNODE ) bid--;
					

					msg("    [*] Done. Thread routine (%x-%x) splitted successfully.\n", 
								get_func(psbthdrtn)->startEA, get_func(psbthdrtn)->endEA );						
				}
				else {
					// we cannot identify thread entry point. User must specify it
					func_t	*thdroutine;					// pointer to thread routine
					int		thdfunc;						// potential thread routine
					bool	inside = false;					// check if we had at least 1 iteration 
					char	dialog[] =						// the GUI form prototype
					{
						"STARTITEM 0\n"										// the 1st item gets the input focus
						"The malWASH project: WARNING\n"					// set title
						"* * * WARNING: malWASH can't identify Thread Routine\n"
						"Please specify the potential Thread Routine\n"		// a label
						"<#Potential Thread Routine#:b:0:30::>\n\n"			// a dropdown list
						"<####I want to declare more Thread Routines:C>>\n"	// being verbose in output
					};
							

					bid++;								// new block (there's no reason to change though)
					binst = 0;							// clear block counter 

					for( ushort chkmask=1; chkmask; inside=true )	// as long as there are thread routines
					{
						// ask function from user
						if( AskUsingForm_c(dialog, &funclist, &thdfunc, &chkmask) != 1 )
							break;

						msg( "    [*] User specified function %s as thread entry point.\n", 
							qstrdup(funclist.at(thdfunc).c_str()) );

						if( (thdroutine = locmain(qstrdup(funclist.at(thdfunc).c_str()))) == NULL ) {
							// we're inside a recursion tree. We can't simply return
							error("Cannot locate thread routine");
						}

						msg( "    [*] Start splitting function at address %x\n", thdroutine->startEA );


						// make a pair of entry point and block
						thdtab.altset(thdroutine->startEA, bid, 'T'); 
								
						// we need this to relocate CreateThread() later
						thdtab.altset(curr, bid, 'R'); 

						// split thread function
						if( funcsplit(thdroutine, sm, dm) > 0 ) {		
							bid += sm == PARANOID ? 0 : 1;	// new block
							binst = 0;						// clear block counter 
						} 
						else if( sm == PARANOID ) bid--;	// adjust blocks


						nodeidx_t addr;
						// enumerate all different basic blocks
						for( addr=visited.alt1st(); addr!=BADNODE; addr=visited.altnxt(addr))
							if( visited.altval(addr) == bid )
								break;

						// if( addr == BADNODE ) bid--;


					}

					if( !inside ) bid--;					// we're 1 block ahead
				}	
				psbthdrtn = 0;								// clear it on every call
				crtthreadlast = true;						// last instrctuion is CreateThread call()
			} 
			else crtthreadlast = false;						// clear the flag
		}
		else if( loccmd.itype == NN_push &&					// we inspect push instructions
					text->startEA <= loccmd.Operands[0].value &&							
					text->endEA   >= loccmd.Operands[0].value )
		{						 
			msg( "    [-] Instruction 'push offset 0x%x' found at %x. Potential thread entry point...\n",
					loccmd.Operands[0].value, curr );


			psbthdrtn = loccmd.Operands[0].value;			// get possible entry point
		}
		else crtthreadlast = false;							// clear flag too
		/*-------------------------------------------------------------------------------
		** End of Special Case
		-------------------------------------------------------------------------------*/		


		// enumerate number of possible xrefs from this instruction first
		// (enumerate and splitting in 1 step can make code unstable)
		for( nxref=0, nxt=get_first_cref_from(curr); nxt!=BADADDR; nxt=get_next_cref_from(curr, nxt), ++nxref )
			;
		
		//
		// now, we'll divide instructions based on the number of xrefs from. An instrution may have 0, 1,
		// 2, or >2 xrers from. We'll use recursion even there's a single "path" to follow. This will help
		// us to keep our design clear and avoid writing many special cases.
		//
		// this is the most common case: There's only 1 xref from current instruction, usually to the 
		// instruction below. There are 3 possible sub-cases here:
		//		[1]. Next instruction is the instruction below
		//		[2]. Next instruction is the instruction below, but it's a target of another instr. below
		//		[3]. Current instruction is a "jmp somewhere"/"call something"
		// 
		// absolute call instructions, have 2 xrefs: 1 to the instruction below and one to the imported
		// function. We treat them as normal instruction with 1 xref from.
		//
		if( nxref == 1 ||									// only 1 xref from
			nxref == 2 && (loccmd.itype == NN_callfi || loccmd.itype == NN_callni) )
		{
			nxt = get_first_cref_from(curr);				// get first and only xref from
		
			if( (curr + loccmd.size != nxt) )				// sub-case [3]?
			{ 
				bid++;										// change bid
				binst = 0;									// clear block counter


				// add this check for MSVC++ compiler, to handle trampoline functions
				if( func_contains(get_func(curr), nxt) == false ) 
				{
					// we need this for finding return addresses. Function (A) which contains "curr" can 
					// indirectly transfer control to the function (B) that contains "nxt". Thus a retn
					// instruction from B can go to the parent function of A. Because we have retn instructions
					// we work backwards, so we map B -> A and not A -> B.
					if( get_func(nxt) && get_func(curr) )
						indfunc.altset(get_func(nxt)->startEA, get_func(curr)->startEA);


					// Special Case: when IDA encounters a call to ExitProcess(), it sets only 1 xref to 
					// the IAT entry of ExitProcess within .idata. Attemping to call funcsplit() will crash
					// IDA, so we have to change block.
					if( !get_func(nxt) ) break;


					if(funcsplit(get_func(nxt), sm, dm)>0) {// split the new function
						bid++;								// change bid
						binst = 0;							// clear block counter
					}
					
					addedge(curr, nxt, dm);					// connect trampoline with real function
					break;									// stop splitting trampoline, as
															// there's only 1 instruction there
				}
				else if( basicblksplit(cfun, nxt, sm, dm) > 0 ) {
					bid++;									// get a new block
					binst = 0;								// clear block counter 
				}

				addedge(curr, nxt, dm);						// add an edge between blocks
			}
			else {											// sub-cases [1]/[2] ?
				// check sub-case [2] first
				char name[ MAXBUFLEN ];						// store name here


				get_name(cfun->startEA,nxt,name,MAXNAMELEN);// get location name (if exists)	

				if( name[0] != 0 &&							// if name exists, 
					cfun->startEA<nxt && nxt<cfun->endEA && // name is not a function name and
					!(visited.altval(nxt) & MSBIT) )		// target is not visited yet
				{
					bid++;									// get a new block
					binst = 0;								// clear block counter 

					
					if( basicblksplit(cfun, nxt,sm,dm) > 0){// follow block
						bid++;								// get a new block
						binst = 0;							// clear block counter 
					}

					addedge(curr, nxt, dm);					// add an edge between blocks
				}
				// don't do anything for sub-case [1]

				// don't change block if you enter in the above if()
				else if( sm == BAST || sm == PARANOID )		// are we in BAST/Paranoid mode?
				{
					// things are trickier here. The key is that if we reach this point, we know that next
					// instruction is the instruction below. Thus we can predict if the next instruction will
					// exceed the threshold, and change our block ID.

					bast_len += loccmd.size;				// increase block size

					decode_insn(nxt);						// decode next instruction (only cmd will change)

					if(sm == PARANOID ||					// Paranoid mode or 
						bast_len+cmd.size > AVSIGTHRESHOLD)	// BAST mode and filled block ?
					{
						bid++;									// get a new block
						binst = 0;								// clear block counter 
						bast_len = 0;							// clear block length
						
						if( basicblksplit(cfun, nxt,sm,dm) > 0){// follow block
							bid++;								// get a new block
							binst = 0;							// clear block counter 
						}

						addedge(curr, nxt, dm);					// add an edge between blocks
					}
				}
			}
		}
		//
		// now instructions with 2 xref from. In this category we have conditional jumps, loop and call
		// instructions.The first xref from will be to the instruction below, while the 2nd will be 
		// the target address of the jump, or a function's entry point, or an entry in .idata.
		//
		else if( nxref == 2 )								// 2 xrefs from
		{
			nxt = get_next_cref_from(curr, get_first_cref_from(curr));
		
			if( loccmd.itype == NN_call )					// special handling of call instructions
			{				
				char segm[MAXBUFLEN];						// store segments

				get_segm_name(nxt, segm, MAXBUFLEN);		// get segment of target function
				if( strcmp(segm, "_text") == 0 ||
					strcmp(segm, "CODE" ) == 0 )			// if function is not imported, analyze it
				{
					// when splitting a malware, it may has code in other segments. No problem, just
					// remove the condition above :)
					char func[MAXFUNAMELEN];


					get_func_name(nxt, func, MAXFUNAMELEN);	// get function name
					
					// ignore some useless functions (DEBUG ONLY)
					//if( strstr(func, "_RTC_") == 0 && strstr(func, "_security_") == 0 ) 
					{
						bid++;								// new block
						binst = 0;							// clear block counter 
						

						// if the call address is not at the beginning of the function, don't call funcsplit						
						if( (nxt != get_func(nxt)->startEA && basicblksplit( get_func(nxt), nxt, sm, dm ) > 0) ||
							funcsplit(get_func(nxt), sm, dm) > 0 ) {	
							bid++;							// new block
							binst = 0;						// clear block counter 
						}
						
						addedge(curr, nxt, dm);				// add an edge block and function
					}
				}
			}
			// we handle this above:
			//
			// else if( loccmd.itype == NN_callfi || loccmd.itype == NN_callni ) 
			//	;											
			else											// conditional jumps
			{
				if( func_contains(get_func(curr), nxt) == false ) 
					// we need this for finding return addresses. Function (A) which contains "curr" can 
					// indirectly transfer control to the function (B) that contains "nxt". Thus a retn
					// instruction from B can go to the parent function of A. Because we have retn instructions
					// we work backwards, so we map B -> A and not A -> B.
					if( get_func(nxt) && get_func(curr) )
						indfunc.altset(get_func(nxt)->startEA, get_func(curr)->startEA);
				
				bid++;										// get a new block
				binst = 0;									// clear block counter 

				// follow the target address first (jump taken)
				// (the order that we're following the nodes matters)
				if( basicblksplit(cfun, get_next_cref_from(curr, get_first_cref_from(curr)), sm, dm) > 0 ) {
					bid++;									// get a new block
					binst = 0;								// clear block counter 
				}

				// follow the instruction(s) that are below this instruction (jump not taken)
				if( basicblksplit(cfun, get_first_cref_from(curr), sm, dm) > 0 ) {
					bid++;									// get a new block
					binst = 0;								// clear block counter 
				}

				// add the edges between nodes
				addedge(curr, get_first_cref_from(curr), dm);				
				addedge(curr, get_next_cref_from(curr, get_first_cref_from(curr)), dm);
			}
		}
		//
		// now the switch statements. Instructions are in the form: jmp  ds:off_414834[eax*4]. We simply
		// follow each possibe target.
		//
		else if( nxref > 2 )								// many xrefs
		{
			bid++;											// get a new block
			binst = 0;										// clear block counter 

			// iterate again xrefs from
			for( ea_t nxt=get_first_cref_from(curr); nxt!=BADADDR; nxt=get_next_cref_from(curr, nxt) )
			{
				if( basicblksplit(cfun, nxt, sm, dm) > 0 ) {// follow switch case
					bid++;									// get a new block
					binst = 0;								// clear block counter 
				}
				
				addedge(curr, nxt, dm);						// don't forget the edge
			}
		}
		//
		// the last case. retn instructions belong here.
		//
		else {												// nxref is uint, so we'll enter iff it's 0
			// loccmd.itype == NN_retn || loccmd.itype == NN_retf
			// we'll get the edges of ret instructions, during relocation. patchblk() will do this
			// job. The reason is that at this point we may want to access return address that 
			// haven't been visited yet.
			
			break;											// stop searching
		}

		prev = curr;										// that's all we need for case [1]			
	}
	
	//
	// there are some case where the next instruction belongs to a previous block because it's a target of
	// another block. In such cases we'll miss 1 edge. We have to add it:
	// 
	// we can also check if prev has only 1 xref from: 
	//		get_next_cref_from(prev, get_first_cref_from(prev)) == BADADDR)	
	//
	if( curr<cfun->endEA &&
		visited.altval(curr) != visited.altval(prev) &&		// instructions have different bid
		get_first_cref_from(prev) == curr &&				// curr is after prev
		(visited.altval(curr) & NOTMSBIT) < (visited.altval(prev) & NOTMSBIT) )	// and has a smaller bid
	{		
		addedge( prev, curr, dm );							// add the edge
	}

	return binst;											// return the total number of instructions
}
//-----------------------------------------------------------------------------------------------------------
/*
**  funcsplit(): This function splits a new function. basicblksplit() may call it, when encounter a new
**		function. This is just a wrapper for basicblksplit(). We create a new function for this job in order
**		to have a more clear design.
**
**	Arguments: cfun (func_t*)   : A pointer to the current function
**              cm  (splitmode) : The splitting algorithm 
**              dm  (debugmode) : The level of information will be printed
**
**	Return Value: The total number of instructions splitted.
*/
uint funcsplit(func_t *currfunc, splitmode sm, debugmode dm)
{
	char	name[MAXBUFLEN];								// function's name
	uint	ninst;											// total number of instructions
	

	get_func_name(currfunc->startEA, name, MAXBUFLEN);		// get function name

	// some functions may cause problems, or may be useless. In any case if you want not to analyze it,
	// all you have to do is to add 1 more line in this if statement:
	if( !strcmp(name, "??$?6U?$char_traits@D@std@@@std@@YAAAV?$basic_ostream@DU?$char_traits@D@std@@@0@AAV10@PBD@Z")  )
	{                    
		msg( "    [+] Removing function %s\n", name );

		/* assume cdecl calling convention */
		put_byte(currfunc->startEA, 0xc3 );					// totally patch 1st byte with a retn

		// Fill the rest wit NOPs
		for(ea_t code=currfunc->startEA+1; code<currfunc->endEA; code++)
			put_byte(code, 0x90 );
			
		// reanalyze code
		analyze_area(currfunc->startEA,  currfunc->endEA);
	}	
		
	if( (ninst = basicblksplit(currfunc, currfunc->startEA, sm, dm)) > 0 )	
	{
		// print it only the first time you see the function
		get_func_name(currfunc->startEA, name, MAXBUFLEN);
	
		msg("    [+]. %3d instruction(s) splitted on function (%x-%x): %s ...\n",
				ninst, currfunc->startEA, currfunc->endEA, name ); 
	}
	
	return ninst;											// return total number of instructions
}
//-----------------------------------------------------------------------------------------------------------
/*
**  printbbstat(): Print some information about basic block splitting.
**
**	Arguments: dm (debugmode): The level of information detail
**
**	Return Value: None.
*/
void printbbstat( debugmode dm )
{
	ulong	val, prev=-1;									// auxilart vars
	uint	count=0;										// number of basic blocks

	
	// enumerate all different basic blocks
	for( nodeidx_t addr=visited.alt1st(); addr!=BADNODE; addr=visited.altnxt(addr)) {

		if( (val = visited.altval(addr)) != prev ) {		// bid changed?
			prev = val;										// update it
			count++;										// increment counter
	
			invbid.altset(val & NOTMSBIT, addr, 'I');		// set this for inverse search
		}
	}
	nblks = count;											// backup total number of blocks (display use only)


	msg( "[+] Program splitted into %d pieces\n", count );
}
//-----------------------------------------------------------------------------------------------------------
