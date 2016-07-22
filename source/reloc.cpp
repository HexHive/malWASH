//-----------------------------------------------------------------------------------------------------------
/*
**                               ,,                                                        
**                             `7MM `7MMF'     A     `7MF' db       .M"""bgd `7MMF'  `7MMF'
**                               MM   `MA     ,MA     ,V  ;MM:     ,MI    "Y   MM      MM  
**  `7MMpMMMb.pMMMb.   ,6"Yb.    MM    VM:   ,VVM:   ,V  ,V^MM.    `MMb.       MM      MM  
**    MM    MM    MM  8)   MM    MM     MM.  M' MM.  M' ,M  `MM      `YMMNq.   MMmmmmmmMM  
**    MM    MM    MM   ,pm9MM    MM     `MM A'  `MM A'  AbmmmqMA   .     `MM   MM      MM  
**    MM    MM    MM  8M   MM    MM      :MM;    :MM;  A'     VML  Mb     dM   MM      MM  
**  .JMML  JMML  JMML.`Moo9^Yo..JMML.     VF      VF .AMA.   .AMMA.P"Ybmmd"  .JMML.  .JMML.
**     
**  malWASH - The malware engine for evading ETW and dynamic analysis: A new dimension in APTs 
**
**  ** The splitting engine ** - Version 2.0
**
**
**  reloc.cpp
**
**  This file performs all the required relocations (jump/call targets, global data references, etc.) in the
**  basic blocks. Relocation is a really complex process. See patchblk() internals for more detail.
**
**
**  Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"                                        // all includes are here


char        funtab[FUNTBLSIZE];                             // store here function names
initptr_t   initptr[MAXINITPTRTBLSIZE];                     // store initialized pointers that need relocation
uint        initptrcnt;                                     // initptr table counter
uint        funtablen = 0;                                  // function table size
netnode     segment,                                        // segment info
            invbid;                                         // find address from bid (inverse search)
segment_t   *idata;                                         // import segmant pointer
//-----------------------------------------------------------------------------------------------------------
/*
**  enum_impfunc_callback(): This is a callback function, called by enum_import_names(). What we're doing 
**      here is to check whether a specific module imports the requested function. Function may be imported
**      by name or by ordinal. In the 2nd case we have to do some extra work.
**
**  Arguments: ea    (ea_t)  : import address
**             name  (char*) : import name (NULL if imported by ordinal)
**             ord   (uval_t): import ordinal (0 for imports by name)
**             param (void*) : user parameter passed to enum_import_names()
**
**  Return Value: 1-ok, 0-stop enumeration.
*/
int __stdcall enum_impfunc_callback(ea_t ea, const char *name, uval_t ord, void *param)
{
    switch( ord )
    {
        case 0:                                             // import by name
            if( !strcmp((char*)param,  name) )              // function match?
                return 0;                                   // if so, stop searching
            break;
        
        default: {                                          // import by ordinal
            char func[MAXFUNAMELEN];
            uint st = 0;                                    
            
            get_name(BADADDR, ea, func, MAXFUNAMELEN);      // get function name from effective address

            
            // if function contains '@' which is followed by a digit, then truncate function name to '@'
            // __stdacall imported functions end with @ followed by argument of retn instruction
            if( strstr(func, "@") && isdigit( strstr(func, "@")[1] ) )
                func[(uint)(strstr(func, "@") - func)] = '\0';  

            if( strstr(func,  "__imp__") )     st = 7;          // if function starts with __imp__, skip it
            else if( strstr(func,  "__imp_") ) st = 6;          // if function starts with __imp_, skip it
            else if( func[0] == '_' )          st = 1;          // if it start with underscore, skip it

    
            if( !strcmp((char*)param,  &func[st]) )         // function match? (ignore "__imp__" at the beginning)
                return 0;                                   // stop searching
        }
    }

    return 1;                                               // match not found. Continue searching
}
//-----------------------------------------------------------------------------------------------------------
/*
**  funcidx(): Look up in function table for a specific string. If string doesn't exist, appened it to the 
**      table. Thus a search in the table never fails.
**
**  Arguments: funstr (char *): A NULL termintated string containing function name
**
**  Return Value: An index (offset from the beginning of the table) to that string.
*/
uint funcidx( char funame[] )
{
    uint        j, k, idx;                                  // declare auxilary counters
    nodeidx_t   modidx;                                     // a node index for searching within import_node


    for(idx=1; idx<funtablen; idx++ )                       // yeah, I know i can do this in O(NlogN).
    {
        // we don't want a name to start in the middle of another one. e.g:
        // SetUnhandledExceptionFilter and UnhandledExceptionFilter
        if( funtab[idx - 1] != '\0' ) continue;             

        // we assume that: functablen + strlen(name) < FUNCTBLSIZE
        for( j=0; funame[j]!='\0' && j<FUNTBLSIZE; j++ )    // iterate over function name
            if( funtab[idx + j] != funame[j] )              // if they're different,
                break;                                      // stop

        if( funame[j] =='\0' ) return idx;                  // match found?
    } 

    
    // function not found. Append it on function table.
    // first find the imported module that contains this function.
    for(k=0, modidx=import_node.sup1st(); modidx!=BADNODE;  // for each imported module
        ++k, modidx=import_node.supnxt(modidx))
    {
        // enumerate all imported functions from each module and search
        // for the imported function (pass function name to callback function)
        int found = enum_import_names(k, enum_impfunc_callback, (void*)funame);     

        if( !found ) {                                      // function found within this module
            char modname[MAXMODNAMELEN] = {0};              // store segment name here

            import_node.supval(k, modname, MAXMODNAMELEN);  // get imported module name

            msg( "    [=] Function %s imported from %s\n", funame, modname );
            break;                                          // stop searching
        }
    }

    if( k >= import_node.altval(-1) ) {                     // function not found in any module
        // do not call fatal(), because funcidx() can get a second chance
        msg( "[-] Warning: Cannot find function %s in any imported module\n", funame ); 
        return ERROR;
    }

    idx = funtablen;                                        // get index of new function name

    *(ushort*)(&funtab[idx]) = k & SHORT;                   // use the first 2 bytes to write module ID
    funtablen += 2;                                         // move pointer


    // Visual Studio sucks. I can't use strcat_s, cause of a runtime crappy assertion that fails:
    // strcat_s( &funtab[funtablen+1], FUNTBLSIZE-funtablen,funame);
    for(j=0; funame[j]!='\0' && funtablen<FUNTBLSIZE; ++j)  // do your own strncat
        funtab[funtablen++] = funame[j];

    funtab[funtablen++] = '\0';                             // add an extra NULL byte

    return idx + 2;                                         // return index of function (not module id)
}
//-----------------------------------------------------------------------------------------------------------
/*
**  segmidx(): Look up in segment table for a specific string. If string doesn't exist, appened it to the 
**      table. Thus a search in the table never fails. Because segments are much less than function calls,
**      we'll use a different approach from funcidx(): We'll use netnodes, to speed up search.
**
**  Arguments: segstr (char *): A NULL termintated string containing segment name
**
**  Return Value: The index to that segment string.
*/
uint segmidx( char segname[] )
{
    uint lst = 0;                                           // last index in netnode
    

    // we could have done this by using hashvals netnodes (maybe it was easier). Nvm...
    // iterate through all segments
    for(nodeidx_t idx=segment.sup1st(); idx!=BADNODE; idx=segment.supnxt(idx), lst++)
    {
        char name[MAXSEGNAMELEN] = {0};                     // store segment name here
        segment.supval(idx, name, MAXSEGNAMELEN);           // get segment name
        
        if( !strcmp(name, segname) ) return idx;            // if name found, return it
    }

    segment.supset(lst, segname, strlen(segname) );         // name not found. Append it at the end
    

    char ch = segname[0];                                   // backup 1st character (usually is underscore) 
    segname[0] = '.';                                       // change it with dot

    if( get_segm_by_name(segname) )                         // store also start address
        segment.altset(lst, get_segm_by_name(segname)->startEA );

    segname[0] = ch;                                        // and restore it

    return lst;                                             // return index
}
//-----------------------------------------------------------------------------------------------------------
/*
**  findoff(): Find the offset of an address inside a block. We have to know where is the address in the 
**      block in order to patch it at runtime. We cannot use strstr(), because tha former has issues with
**      NULL bytes. We don't start searching from the beginning of the block but from the last instruction.
**
**  Arguments: block  (uchar *) : A pointer to our block
**             blkcnt (uchar *) : Size of our block (so far)
**             start  (uchar *) : Offset to start searching
**             addr   (uchar *) : The address to search for
**
**  Return Value: If addresss not found, return ERROR. Otherwise, return the last offset of that address 
**      within the block.
*/
uint findoff( uchar block[], uint blkcnt, uint start, uint addr)
{
    for( uint i=start; i<=blkcnt-4; i++ ) {                 // for each byte
        ea_t *dxref = (ea_t*)&block[i];                     // get a dword (that's why we go up to blkcnt-4) 

        if( *dxref == addr ) return i;                      // return index if found
    }

    return ERROR;                                           // not found. return error
}
//-----------------------------------------------------------------------------------------------------------
/*
**  relocfun(): Relocate a function call inside a basic block. If current instruction is not a call, function
**      exits with ERROR. Otherwise we check the call type. On indirect calls (which are calls to dlls) we 
**      store the function name in function table and we return the index on that table. For relative 
**      function calls, we calculate the target bid of the call and we return that bid with the MSBit set 
**      (MSBit denotes the type of call: direct/indirect).
**
**  Arguments: curr   (ea_t)  : The current instruction address 
**             loccmd (insn_t): A object of the current instruction
**
**  Return Value: If current instruction is not a call return ERROR. If it's a direct jump, return bid of the
**      target with MSBit set. If it's an indirect jump, return an index of function name in function table.
*/
uint relocfun( ea_t curr, insn_t loccmd )
{
    char    func[MAXFUNAMELEN] = {0};                       // store function name here
    ea_t    funcaddr;                                       // function address
    uint    funtabidx;                                      // function index in funtab
                    

    // relative (direct) function calls: call j___RTC_CheckEsp (E8 CC CD FF FF)
    if( loccmd.itype == NN_call )
    {
        // the first code xref is to the instruction below. the next is function address 
        funcaddr = get_next_cref_from (curr, get_first_cref_from(curr) );
        get_func_name(funcaddr, func, MAXFUNAMELEN);        // get function name

         msg( "    [-] Local function call at %x to %s\n", curr, func);

         return SUCCESS; //visited.altval(funcaddr) | MSBIT;            // return bid with MSBit set
    }   
    //
    // indirect function calls: call ds:__imp__GetKeyState@4 (FF 15 38 84 41 00)
    // MSVC++ also uses trampoline functions:
    //      .text:004122C8                      ; void *__cdecl memset(void *Dst, int Val, size_t Size)
    //      .text:004122C8                     _memset         proc near        ; CODE XREF: j__memsetj
    //      .text:004122C8 FF 25 B8 A3 41 00            jmp     ds:__imp__memset
    //      .text:004122C8                     _memset         endp
    //
    // An instruction will transfer execution inside a library when:
    //  [1]. is an indirect call that imports from .idata
    //  [2]. is an indirect jump, that the target is on .idata (import segment) (beware conflicts
    //          with indirect jump on switch statements)
    //
    else if( (loccmd.itype == NN_callni || loccmd.itype == NN_callfi ||
             (loccmd.itype == NN_jmpni && get_first_dref_from(curr) != BADADDR))  &&    
             (idata->startEA <= get_first_dref_from(curr) && 
                                get_first_dref_from(curr) < idata->endEA ) )
    {
        uchar   st = 0;                                     // omit the first part of the function

        // for call: the first code xref is to the instruction below. the next is function address 
        // for jmp: there's only 1 data xref from, which is the function address
        funcaddr = (loccmd.itype == NN_jmpni) ? get_first_dref_from(curr) :
                                                get_next_cref_from (curr, get_first_cref_from(curr) ) == BADADDR ?
                                                    get_first_cref_from(curr) :
                                                    get_next_cref_from (curr, get_first_cref_from(curr) );

        get_name(BADADDR, funcaddr, func, MAXFUNAMELEN);    // get name of address from .idata

        if( !strcmp(func, "_USER32_NULL_THUNK_DATA") )      // special case: FindWindowA()
        {
            strcpy_s(func, MAXFUNAMELEN, "FindWindowA");
        }


        // imported functions are in the form with: __imp__FUNCNAME@N, where N is the number
        // of bytes that are needed for the arguments

        // if function contains '@' which is followed by a digit, then truncate function name to '@'
        // __stdacall imported functions end with @ followed by argument of retn instruction
        if( strstr(func, "@") && isdigit( strstr(func, "@")[1] ) )
            func[(uint)(strstr(func, "@") - func)] = '\0';  


        if( strstr(func,  "__imp__") ) st = 7;              // if function starts with __imp__, skip it
        else if( strstr(func,  "__imp_") ) st = 6;          // if function starts with __imp_, skip it
        else if( func[0] == '_' )      st = 1;              // if it start with underscore, skip it

        if( (funtabidx = funcidx( &func[st] )) == ERROR ) { // store the "real" name in function table
        
            // give funcidx() a 2nd chance: if original function starts with _ then after "imp" there are
            // 2 underscores and not 3. So repeat using an extra underscore         
            if( (funtabidx = funcidx( &func[st-1] )) == ERROR )
                return ERROR;
        }

        msg( "    [-] Library function call at %x to %s\n", curr, &func[st]);
        
        return funtabidx;                                   // return the index
    }
    //
    // We have a simple way to resolve instructions like "call eax". Look at the example:
    //  mov     esi, ds:__imp__MultiByteToWideChar@24   ; 40
    //  push    0                                       ; 40
    //  push    0                                       ; 40
    //  push    0FFFFFFFFh                              ; 40
    //  push    edi                                     ; 40
    //  push    0                                       ; 40
    //  push    0FDE9h                                  ; 40
    //  call    esi ; MultiByteToWideChar(x,x,x,x,x,x)  ; 40
    //  cmp     eax, 200h                               ; 40
    // 
    // As you can see, we don't change block during "call esi". Because esi, is referenced directly
    // with an imported function address, it's possible to handle it. If esi had a function from
    // .text we couldn't be able to handle it.
    //
    else if( idata->startEA <= get_first_dref_from(curr) &&                         
                               get_first_dref_from(curr) < idata->endEA ||
             idata->startEA <= get_next_cref_from(curr, get_first_cref_from(curr)) &&
                               get_next_cref_from(curr, get_first_cref_from(curr)) < idata->endEA )
    {
        uchar   st = 0;                                     // omit the first part of the function


        get_name(BADADDR, get_first_dref_from(curr) != BADADDR ?
                          get_first_dref_from(curr) :
                          get_next_cref_from(curr, get_first_cref_from(curr)), 
                        func, MAXFUNAMELEN);                // get name of address from .idata

        // imported functions are in the form with: __imp__FUNCNAME@N, where N is the number
        // of bytes that are needed for the arguments
             
        // if function contains '@' which is followed by a digit, then truncate function name to '@'
        // __stdacall imported functions end with @ followed by argument of retn instruction
        if( strstr(func, "@") && isdigit( strstr(func, "@")[1] ) )
            func[(uint)(strstr(func, "@") - func)] = '\0';  

        if( strstr(func, "__imp__") ) st = 7;               // if function starts with __imp__, skip it
        else if( strstr(func, "__imp_") ) st = 6;           // if function starts with __imp_, skip it      
    
        // sometimes, this is wrong ...
        else if( func[0] == '_' ) st = 1;                   // if it start with underscore, skip it         


        if( (funtabidx = funcidx( &func[st] )) == ERROR ) { // store the "real" name in function table
        
            // give funcidx() a 2nd chance: if original function starts with _ then after "imp" there are
            // 2 underscores and not 3. So repeat using an extra underscore         
            if( (funtabidx = funcidx( &func[st-1] )) == ERROR )
                return ERROR;
        }

        msg( "    [-] Library function reference at %x to %s\n", curr, &func[st]);
        
        // return the index. Special case the mov eax, __imp__addr which is 5 bytes long
        return funtabidx | (loccmd.size == 2 ? MSBIT2 : (get_byte(curr) == 0xa1 ? MSBIT : 0));  
    }
    

    return SUCCESS;                                         // if function is not a call, return ERROR
}
//-----------------------------------------------------------------------------------------------------------
/*
**  findrettargets(): This function is responsible for finding all possible return address from the last
**      instruction. Last instruction is usually a ret, but it can also be an indirect jump of the last
**      stage of a trampoline function.
**      This function works as follows: It searches for the function that contains the last instruction and
**      from there it searches for all possible caller functions. For each function it searches for all 
**      points that this function is called. The next instruction after this point is a possible return
**      address. The only exception is the trampoline functions. In such case it won't exists next 
**      instruction after call. Assuming that our code is "structured", we can end up that we're in a 
**      trampoline function so we get the parent function of the parent function (aka the granpa function)
**      We'll store all return addresses in a netnode. We can also use the edge netnode to store them
**      instead.
**
**  Arguments: retaddr (netnode) : A netnode to store return address
**             last   (ea_t)     : Address of the last instrucion of the block
**
**  Return Value: If no errors occured, return value the number of possible return addresses. In case of
**  an error, -1 is returned. 
*/
uint findrettargets( netnode retaddr, ea_t last )
{
    func_t      *curf, *pntf /*, *grnf */;              // function pointers
    // nodeidx_t    ret;                                // netnode iterator
    ea_t        nxtinsn;                                // next instruction after return
    uint        len = 0, i;                             // number of ret targets & iterator
    

    // if we have an indirect function we have to find return addresses for normal parent functions
    // and for parent functions of indirect function
    for( i=0, curf=get_func(last); i<2; ++i, curf=get_func( indfunc.altval(curf->startEA) ) )
    {
        for( ea_t xref=get_first_cref_to(curf->startEA);// find every call to this function
                xref!=BADADDR; xref=get_next_cref_to(curf->startEA, xref) )
        {
            // our goal is to find the bid, of the return address
            if( (pntf = get_func(xref)) == NULL )       // find parent function
                continue;                               // and skip it if doesn't exists
            
            if( (nxtinsn=find_code(xref, SEARCH_DOWN)) >= pntf->endEA )
            {
                // we have a trampoline function. Of course we could have a chain of trampoline functions
                // but that's not realistic. For now we'll assume that there's 1 trampoline function
                // We can easily handle trampoline chains using a loop but really, there's no point to do it.
            /*  for( ret=get_first_cref_to(pntf->startEA); ret!=BADADDR; ret=get_next_cref_to(pntf->startEA, ret) )
                {
                    grnf    = get_func(ret);            // get caller of parent function (grandpa :P function)
                    nxtinsn = find_code(ret, SEARCH_DOWN);  // next instruction

                    if( nxtinsn > grnf->endEA ) {       // trampoline chain?
                    
                        // fatal("This version cannot handle chains of trampoline functions");                      
                        // return ERROR;                    // return error 

                        // or,
                        continue;                       // we can just ignore this possible return address
                    }

                    // nxtinsn is a canditate return value
                    // save it only if its part of a visited block
                    if( visited.altval(nxtinsn) & NOTMSBIT ) {      
                        retaddr.altset(nxtinsn, visited.altval(nxtinsn) & NOTMSBIT);
                        len++;
                    
                        addedge( last, nxtinsn, VERY_VERBOSE ); // add the edge between blocks (optional)
                    }

                    msg( "        [*] Far Return Address found at %x\n", nxtinsn );
                }   
            */
            } 
            else {

                // save it only if its part of a visited block
                if( visited.altval(nxtinsn) & NOTMSBIT ) {      
                    retaddr.altset(nxtinsn, visited.altval(nxtinsn) & NOTMSBIT);
                    len++;
                            
                    addedge( last, nxtinsn, VERY_VERBOSE );     // add the edge between blocks (optional)
                }

                msg( "        [*] Return Address found at %x\n", nxtinsn );
            }
        }

        if( indfunc.altval(curf->startEA) == 0 )        // if there are no indirect fuctions  
            break; 
    } 

    // At this point retaddr netnode contains all possible return address with their bIDs.


    // we use 2 byte jumps to reduce space. Thus maximum jump offset can be 127 bytes and for each
    // jump we need 8 bytes. Thus we can have up to 15 return targets.
    // FIX: You can use 4 byte jump instructions instead.
    // if( len >= 15 ) {
    //  fatal( "Too many return targets from %x. Stopping to avoid overflow.", last );
    //  return ERROR;
    // }


    return len;                                         // return the number of possible return addresses
}
//-----------------------------------------------------------------------------------------------------------
/*
**  patchblk(): This is the most important function of our plugin and the "magic" that makes our splitting
**      process feasible. We patch the last instruction of a basic block. Instead of jumping to the next basic 
**      block, we have to make the required changes, and end up with the bid of next block stored in ebx, 
**      without actually jumping anywhere. 
**
**  Arguments: blk    (uchar *) : A pointer to our block
**             blkcnt (uchar *) : Size of our block (so far)
**             last   (ea_t)    : Address of the last instrucion of the block
**             boff   (ushort*) : A pointer to the last segment relocation offset. We have to increase the
**                                last offset by 2 because we add 2 push instructions (2 bytes) before.
**             duptab (dup_t*)  : The last entry of duplication table (we need it for a special case)
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned. In case of a indirect
**      jump of a trampoline function, function returns a positive integer that represent the new offset of
**      the module address that needs to be relocated.
*/
uint patchblk( uchar blk[], uint *blkcnt, ea_t last, ushort *boff=NULL, dup_t *duplst=NULL )
{
    // define our MACROS first
#define PBYTE1(b)          (blk[(*blkcnt)++] = (b) & 0xff)  // append a single byte to blk array
#define PLONG(l)           *(uint*)  (blk + *blkcnt) = (l); *blkcnt += 4    // append a 4 byte integer to blk array
#define PSHORT(s)          *(ushort*)(blk + *blkcnt) = (s); *blkcnt += 2    // append a 2 byte integer to blk array
#define PBYTE2(a, b)       PBYTE1(a); PBYTE1(b)             // append 2 bytes to blk array
#define PBYTE3(a, b, c)    PBYTE2(a, b); PBYTE1(c)          // append 3 bytes to blk array
#define PBYTE4(a, b, c, d) PBYTE3(a, b, c); PBYTE1(d)       // append 4 bytes to blk array
#define SET_EBX(target)    PBYTE1(0xBB); PLONG(target)      // write the instruction mov ebx, _long_

    insn_t      loccmd;                                     // backup of cmd global variable 
    uchar       edglst[256] = { 0 };                        // store here edge list
    size_t      len;                                        // list length
    ushort      *e;                                         // pointer to edglst
    uchar       offlft;                                     // offset left from "jump_end" label
    char        mnem[MAXMNEMLEN];                           // store last instruction's mnemonic here
    uint        cbid, i;                                    // auxilary stuff


    generate_disasm_line(last, mnem, MAXMNEMLEN);           // get last instruction's mnemonic 
    tag_remove(mnem, mnem, 0);
    
    msg( "    [-] Last instruction %x:%s\n", last, qstrdup(mnem) );

    cbid = visited.altval(last) & NOTMSBIT;                 // get current block ID

    // read edge list of target block
    if( (len=edge.supval(cbid, NULL, 0, 'E')) == -1 )       // empty list ?
        len = 0; 
    else edge.supval(cbid, edglst, len, 'E');               // if not get it

    decode_insn(last);                                      // decode the last instruction
    loccmd = cmd;                                           // use the local copy of it

    *blkcnt -= loccmd.size;                                 // remove last instruction

    //
    // Now check the type of the last instruction.
    // 1st case: relative short jumps. Instructions are in the form: jmp loc_relative_address.
    //
    if( loccmd.itype == NN_jmp )
    {
        // replace last instruction with:
        // 53               push ebx                ; back up ebx
        // BB 44 33 22 11   mov ebx, 11223344h      ; where 0x11223344 is the bid
        // 90               nop                     ; always finish with a NOP (why? idk :P)

        PBYTE1( 0x53 );                                     // push ebx
        SET_EBX( ((ushort*)edglst)[0] );                    // there's 1 target block
    }
    //
    // Conditional jumps. Instructions are in the form: j?? loc_relative_address, where j??
    // is a conditional jump instruction.
    //
    else if( loccmd.itype >= NN_ja && loccmd.itype <= NN_jz )
    {
        // we also have 2 cases here:
        // conditional jump target may be near (from -128 to +127 bytes) to current instruction,
        // or may not. In the latter case, we need 4 bytes to represent the address and 2 bytes
        // for the instruction opcodes.
        //
        // replace last instruction with:
        // 53               push ebx                ; backup ebx
        //
        // [CASE 1 - FOR NEAR JUMPS]
        // ?? 07            j?? jump_taken          ; keep the same jump type
        //
        // [CASE 2 - FOR FAR JUMPS]
        // 0f ?? 07 00 00 00 j?? jump_taken         ; for far jumps
        //
        // BB 44 33 22 11    mov ebx, 11223344h     ; if jump taken, go to target1
        // EB 05             jmp jump_end           ; it's an if-else statement
        //      jump_taken:
        // BB 88 77 66 55    mov ebx, 55667788h     ; if jump not taken, go to instruction below
        //      jump_end:
        // 90                nop                        ; nop
        //
        // the 1st target bid, is always the block below, because the 1st cxref-from is the instruction below
        PBYTE1( 0x53 );                                     // push ebx
        
        if( loccmd.size == 2 ) {                            // near conditional jump?
            PBYTE2( get_byte(loccmd.ea), 0x07 );            // j?? +7
        }
        else {                                              // then, it's a far conditional jump
            PBYTE2( 0x0f, get_byte(loccmd.ea + 1) );
            PLONG( 0x07 );
        }

        SET_EBX( ((ushort*)edglst)[0] );                    // mov ebx, target_1 (when jump is taken)

        PBYTE2( 0xEB, 0x05 );                               // jmp +5
        SET_EBX( ((ushort*)edglst)[1] );                    // mov ebx, target_2 (when jump is not taken)
        PBYTE1( 0x90 );                                     // nop
    }
    //
    // Instruction that are in the last stage of trampoline functions. We create a separate category for 
    // these instructions to keep code simple. Here we have indirect jumps to imported modules. The problem
    // is that it's hard to find the next block.
    //
    // Note that the current block consist of only 1 jump instruction. Indirect jumps to imported modules
    // are not a reason to change block, unless we reach function end. Because we assume "structured" code,
    // functions will always end with a "retn" instruction. Thus the only way for a function to end with
    // such a jump is to be a trampoline function.
    //
    // So how we can distinguish between jumps for switch statements and jumps from trampoline functions?
    //  [1]. switch jumps have >1 code xrefs
    //  [2]. switch jumps use a register, while trampoline jumps are not
    //  [3]. reference address of trampoline jumps will be in .idata
    //
    // method [1] also works: if( get_next_cref_from(last, get_first_cref_from(last) ) == BADADDR )
    // but we'll do here method 3.
    //
    // Because we don't know if cdecl or stdcall calling convention is used we cannot "emulate" the function 
    // return (we also don't know the number of arguments). Return is executed inside dll, so manipulating 
    // return value is not straightforward.
    // The plan here is the following: We'll store the original return address somewhere below the original
    // code (we cannot store it in stack because stdcall may used, and thus we'll lose control over it). 
    // Then we'll patch the return address, so that call to dll will return right after of jump. Finally,
    // we can extract the original return address and do the same trick that we can do to find the next 
    // block, having the return address (see below, how we handle retn instructions).
    //
    else if( (loccmd.itype == NN_jmpfi || loccmd.itype == NN_jmpni) &&
            loccmd.Operands[0].addr >= get_segm_by_name(".idata")->startEA &&
            loccmd.Operands[0].addr <= get_segm_by_name(".idata")->endEA )
    {
        // replace the 1 indirect jump with the code:
        // eb 04                jmp    6 <code_start>           ; reserve 4 bytes for original return address
        //
        // ff ff ff ff          [4 bytes to store original return address]
        //
        //              00000006 <code_start>:                  ;
        // 50                   push   eax                      ; backup these registers        
        // 53                   push   ebx                      ;       
        // e8 00 00 00 00       call   +5                       ; call next instr, to put eip in the stack
        // 58                   pop    eax                      ; eax = current address
        // 83 e8 0b             sub    eax, 0xb                 ; go back 11 bytes and use it as storage
        //
        // 8b 5c 24 08          mov    ebx, DWORD PTR [esp+0x8] ; save original return address 
        // 89 18                mov    DWORD PTR [eax],ebx      ; ([esp]=ebx, [esp+4]=eax, [esp+8]=retn)
        // 5b                   pop    ebx                      ; restore ebx
        // e8 00 00 00 00       call   14 <next>                ; call next instr, to put eip in the stack
        //              00000019 <next>:                        ;
        // 58                   pop    eax                      ; eax = &next
        // 83 c0 ??             add    eax, 0x??                ; adjust eax to point to return_here
        // 89 44 24 04          mov    DWORD PTR [esp+0x4], eax ; overwrite original return addr. with fake
        // 58                   pop    eax                      ; now restore eax
        // ff 25 b8 a3 41 00    jmp     ds:__imp__memset        ; jump to module
        //              00000028 <return_here>:                 ;
        // 53                   push   ebx                      ; backup ebx
        //                                                      ;
        // e8 00 00 00 00       call   +5                       ; call next instr, to put eip in the stack
        // 5b                   pop    ebx                      ; ebx = current address
        // 83 eb 30             sub    eax, 0x30                ; go back ?? bytes and use it as storage
        // 8b 1b                mov    ebx, DWORD PTR [ebx]     ; read  original return address
        //
        //  [SAME AS RETN CASE -see below-]:
        //
        // 81 FB 44 33 22 11    cmp ebx, 11223344h              ; check against 1st possible return value
        // 74 ??                jz jump_target1                 ;
        // 81 FB 88 77 66 55    cmp ebx, 55667788h              ; check against 2nd possible return value
        // 74 ??                jz jump_target2                 ;
        // ...
        //      jump_illegal:
        // BB FF FF FF FF       mov ebx, ffffffffh              ; set bid to ERROR
        // EB ??                jmp jump_end                    ; it's an switch statement!
        // 90                   nop                             ; we add a nop here to have 8 byte jump_targets
        //      jump_target1:   
        // BB 44 33 22 11       mov ebx, 11223344h              ; set bid from target1
        // EB ??                jmp jump_end                    ; it's an switch statement!
        // 90                   nop                             ; we add a nop here to have 8 byte jump_targets
        //      jump_target2:
        // BB 44 33 22 11       mov ebx, 55667788h              ; set bid from target2
        // EB ??                jmp jump_end                    ; last jump is useless but there's no problem
        // 90                   nop                             ; pad
        // ...
        //      jump_end:
        // 90                   nop                             ; nop
        //                      ...                             ;
        //              00000100 <temp_data>:                   ; store original return address here
        netnode     retaddr;                                // hold all possible return addresses
        nodeidx_t   ret;                                    // netnode iterator
        uint        reloff;                                 // offset of function within block

        
        *blkcnt = 0;                                        // clear counter first
        
        PBYTE2( 0xeb, 0x04 );                               // skip storage space
        PLONG( 0x90909090 );                                // reserve some space (we use NOPs, to
                                                            // avoid confusing the dissasembler :P)

        PBYTE1( 0x50 );                                     // push eax
        PBYTE1( 0x53 );                                     // push ebx
        PBYTE1( 0xe8 ); PLONG( 0x00 );                      // call +5
        PBYTE1( 0x58 );                                     // pop  eax
        PBYTE3( 0x83, 0xe8, 0x0b );                         // sub  eax, 0xb
        PBYTE4( 0x8b, 0x5c, 0x24, 0x08 );                   // mov  ebx, dword ptr [esp+0x8]    
        PBYTE2( 0x89, 0x18 );                               // mov  [eax], ebx
        PBYTE1( 0x5b );                                     // pop  ebx     
        PBYTE1( 0xe8 ); PLONG( 0x00 );                      // call +5
        PBYTE1( 0x58 );                                     // pop  eax

        PBYTE3( 0x83, 0xc0, 9+loccmd.size );                // add  eax, offset
        PBYTE4( 0x89, 0x44, 0x24, 0x04 );                   // mov dword ptr [esp+4], eax
        PBYTE1( 0x58 );                                     // pop eax

        //
        // * * * * * WARNING: A special case * * * * *
        //  When the indirect jump to a library call (last instruction) is a function from dup* family, we 
        //  have to add some prolog and epilog code (e.g. to replace the duplicated SOCKET/HANDLE). Thus we
        //  have to update the boff of the corresponding duptab entry.
        //
        if( duplst )                                        // Do we have a dup* function (not NULL)?
        {
            msg( "    [+] Meeting a dup* library call as last instruction. Updating duptab entry\n" );
            
            duplst->boff = *blkcnt;                         // move boff of dup* entry
        }

        reloff = (*blkcnt) + 2;                             // for indirect jumps, address starts at 3rd byte

        for(i=0; i<loccmd.size; i++)                        // copy original instruction
                blk[(*blkcnt)++] = get_byte(last + i);

        PBYTE1( 0x53 );                                     // push ebx
        PBYTE1( 0xe8 ); PLONG( 0x00 );                      // call +5
        PBYTE1( 0x5b );                                     // pop  ebx
        
        PBYTE3( 0x83, 0xeb, loccmd.size+42 );               // sub    eax, 48 (locate storage location) 
        PBYTE2( 0x8b, 0x1b );                               // mov  ebx, [ebx]  
    
        //
        // now, we work similar to retn instructions
        //
        retaddr.create("$retaddr", 0);                      // create netnode
        
        if( (len=findrettargets(retaddr, last)) == ERROR )  // find all return addresses
            return ERROR;


        /* if we have less than 16 return targets, then a single byte jump offset is enough. */
        if( len < 16 )   
        {
            // set up cmp/jz statements
            for( ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret))
            {
                PBYTE2( 0x81, 0xFB );
                PLONG( ret );                               // set up cmp
                PBYTE2( 0x74, len<<3);                      // offset is constant: (len+1)*8
            }
    
            SET_EBX( -1 );                                  // set the illegal check
            PBYTE2( 0xEB, len<<3 );                 
            PBYTE1( 0x90 );                         

            // now setup mov/jmp statements     
            for( offlft=(len-1)<<3, ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret),  offlft-=8)
            {
                SET_EBX( retaddr.altval(ret) );             // set target bid
                PBYTE2( 0xEB, offlft );                     // set jump
                PBYTE1( 0x90 );                             // don't forget the pad
            }       
        }
        else {                                              // otherwise, we need 4 byte offsets    
            uint offlft;                                    // override offlft with a bigger one

            
            // set up cmp/jz statements
            for( ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret))
            {
                PBYTE2( 0x81, 0xFB );
                PLONG( ret );                               // set up cmp

                PBYTE2( 0x0f, 0x84 );                       // je 4_byte_offset
                PLONG( len*0xc );                           // each cmp/jz is 12 bytes long
            }
    
            SET_EBX( -1 );                                  // set the illegal check
            PBYTE1( 0xE9 ); PLONG( len*0xc );               // jump ahead           
            PBYTE2( 0x90, 0x90 );                           // each "gadget" should be 12 bytes

            // now setup mov/jmp statements     
            for( offlft=(len-1)*0xc, ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret),  offlft-=0xc)
            {
                SET_EBX( retaddr.altval(ret) );             // set target bid
                PBYTE1( 0xE9 ); PLONG( offlft );            // set jump
                PBYTE2( 0x90, 0x90 );                       // each "gadget" should be 12 bytes
            }
        }


        PBYTE1( 0x90 );                                     // nop

        if( get_byte(last) == 0xc2 ) {                      // in case of retn XX
            PBYTE2( 0x81, 0xC4 );
            PLONG ( get_word(last+1)-4 );                   // align stack
        }

        retaddr.kill();                                     // we don't need netnode anymore

        return reloff;                                      // return the number of return instructions
    }
    //
    // Indirect jumps. Note that we cannot handle instructions like "jmp eax". The target of the jump must be
    // know at compile time. Even if it's possible to know the targets at compile time, we cannot handle such
    // instructions yet. However switch statements have instructions like: "jmp ds:off_411BC0[eax*4]". We 
    // can handle such cases (indirect jumps through a jump table).
    //
    else if( loccmd.itype == NN_jmpfi || loccmd.itype == NN_jmpni )
    {
        // replace last instruction with:
        // 53                   push ebx                        ; backup ebx
        // 51                   push ecx                        ; backup also ecx (we can do the same without ecx)
        // 8B 0C 85 C0 1B 41 00 mov ecx,ds:off_411BC0[eax*4]    ; replace jmp target with mov ecx, target
        //                                                      ; just patch the first 2 bytes  
        // 81 F9 A7 19 41 00    cmp ecx, 004119A7h              ; check against 1st possible target
        // 74 ??                jz jump_target1
        // 81 F9 B0 19 41 00    cmp ecx, 004119B0h              ; check against 2nd possible target
        // 74 ??                jz jump_target2
        // ...
        //      jump_illegal:
        // BB FF FF FF FF       mov ebx, ffffffffh              ; set bid to ERROR
        // EB ??                jmp jump_end                    ; it's an switch statement!
        // 90                   nop                             ; we add a nop here to have 8 byte jump_targets
        //      jump_target1:
        // BB 44 33 22 11       mov ebx, 11223344h              ; set bid from target1
        // EB ??                jmp jump_end                    ; it's an switch statement!
        // 90                   nop                             ; we add a nop here to have 8 byte jump_targets
        //      jump_target2:
        // BB 44 33 22 11       mov ebx, 55667788h              ; set bid from target2
        // EB ??                jmp jump_end                    ; last jump is useless but there's no problem
        // 90                   nop                             ; pad
        // ...
        //      jump_end:
        // 59                   pop ecx                         ; we don't need ecx anymore
        // 90                   nop                             ; nop
        //
        // WARNING: Watch out overflows! We use 1byte relative jumps, with 8 byte statements. This means that
        //  we can have switch statements with up to 16 cases. In case that we have more than 16 jumps targets,
        //  we'll use 4 byte relative jumps instead.
        PBYTE1( 0x53 );                                     // push ebx
        PBYTE1( 0x51 );                                     // push ecx
        PBYTE3( 0x8B, 0x0C, get_byte(loccmd.ea+2) );        // instead of jump, move target address to ecx
        PLONG( get_long(loccmd.ea+3) );
        
        if( len < 16 ) {                                    // if we have <16 jumps targets, use 1 byte jumps
            // set up cmp/jz statements
            for(i=0, e=(ushort*)edglst; i<len>>1; ++i, ++e) // for each entry in switch table
            {
                PBYTE2( 0x81, 0xF9 );
                PLONG( invbid.altval(*e, 'I') );            // set up cmp

                // Now, we have to find the jump offset. Every cmp/jz and mov/jmp pair is exactly 8 bytes
                // long. While we're testing each statment, the relative offset doesn't change, so the
                // offset will be constant: (len/2) * 8 = len*4 
                PBYTE2( 0x74,   len<<2 );                   // offset is constant: len/2*8
            }

            SET_EBX( -1 );                                  // set the illegal check
            PBYTE2( 0xEB, len<<2 );                 
            PBYTE1( 0x90 );                                 

            // now setup mov/jmp statements             
            for(offlft=(len<<2)-8, i=0, e=(ushort*)edglst; i<len>>1; ++i, ++e, offlft-=8 )          
            {
                SET_EBX( *e );                              // set target bid
                PBYTE2( 0xEB, offlft );                     // set jump
                PBYTE1( 0x90 );                             // don't forget the pad
            }
        }
        else {                                              // otherwise, we need 4 byte jumps
            uint offlft;                                    // override offlft with a bigger one


            // set up cmp/jz statements
            for(i=0, e=(ushort*)edglst; i<len>>1; ++i, ++e) // for each entry in switch table
            {
                PBYTE2( 0x81, 0xF9 );
                PLONG( invbid.altval(*e, 'I') );            // set up cmp

                // use jz with 4 byte relative offset
                PBYTE2( 0x0f, 0x84 );                       // je 4_byte_offset
                PLONG( len*0x6 );                           // each cmp/jz is 12 bytes long 
                                                            // (len<<1 is the number of targets)
            }

            SET_EBX( -1 );                                  // set the illegal check
            PBYTE1( 0xE9 ); PLONG( len*0x6 );               // jump ahead           
            PBYTE2( 0x90, 0x90 );                           // each "gadget" should be 12 bytes

            // now setup mov/jmp statements             
            for(offlft=((len>>1)-1)*0xc, i=0, e=(ushort*)edglst; i<len>>1; ++i, ++e, offlft-=0xc )          
            {
                SET_EBX( *e );                              // set target bid
                PBYTE1( 0xE9 ); PLONG( offlft );            // set jump
                PBYTE2( 0x90, 0x90 );                       // each "gadget" should be 12 bytes
            }

        }

        PBYTE2( 0x59, 0x90 );                               // pop ecx; nop

        // The offset within block of the last relocation (the one that contains the base address of the
        // switch table) has moved down by 2 bytes (because we added 2 push instructions before it). We
        // have to adjust this offset
        if( boff ) *boff += 2;
    }
    //
    // Call instrutions. The calling function has a relative offset. Still it's fairly easy to handle
    // them. Note that we cannot handle calls like "call eax".
    //
    // NOTE: we don't care about indirect calls (NN_callni and NN_callfi). These calls usually happen
    // to imported modules, so we don't need to split them. However we have to avoid cases where the
    // last instruction of a block is a library call and the next instruction is the target address of
    // another block. Thus the library call will be the last instruction of the block. We don't need
    // any relocations in such cases.
    //
    else if( loccmd.itype == NN_call ) // || loccmd.itype == NN_callni || loccmd.itype == NN_callfi )
    {
        // replace last instruction with:
        // 68 44 33 22 11   push eip                ; eip = last + loccmd.size (instruction below call)
        // 53               push ebx                ; backup ebx now (to be able to pop it first later)
        // BB 88 77 66 55   mov ebx, 55667788h      ; set bid from target1
    
        PBYTE1( 0x68 );
        PLONG( last + loccmd.size );                        // push next instruction in stack
        PBYTE1( 0x53 );                                     // push ebx
        SET_EBX( ((ushort*)edglst)[0] );                    // set the only target bid
    }
    //
    // That's the harderst case. And MSVC++ trampoline functions makes it even harder. We don't have a
    // robust way to determine in which block to go after return. However we can still do something. In
    // a program that everything is know at compile time, we can find all possible return addresses, and
    // thus all possible target blocks. The way we work is the following:
    //  [1]. Find function that ret was called
    //  [2]. Find all xrefs to that function
    //  [3]. For each xref, the instruction below is the possible target. If parent function is a trampoline 
    //       function, then the next instruction will be outside of function limits. Then go to the "grandpa"
    //       function, the caller function of the caller function, and look for the next instruction there.
    //
    //  We cannot handle chains of trampoline functions, although it's really easy to do it (replace "if" 
    //  with a "while" statement). We don't handle them because it's impossible to meet them in compiler
    //  generated and non obfuscated code.
    //
    else if( loccmd.itype == NN_retn || loccmd.itype == NN_retf )
    {
        //
        // We have 2 cases here. If instruction is retn, we do nothing (just NOp). If it's retn XX (stdcall 
        // calling convention), where XX is the number of bytes that we have to some more tricks:
        //
        //  [CASE 1]: retn 
        // 87 1c 24             xchg [esp], ebx         ; backup ebx and get return address to ebx in 1 step
        //
        //  [CASE 2]: retn XX
        // 89 9C 24 22 11 00 00 mov [esp+0x1122], ebx   ; backup ebx at the last argument 
        // 8B 1C 24             mov ebx, [esp]          ; get return address
        //
        //  [BOTH CASES]:
        // 81 FB 44 33 22 11    cmp ebx, 11223344h      ; check against 1st possible return value
        // 74 ??                jz jump_target1
        // 81 FB 88 77 66 55    cmp ebx, 55667788h      ; check against 2nd possible return value
        // 74 ??                jz jump_target2
        // ...
        //      jump_illegal:
        // BB FF FF FF FF       mov ebx, ffffffffh      ; set bid to ERROR
        // EB ??                jmp jump_end            ; it's an switch statement!
        // 90                   nop                     ; we add a nop here to have 8 byte jump_targets
        //      jump_target1:
        // BB 44 33 22 11       mov ebx, 11223344h      ; set bid from target1
        // EB ??                jmp jump_end            ; it's an switch statement!
        // 90                   nop                     ; we add a nop here to have 8 byte jump_targets
        //      jump_target2:
        // BB 44 33 22 11       mov ebx, 55667788h      ; set bid from target2
        // EB ??                jmp jump_end            ; last jump is useless but there's no problem
        // 90                   nop                     ; pad
        // ...
        //      jump_end:
        // 90                   nop                     ; nop
        //
        //  [CASE 2]:
        // 81 C4 44 33 22 11    add esp, 11223344h      ; remove args-1 from stack
        //
        netnode     retaddr;                                // hold all possible return addresses
        nodeidx_t   ret;                                    // netnode iterator


        retaddr.create("$retaddr", 0);                      // create netnode

        if( (len=findrettargets(retaddr, last)) == ERROR )  // find all return addresses
            return ERROR;

        if( get_byte(last) == 0xf3 ) ++last;                // in case of: F3 C3    rep retn

        // At this point retaddr netnode contains all possible return address with their bIDs.
        // Let's see the 2 types of retn instructions:
        //      0:  c3                      ret
        //      1:  c2 08 00                ret    0x8
        if( get_byte( last ) == 0xc3 ) { PBYTE3( 0x87, 0x1C, 0x24 ); }
        else {
            PBYTE3( 0x89, 0x9C, 0x24 );                 // store ebx
            PLONG ( get_word(last+1)-0 );               // find the right offset
            PBYTE3( 0x8B, 0x1C, 0x24 );                 // get return address
        }


        /* if we have less than 16 return targets, then a single byte jump offset is enough. */
        if( len < 16 ) 
        {
            // set up cmp/jz statements
            for( ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret))
            {
                PBYTE2( 0x81, 0xFB );
                PLONG( ret );                           // set up cmp
                PBYTE2( 0x74, len<<3 );                 // offset is constant: (len+1)*8
            }
    
            SET_EBX( -1 );                              // set the illegal check
            PBYTE2( 0xEB, len<<3 );                 
            PBYTE1( 0x90 );                         

            // now setup mov/jmp statements     
            for( offlft=(len-1)<<3, ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret), offlft-=8)
            {
                SET_EBX( retaddr.altval(ret) );         // set target bid
                PBYTE2( 0xEB, offlft );                 // set jump
                PBYTE1( 0x90 );                         // don't forget the pad
            }
        }
        else                                            // otherwise, we need 4 byte offsets
        {
            uint offlft;                                // override offlft with a 4 byte one


            // set up cmp/jz statements
            for( ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret))
            {
                PBYTE2( 0x81, 0xFB );
                PLONG( ret );                               // set up cmp

                PBYTE2( 0x0f, 0x84 );                       // je 4_byte_offset
                PLONG( len*0xc );                           // each cmp/jz is 12 bytes long
            }
    
            SET_EBX( -1 );                                  // set the illegal check
            PBYTE1( 0xE9 ); PLONG( len*0xc );               // jump ahead           
            PBYTE2( 0x90, 0x90 );                           // each "gadget" should be 12 bytes

            // now setup mov/jmp statements     
            for( offlft=(len-1)*0xc, ret=retaddr.alt1st(); ret!=BADNODE; ret=retaddr.altnxt(ret),  offlft-=0xc)
            {
                SET_EBX( retaddr.altval(ret) );             // set target bid
                PBYTE1( 0xE9 ); PLONG( offlft );            // set jump
                PBYTE2( 0x90, 0x90 );                       // each "gadget" should be 12 bytes
            }
        }

        PBYTE1( 0x90 );                                     // nop

        if( get_byte(last) == 0xc2 ) {                      // in case of retn XX
            PBYTE2( 0x81, 0xC4 );
            PLONG ( get_word(last+1)-0 );                   // align stack
        }

        retaddr.kill();                                     // we don't need netnode anymore
    }
    //
    // loop functions. If the condition is false jump back. We just patch the target as we did
    // in conditional jumps. For now we don't implement it.
    //
    else if( loccmd.itype >= NN_loopw && cmd.itype <= NN_loopqne )
    {
        // loopXX instrutions use 1 byte for the relative offset. Instructions are usually 2 or 3 bytes:
        // 67 e2 f9         addr16 loop 0 <LOOP>
        // e1 f7            loope  0 <LOOP>
        // e2 fa            loop   0 <LOOP>
        // 
        // As long as there are 2 possible target block, we work exactly as conditional jumps, and we
        // replace the last instruction with:
        // 53               push ebx                ; backup ebx
        //
        // ?? ?? 07         loop?? jump_taken       ; keep the same jump type
        //
        // BB 44 33 22 11   mov ebx, 11223344h      ; if jump taken, go to target1
        // EB 05            jmp jump_end            ; it's an if-else statement
        //      jump_taken:
        // BB 88 77 66 55   mov ebx, 55667788h      ; if jump not taken, go to instruction below
        //      jump_end:
        // 90               nop                     ; nop
        //
        // the 1st target bid, is always the block below, because the 1st cxref-from is the instruction below
        PBYTE1( 0x53 );                                     // push ebx
        
        if( loccmd.size == 2 ) {                            // 2 byte loopXX ?
            PBYTE2( get_byte(loccmd.ea), 0x07 );            // loop?? +7
        }
        else {                                              // then, it's a 3 byte loopXX
            PBYTE3( get_byte(loccmd.ea + 1), get_byte(loccmd.ea + 1), 0x07 );
        }

        SET_EBX( ((ushort*)edglst)[0] );                    // mov ebx, target_1 (when jump is taken)

        PBYTE2( 0xEB, 0x05 );                               // jmp +5
        SET_EBX( ((ushort*)edglst)[1] );                    // mov ebx, target_2 (when jump is not taken)
        PBYTE1( 0x90 );                                     // nop
    }

    // we don't actually have an instruction that can change control flow. The reason why the block ends here,
    // is because the next instruction is the beginning of another block. All we have to do is to keep the 
    // last instruction and then add the code that sets ebx with the right bid. 
    else
    {
        *blkcnt += loccmd.size;                             // restore last instruction

        PBYTE1( 0x53 );                                     // push ebx
        SET_EBX( ((ushort*)edglst)[0] );                    // set the only target bid
    }

    // The first thing to do after block gets executed is to pop ebx:
    // 5B                   pop ebx                 ; do the pop now!


    return SUCCESS;                                         // no errors happened

#undef SET_EBX                                              // undefine MACROS
#undef PBYTE4
#undef PBYTE3
#undef PBYTE2
#undef PSHORT
#undef PLONG
#undef PBYTE1
}
//-----------------------------------------------------------------------------------------------------------
/*
**  relocblks(): This function does all the required relocations to every basic block. relocblks(), 
**      iterates over each block and resolves any dependencies (function calls, indirect jumps, global data 
**      references, etc.) that can make the block not to run under another process's address space.
**
**  Arguments: None.
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint relocblks( void )
{
    uchar       blk[ MAXBLKSIZE ];                          // basic block opcodes
    funcrel_t   funcrel[ MAXFUNCRELOC ];                    // function relocations
    segmrel_t   segmrel[ MAXSEGMRELOC ];                    // global data relocations
    dup_t       duptab[ MAXDUPTABSZ ];                      // duplicated arguments
    heap_t      heaptab[ MAXHEAPTABSZ ];                    // heap manipulation arguments
    uint        funrelcnt=0, segrelcnt=0, dupcnt=0,
                            heapcnt=0, blkcnt=0;            // and their counters
    ulong       idx, val, dup, heap, prev=-1;               // auxilart vars
    ea_t        dxref;                                      // data xrefs from
    insn_t      loccmd;                                     // backup of cmd global variable 


    idata = get_segm_by_name(".idata");                     // find .idata (import) segment

    // enumerate all different basic blocks
    for( nodeidx_t addr=visited.alt1st(); addr!=BADNODE; addr=visited.altnxt(addr))
    {   
        decode_insn(addr);                                  // decode the current instruction
        loccmd = cmd;                                       // use the local copy of it
        

        if( (val = visited.altval(addr)) != prev ) {        // bid changed?
            
            if( prev != -1 ) {                              // don't do it for the dummy (-1) block

                // patch last instruction
                // NOTE: If last instruction is an indirect jump to a dup* function, then the corresponding
                //  entry in duptab will be the last one ;). If such entry does not exist simply pass a NULL.
                uint retn = patchblk(blk, &blkcnt, visited.altprev(addr), &segmrel[segrelcnt - 1].boff,
                            !dupcnt ? NULL : &duptab[dupcnt - 1] );

                if( retn != ERROR && retn != SUCCESS )      // trampoline relocation?
                    funcrel[ 0 ].boff = retn;               // update offset of function relocation

                if( retn  == ERROR ||
                    crthook(blk, &blkcnt, duptab, dupcnt, funcrel, funrelcnt) == ERROR || 
                    heaprepl(blk, &blkcnt, heaptab, heapcnt, funcrel, &funrelcnt) == ERROR ||
                    storeblk(prev & NOTMSBIT, blk, blkcnt, segmrel, segrelcnt, funcrel, funrelcnt, 
                                duptab, dupcnt, heaptab, heapcnt) == ERROR )
                {
                    return ERROR;                           // stop execution                   
                }
            }
            
            prev = val;                                     // update it
            // and clear counters
            blkcnt = 0; funrelcnt = 0; segrelcnt = 0; dupcnt = 0; heapcnt = 0;      
        }



/*
        if( loccmd.itype == NN_call )
        {
            char    segm[MAXBUFLEN],                        // store segment name
                    func[MAXFUNAMELEN];                     // and function name

            
            // find function's entry point
            ea_t funcep = get_next_cref_from(addr, get_first_cref_from(addr));
        
            
            get_segm_name(funcep, segm, MAXBUFLEN);         // get segment of target function
            
            if( strcmp(segm, "_text") == 0 ||
                    strcmp(segm, "CODE" ) == 0 )            // if function is not imported, check name
            {
                    get_func_name(funcep, func, MAXFUNAMELEN);  // get function name
                        
                    if( !strcmp(func, 
                        "j_??$?6U?$char_traits@D@std@@@std@@YAAAV?$basic_ostream@DU?$char_traits@D@std@@@0@AAV10@PBD@Z") )
                    {
                        for( uint i=0; i<loccmd.size; i++ )     // store opcodes
                            patch_byte(addr + i, 0x90);                                 

                    }
            }
        }
        */

        
        for( uint i=0; i<loccmd.size; i++ )                 // store opcodes
            blk[blkcnt++] = get_byte(addr + i);             
        
        /*---------------------------------------------------------------------
        ** function relocations
        ---------------------------------------------------------------------*/
        if( (idx = relocfun(addr, loccmd)) != SUCCESS )     // look for function relocations
        {
            ushort nargs;                                   // number of function's arguments


            if( idx == ERROR )  return ERROR;               // error?

            if( !(idx & MSBIT2) )                           // in "call reg" don't don any relocations
            {
                // in direct calls, address starts at 2nd opcode byte, while in indirect jumps address 
                // starts at 3rd opcode byte (we have already save opcodes to blk, so blkcnt - loccmd.size
                // will point to current instruction 
                funcrel[ funrelcnt ].boff      = blkcnt - loccmd.size + (idx & MSBIT ? 1 : 2);
                funcrel[funrelcnt++].funtaboff = idx;       // store index
            }

            /*---------------------------------------------------------------------
            ** heap allocation/deallocation?
            ---------------------------------------------------------------------*/
            if( (heap = heapchk(addr)) != ANY )
            {
                if( heap == ERROR ) return ERROR;           // error?

                heaptab[ heapcnt ].boff = blkcnt-loccmd.size;
                heaptab[heapcnt++].info = heap;             // store heap info here
            }
            /*---------------------------------------------------------------------
            ** need for using duplicated SOCKET/HANDLE argument?
            ---------------------------------------------------------------------*/
            else if( (dup = dupchk(addr, &nargs)) != ANY )
            {
                if( dup == ERROR )  return ERROR;           // error?

                // offset in block of call/jmp to librry call that needs to duplicate it's HANDLE/SOCKET
                duptab[ dupcnt ].boff  = blkcnt-loccmd.size;
                duptab[ dupcnt ].loc   = dup /* & SHORT */; // duplicated metadata
                duptab[dupcnt++].nargs = nargs;

                if( idx & MSBIT2 )                          // in "call reg" don't don any relocations
                {
                    funcrel[ funrelcnt ].boff      = blkcnt - loccmd.size + (idx & MSBIT ? 1 : 2);
                    funcrel[funrelcnt++].funtaboff = idx;       // store index
                }
            }
        }
        
        /*---------------------------------------------------------------------
        ** global data relocations
        ---------------------------------------------------------------------*/
        else if((dxref=get_first_dref_from(addr))!=BADADDR  // get data xref from this address (if exists)
            &&  !thdtab.altval(dxref, 'T') )                // skip thread routines
        {
            char segm[MAXSEGNAMELEN] = {0};

            for( ; dxref!=BADADDR && (dxref >> 24)!=0xff; dxref=get_next_dref_from(addr, dxref) )
            {
                // in case that we have >1 data xrefs from
            
                get_segm_name(dxref, segm, MAXSEGNAMELEN);  // get segment name

                if( segm[0] != NULL )                       // if target segment exists
                {   
                    // ida replaces '.' with '_' in segment names
                    msg( "    [*] Accessing data .%s:%x at address %x. ", &segm[1], dxref, addr ); 

                    // Altough we can load at runtime the whole .data or .bss segment in memory, it's really 
                    // stupid to do the same with .text! There are cases (like switch tables) that we have 
                    // data to .text segment. The method here is to get only the pieces of .text segment that
                    // do not contain code. 
                    // NOTE: We assume that the data lay at the bottom of a current function.
                    if( !strcmp(segm, "_text") || !strcmp(segm, "CODE") )
                    {
                        ea_t    start, end;                 // the limits of the data withing .text
                        func_t *curfun = get_func(addr);    // get current function


                        // assume that start and end cannot be BADADDR 
                        // search for the upper bound of data withing this function
                        // watch out if there are not data above!
                        for(start=dxref; start>curfun->startEA && start!=BADADDR; start=find_data(start, SEARCH_UP))
                            ;
                    
                        // go 1 step back 
                        start = start == BADADDR ? dxref : find_data(start, SEARCH_DOWN);   
                    
                        // do the same for the lower bound
                        for(end=dxref; end<curfun->endEA && end!=BADADDR; end=find_data(end, SEARCH_DOWN))
                            ;

                        if( end == BADADDR || end == start || end == dxref )    // problematic cases
                        {
                            // end is BADADDR when there are no data after jump table
                            // end is equal with start when jump table is outside of function end

                            if( get_next_func(end) == NULL ) {
                                fatal( "Cannot find jump table end" );
                                return -1;
                            }
                            
                            end = get_next_func(end)->startEA;  // table end = the beginning of the next function
                        }
                        // end = find_data(end, SEARCH_UP);     // DO NOT go 1 step back
                

                        qstring segname;                        // that's sprintf equivalent
                        segname.sprnt("%s_%x", segm, start);

                        idx = segmidx( qstrdup(segname.c_str()) );  // get segment index

                        // potential problem: We may store data to the file more than once.
                        // this won't affect the results, but it's still bad.
                        stintsegrange(start, end, qstrdup(segname.c_str()) );
                    
                        msg( "Data segment within .text:%x-%x", start, end );
                    }
                    else {                                  // different segment. Store it "normally"
                        idx = segmidx(segm);                // get segment index
                    }
                
                    // find offset of address inside block (don't forget to start searching from the last instr)
                    segmrel[ segrelcnt ].boff      = findoff(blk, blkcnt, blkcnt-loccmd.size, dxref);
                    segmrel[segrelcnt++].segtaboff = idx;   // store index
                
                    msg("\n");
                }   

                // check if we have initialized pointers to another segment
                initptrchk( dxref );
            }

            // now we handle the switch tables. We consider that we have access to a switch table iff:
            // [1]. There is a indirect near jump instruction
            // [2]. The data lay in .text segment (switch tables are stored in .text)
            // 
            // Let's see a counterexample of 2 data xrefs-from in .text:
            //      .text:00411686 lea     edx, v                     
            //
            // There are 2 data xrefs (004116B4 and 004116BC):
            //      .text:004116B4 v               _RTC_framedesc <3, offset dword_4116BC> 
            //      .text:004116BC dword_4116BC    dd 0FFFFFE68h, 190h    
            if( loccmd.itype == NN_jmpni && (!strcmp(segm, "_text") || !strcmp(segm, "CODE")) )
            {
                // ok we found a switch table :)
                msg("    [=] Switch statement found at %x. Jump table at %x \n", addr, dxref );
            
                // That's all we have to do! 
            }
        }
    }


    // don't forget the last block!
    
    // patch last instruction
    // NOTE: If last instruction is an indirect jump to a dup* function, then the corresponding
    //  entry in duptab will be the last one ;). If such entry does not exist simply pass a NULL.
    uint retn = patchblk(blk, &blkcnt, visited.altlast(), &segmrel[segrelcnt - 1].boff,
                            !dupcnt ? NULL : &duptab[dupcnt - 1] );
    
    if( retn != ERROR && retn != SUCCESS )      // trampoline relocation?
        funcrel[ 0 ].boff = retn;               // update offset of function relocation

    return 
    (
        // patchblk(blk, &blkcnt, visited.altlast())        // patch last instruction
        retn
                                                            // get address of last instr. of last block
        |                                                   // if any of these is error you'll return -1.
        crthook(blk, &blkcnt, duptab, dupcnt, funcrel, funrelcnt)   
        |                                                   // replace heap functions
        heaprepl(blk, &blkcnt, heaptab, heapcnt, funcrel, &funrelcnt)
        |
        storeblk(prev & NOTMSBIT, blk, blkcnt, segmrel,     // store block to file
                segrelcnt, funcrel, funrelcnt, duptab, dupcnt, heaptab, heapcnt)        
    );
}
//-----------------------------------------------------------------------------------------------------------
/*
**  initptrchk(): This function checks whether we have an initialized pointer pointing in another segment
**      (except .text). This is required because, when we relocate this segment that pointer won't be valid 
**      anymore. A very common example that appears a lot in our samples is when we have the following 
**      global definition (or a similar): static char *foo = "bar";
**      In this case the pointer foo will be stored in .data segment (initialized variable). But the constant
**      "bar" will be store in .rdata (read-only). Thus we'll have an initialized pointer from .data to 
**      .rdata. Once we relocate .rdata this pointer will be stale. See function body for a detailed expla-
**      nation of the solution
**
**  Arguments: dxref (ea_t) : A potential initialized pointer in segment != .text
**
**  Return Value: None.
*/
void initptrchk( ea_t dxref )
{
    char        seg1[MAXSEGNAMELEN] = {0}, seg2[MAXSEGNAMELEN] = {0};
    segment_t   *srcseg, *dstseg;                           // source and destination segments
    

    //
    // The proposed solution is very simple: We have already solved this problem in .text relocations. Now
    // we have to do the same in .data and in other segments. However we cannot add a "SEGM" list below
    // each segment as we did in .text, because we may have to relocate address from segments that are
    // loaded yet. We'll do is to have a separate file called .segmrel that contains all required reloca-
    // tions. This file contains 64bit entries with each entry containing the following fields:
    //
    //      0              7               15              23              31
    //      +---------------+---------------+---------------+---------------+
    //      |       Source Segment ID       |       Target Segment ID       |
    //      +---------------+---------------+---------------+---------------+
    //      |              Relocation Offset in Source Segment              |
    //      +---------------+---------------+---------------+---------------+
    //
    // After we load all segments in memory, we parse this table. "Source Segment ID" contains the index
    // of the segment, that has the pointer that needs relocation, in the segmtab. "Target Segment ID"
    // contains the index in segmtab of the segment that this pointer points to. The 3rd field contains
    // the offset within the source segment of the address that needs relocation. 
    //
    // The relocation is done as follows:
    //  *(uint*)(SEGMBASEADDR + srcseg*SEGMNXTOFF + segoff) = 
    //  *(uint*)(SEGMBASEADDR + srcseg*SEGMNXTOFF + segoff) - shctrl->segm[dstseg].startEA +
    //          (SEGMBASEADDR + dstseg*SEGMNXTOFF);
    //

    if( get_first_dref_from( dxref ) == BADADDR )           // if there's not dref to another segment
        return;                                             // simply return
    
    srcseg = getseg( dxref );                               // get source segment
    dstseg = getseg( get_first_dref_from(dxref) );          // get destination segment

    if( !dstseg || srcseg->startEA == dstseg->startEA )     // if the pointer points to the same segment
        return;                                             // you don't need to do anything

    initptr[ initptrcnt ].src_seg = srcseg->startEA;
    initptr[ initptrcnt ].dst_seg = dstseg->startEA;
    initptr[initptrcnt++].seg_off = dxref - srcseg->startEA;

     
    get_segm_name(srcseg->startEA, seg1, MAXSEGNAMELEN);    // get source segment name
    get_segm_name(dstseg->startEA, seg2, MAXSEGNAMELEN);    // get destination segment name

    msg( "        [-] Accessing an initialized pointer (%x)->(%x) from segment %s to %s\n", 
            dxref, get_first_dref_from(dxref), seg1, seg2 );
}
//-----------------------------------------------------------------------------------------------------------
