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
**  store.cpp
**
**  This file has all function that we need to store the block and all their meta data to disk. Basic blocks
**  have a specific format that is described in storeblk() function.
**
**
**  Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015 
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"                                        // all includes are here


char    modtab[ FUNTBLSIZE ];                               // module table
uint    modtablen;                                          // module table size
char    segtab[ FUNTBLSIZE ];                               // segment table
uint    segtablen;                                          // segment table size
//-----------------------------------------------------------------------------------------------------------
/*
**  storeinternal(): Write a buffer to a file.
**
**  Arguments: buf      (uchar*) : Buffer to store
**             buflen   (uint)   : Buffer size
**             filename (char*)  : File name
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storeinternal( uchar *buf, uint buflen, char *filename )
{
    FILE *fp;                                               // our file pointer

    if( (fp=qfopen(filename, "wb")) == NULL ) {             // try to create file
        fatal( "Cannot create file %s", filename );
        return ERROR;
    }

    if( qfwrite(fp, buf, buflen) != buflen ) {              // write table to file
        fatal("Cannot write to file %s", filename );
        qfclose(fp);
        return ERROR;
    }

    if( qfclose(fp) ) {                                     // try to close handle
        fatal("Cannot close file %s", filename );
        return ERROR;
    }   

    return SUCCESS;                                         // success!
}
//-----------------------------------------------------------------------------------------------------------
/*
**  stintsegrange(): Write a part of a segment to a file. The first 8 bytes of the file contain its virtual
**      start and "end" address respectively.
**
**  Arguments: start    (ea_t)  : start address
**             end      (ea_t)  : end adress
**             filename (char*) : File name
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint stintsegrange( ea_t start, ea_t end, char *filename )
{   
    uchar   *data;                                          // store the whole segment here
    FILE    *fp;                                            // our file pointer


    if( filename[0] == '_' ) filename[0] = '.';             // fix 1st character

    if( (data=(uchar*) malloc(end - start)) == NULL ) {     // allocate space (end > start ALWAYS)
        fatal( "Cannot allocate space for segment data. start:%x, end:%x", start, end);
        return ERROR;
    }

    // This fails for some reason, although we successfully read all bytes:
    //      if(!get_many_bytes(start, (void*)data, end-start))
    get_many_bytes(start, (void*)data, end-start);          // read bytes

    for( ea_t i=start; i<end; i++ )                         // set uninitialized data to zero
        if( !isLoaded( i ) )
            data[i - start] = 0;
        
    if( (fp=qfopen(filename, "wb")) == NULL ) {             // try to create file
        fatal( "Cannot create file %s", filename );
        free(data);                                         // release memory
        return ERROR;
    }

    if( qfwrite(fp, &start, 4) != 4 ||                      // write start
        qfwrite(fp, &end,   4) != 4 ||                      // write end
        qfwrite(fp, data, end-start) != end-start )         // write data
    {
        fatal( "Cannot write to file %s", filename );
        free(data);                                         // release memory
        qfclose(fp);                                        // close file
        return ERROR;
    }

    if( qfclose(fp) ) {                                     // try to close handle
        fatal( "Cannot close file %s\n", filename );
        free(data);                                         // release memory
        return ERROR;
    }   

    free(data);                                             // release memory
    return SUCCESS;                                         // success!
}
//-----------------------------------------------------------------------------------------------------------
/*
**  storefuntab(): Write function table into a file.
**
**  Arguments: None.
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storefuntab( void )
{
    if( storeinternal((uchar*) funtab, funtablen, ".funtab") == ERROR )
        return ERROR;
    
    return SUCCESS;
}
//-----------------------------------------------------------------------------------------------------------
/*
**  storesegmtab(): Write segment table into a file. 
**
**  Arguments: None.
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storesegtab( void )
{
    FILE *fp;                                               // our file pointer


    // segment table is just a list of pairs: the first 2 bytes denote the segment index, and the 
    // then there's a NULL terminating segment name.

    if( (fp=qfopen(".segtab", "wb")) == NULL ) {            // try to create file
        fatal( "Cannot create file .segtab" );
        return ERROR;
    }

    // iterate through all segments
    for(nodeidx_t idx=segment.sup1st(); idx!=BADNODE; idx=segment.supnxt(idx))
    {
        char    name[MAXSEGNAMELEN] = {0};                  // store segment name here
        size_t len;                                         // and its len
        uint    j;                                          // iterator


        len = segment.supval(idx, name, MAXSEGNAMELEN);     // get segment name
        
        // assume that writes are successful
        qfwrite(fp, &idx, 2);                               // write index (truncate to 2 bytes)
        qfwrite(fp, name, len);                             // write name
        qfwrite(fp, EOSCHAR, 1);                            // write EOS (End Of String)


        // now, copy the entry in modtab array (we only need it for pack* operations)
        *(ushort*)(&segtab[segtablen]) = idx & SHORT;       // write idx first
        segtablen += 2;                                     // move pointer

        // As we said, Visual Studio sucks cause we can't use strcat_s
        for(j=0; name[j]!='\0' && segtablen<SEGTBLSIZE; ++j)// do your own strncat
            segtab[segtablen++] = name[j];                  // byte by byte copy

        segtab[segtablen++] = EOSCHAR_CH;                   // finish with EOS
    }

    if( qfclose(fp) ) {                                     // try to close handle
        fatal( "Cannot close file .segtab" );
        return ERROR;
    }   
    
    return SUCCESS;
}
//-----------------------------------------------------------------------------------------------------------
/*
**  storemodtab(): Write module table into a file. This function is very similar with storemodtab(), as 
**      both segment and module tables have the same format.
**
**  Arguments: None.
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storemodtab( void )
{
    FILE *fp;                                               // our file pointer


    // segment table is just a list of pairs: the first 2 bytes denote the segment index, and the 
    // then there's a NULL terminating segment name.

    if( (fp=qfopen(".modtab", "wb")) == NULL ) {            // try to create file
        fatal( "Cannot create file .modtab" );
        return ERROR;
    }

    // iterate through all segments
    for(nodeidx_t idx=import_node.sup1st(); idx!=BADNODE; idx=import_node.supnxt(idx))
    {
        char    name[MAXMODNAMELEN] = {0};                  // store module name here
        size_t  len;                                        // and its len
        uint    j;                                          // iterator


        len = import_node.supval(idx, name, MAXMODNAMELEN)  // get module name
                - 1;                                        // omit the last NULL byte
        
        // convert name to lowercasef
        for(uint i=0; name[i]!='\0'; i++)
            name[i] = tolower( name[i] );                   // convert each character

        // assume that writes are successful
        qfwrite(fp, &idx, 2);                               // write index (truncate to 2 bytes)
        qfwrite(fp, name, len);                             // write name
        qfwrite(fp, ".dll", 4);                             // write dll extension
        qfwrite(fp, EOSCHAR, 1);                            // write EOS (End Of String)


        // now, copy the entry in modtab array (we only need it for pack* operations)
        *(ushort*)(&modtab[modtablen]) = idx & SHORT;       // write idx first
        modtablen += 2;                                     // move pointer

        // As we said, Visual Studio sucks cause we can't use strcat_s
        for(j=0; name[j]!='\0' && modtablen<MODTBLSIZE; ++j)// do your own strncat
            modtab[modtablen++] = name[j];                  // byte by byte copy

        modtab[modtablen++] = '.';                          // finally copy .dll\0
        modtab[modtablen++] = 'd';
        modtab[modtablen++] = 'l';
        modtab[modtablen++] = 'l';
        modtab[modtablen++] = EOSCHAR_CH;
    }

    if( qfclose(fp) ) {                                     // try to close handle
        fatal( "Cannot close file .modtab" );
        return ERROR;
    }   
    
    return SUCCESS;
}
//-----------------------------------------------------------------------------------------------------------
/*
**  storethdtab(): Write thread table into a file.
**
**  Arguments: None.
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storethdtab( void )
{
    FILE *fp;                                               // our file pointer


    // thread table is a list of pairs: the first 2 bytes denote the segment index, and the 
    // then there's a NULL terminating segment name.
    if( (fp=qfopen(".thdtab", "wb")) == NULL ) {            // try to create file
        fatal( "Cannot create file .thdtab" );
        return ERROR;
    }

    // iterate through all segments
    for(nodeidx_t idx=thdtab.alt1st('T'); idx!=BADNODE; idx=thdtab.altnxt(idx, 'T'))
    {
        ea_t bid = thdtab.altval( idx, 'T' ) & SHORT;       // get block id

        // assume that writes are successful
        qfwrite(fp, &idx, 4);                               // write address
        qfwrite(fp, &bid, 2);                               // write block id
    }

    if( qfclose(fp) ) {                                     // try to close handle
        fatal( "Cannot close file .thdtab" );
        return ERROR;
    }   
    
    return SUCCESS;
}

//-----------------------------------------------------------------------------------------------------------
/*
**  storeinitptrs(): Write initialized pointer table into a file.
**
**  Arguments: None.
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storeinitptrs( void )
{
    FILE *fp;                                               // our file pointer

    // Each entry in initialized pointer table is 64 bits:
    //
    //      0              7               15              23              31
    //      +---------------+---------------+---------------+---------------+
    //      |       Source Segment ID       |       Target Segment ID       |
    //      +---------------+---------------+---------------+---------------+
    //      |              Relocation Offset in Source Segment              |
    //      +---------------+---------------+---------------+---------------+ 
    //
    if( (fp=qfopen(".initab", "wb")) == NULL ) {            // try to create file
        fatal( "Cannot create file .initab" );
        return ERROR;
    }


    for( uint i=0; i<initptrcnt; i++ )
    {
        ushort src = -1, dst = -1;

        // serial (pffff it's not efficient!) search all segments till you find the matching one
        for(nodeidx_t idx=segment.alt1st(); idx!=BADNODE; idx=segment.altnxt(idx))
        {
                 if( segment.altval(idx) == initptr[i].src_seg ) src = idx;
            else if( segment.altval(idx) == initptr[i].dst_seg ) dst = idx;
        }

        if( dst != 0xffff && src != 0xffff )                    // if we have valid indices
        {
            // assume that writes are successful
            qfwrite(fp, &src, 2);                               // write source segment index
            qfwrite(fp, &dst, 2);                               // write destination segment index
            qfwrite(fp, &initptr[i].seg_off, 4);                // write pointer offset with segment
        }

    }

    if( qfclose(fp) ) {                                     // try to close handle
        fatal( "Cannot close file .initab" );
        return ERROR;
    }   
    
    return SUCCESS;
}


//-----------------------------------------------------------------------------------------------------------
/*
**  storeblk(): Store a basic block to a file. The name of the file is the basic block ID. Each basic block 
**      has a header and a specific format. See inside function body for details.
**
**  Arguments: bid        (uint)       : Block ID
**             blk        (uchar*)     : Block opcodes
**             blklen     (uint)       : Length of blk array (equal to blkcnt)
**             segmrel    (segmrel_t*) : Array of segment  relocations
**             segmrelcnt (uint)       : Size  of segment  relocations array
**             funcrel    (funcrel_t*) : Array of function relocations
**             funcrelcnt (uint)       : Size  of function relocations array
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storeblk( uint bid, uchar blk[], uint blklen, segmrel_t *segmrel, uint segrelcnt, 
               funcrel_t *funcrel, uint funrelcnt, dup_t *duptab, uint dupcnt, heap_t *heaptab, uint heapcnt )
{
    //  Below is the file format of basic block files.
    //  
    //  Bit
    //  0              7               15              23              31
    //  +--------------+---------------+---------------+---------------+
    //  |                     "WASH" (File Header)                     |
    //  +--------------+---------------+---------------+---------------+
    //  |           Block ID           |                               |
    //  +--------------+---------------+                               |
    //  |           NULL Terminating List of Target Block IDs          |
    //  +--------------+---------------+---------------+---------------+
    //  |                 "BBLK" (Basic Block Header)                  |
    //  +--------------+---------------+---------------+---------------+
    //  |       Basic Block Size       |                               |
    //  +--------------+---------------+                               |
    //  |                                                              |
    //  |             The actual opcodes of the basic block            |
    //  |                                                              |
    //  +--------------+---------------+---------------+---------------+
    //  |              "SEGM" (Segment Relocation Header)              |
    //  +--------------+---------------+---------------+---------------+
    //  |     Relocation Offset #1     |    Segment Table Offset #1    |
    //  |            .....             |             .....             |
    //  |     Relocation Offset #N     |    Segment Table Offset #N    |
    //  +--------------+---------------+---------------+---------------+
    //  |             "FUNC" (Function Relocation Header)              |
    //  +--------------+---------------+---------------+---------------+
    //  |     Relocation Offset #1     |    Function Table Offset #1   |
    //  |            .....             |             .....             |
    //  |     Relocation Offset #N     |    Function Table Offset #N   |
    //  +--------------+---------------+---------------+---------------+
    //  |          "DUPL" (SOCKET/HANDE Duplication Header)            |
    //  +--------------+---------------+---------------+---------------+
    //  |    Duplication Offset #1     |Duplicated argument #1 location|
    //  |            .....             |             .....             |
    //  |    Duplication Offset #N     |Duplicated argument #N location|
    //  +--------------+---------------+---------------+---------------+    
    //  |              "HEAP" (Heap Manipulation Header)               |
    //  +--------------+---------------+---------------+---------------+
    //  |     Relocation Offset #1     |        Heap Operation         |
    //  |            .....             |             .....             |
    //  |     Relocation Offset #N     |        Heap Operation         |
    //  +--------------+---------------+---------------+---------------+
    //  |                  "ENDW" (File End Trailer)                   |
    //  +--------------+---------------+---------------+---------------+
    //
    // static uint  count = 0;                                  // how many blocks we have stored so far
    const  uint zero = 0;                                   // needed for qfwrite()
    uchar       edglst[256] = { 0 };                        // store here edge list
    ushort      *e;                                         // and its short pointer
    char        cntstr[16];                                 // 16bit id, 16 characters are enough
    FILE        *fp;                                        // our file pointer
    uint        i, len;                                     // auxilary vars 


    msg( "[+] Storing basic block %d... ", bid );

    _itoa_s(bid, cntstr, 16, 10);                           // use safe version of itoa()                       
    if( (fp=qfopen(cntstr, "wb")) == NULL ) {               // try to create file
        fatal( "Cannot create file %d", bid );
        return ERROR;
    }

    // We assume that no errors occured during write, to keep code simple

    qfwrite(fp, "WASH", 4);                                 // write MAGIC file header
    qfwrite(fp, &bid, 2);                                   // write bid (truncate to 2 bytes)
        
    // now, write 2 byte block targets
    if( (len=edge.supval(bid, NULL, 0, 'E')) != -1)         // not all blocks go somewhere
    {
        edge.supval(bid, edglst, len, 'E');                 // get block target

        for( i=0, e=(ushort*)edglst; i<len>>1; i++, e++ )   // store each target block
            qfwrite(fp, e, 2);
    }   
    
    qfwrite(fp, &zero, 2);                                  // terminate target block list

    qfwrite(fp, "BBLK", 4);                                 // write basic block file header
    qfwrite(fp, &blklen, 2);                                // write basic block size
    qfwrite(fp, blk, blklen);                               // write actual basic block


    qfwrite(fp, "SEGM", 4);                                 // write segment file header

    for( i=0; i<segrelcnt; i++ )                            // write segment relocations
    {
        qfwrite(fp, &segmrel[i].boff     , 2);              // truncate them to 16 bits
        qfwrite(fp, &segmrel[i].segtaboff, 2);
    }

    qfwrite(fp, "FUNC", 4);                                 // write function file header

    for( i=0; i<funrelcnt; i++ )                            // write function relocations
    {
        qfwrite(fp, &funcrel[i].boff     , 2);              // truncate them to 16 bits
        qfwrite(fp, &funcrel[i].funtaboff, 2);
    }
    
    qfwrite(fp, "DUPL", 4);                                 // write duplication file header

    for( i=0; i<dupcnt; i++ )                               // write duplicated SOCKET/HANDLE arguments
    {
        ushort loc = ((UNPACK_2(duptab[i].loc) ? UNPACK_2(duptab[i].loc) 
                                               : UNPACK_1(duptab[i].loc)) << 8) | duptab[i].loc & 0xff;

        qfwrite(fp, &duptab[i].boff, 2);                    // write offset within block
        qfwrite(fp, &loc, 2);                               // write location (and type in MSByte)
    }
    
    qfwrite(fp, "HEAP", 4);                                 // write heap manipulation file header

    for( i=0; i<heapcnt; i++ )                              // write duplicated SOCKET/HANDLE arguments
    {
        qfwrite(fp, &heaptab[i].boff, 2);                   // write offset within block
        qfwrite(fp, &heaptab[i].info, 2);                   // write heap operation
    }   
    
    qfwrite(fp, "ENDW", 4);                                 // denote end of file

    if( qfclose(fp) ) {                                     // try to close handle
        fatal( "Cannot close file %d", bid );
        return ERROR;
    }   

    msg( "Done\n" );
    return SUCCESS;                                         // success!
}
//-----------------------------------------------------------------------------------------------------------
/*
**  storesegms(): Store all segments appeared in "segment" netnode.
**
**  Arguments: None. 
**
**  Return Value: If no errors occured, return value is 0; otherwise -1 is returned.
*/
uint storesegms( void )
{
    char    seg1[MAXSEGNAMELEN] = {0};                      // store 1st segment name
    char    seg2[MAXSEGNAMELEN] = {0};                      // store 2nd segment name
    bool    segfound;                                       // did a segment search was successfull?


    nsegms = 0;                                             // clear segment counter

    for(nodeidx_t idx=segment.sup1st(); idx!=BADNODE; idx=segment.supnxt(idx), ++nsegms)
    {
        memset(seg1, '\0', MAXSEGNAMELEN);
        segment.supval(idx, seg1, MAXSEGNAMELEN);           // get segment name
        
        // search for this segment in all segments
        // we don't need the following check anymore: 
        //      if( strcmp(seg1, "_text") )                 // exclude .text from search
        for(segment_t *s=get_first_seg(); s!=NULL; s=get_next_seg(s->startEA))
        {
            memset(seg2, '\0', MAXSEGNAMELEN);
            get_segm_name(s->startEA, seg2, MAXSEGNAMELEN); 

            if( !strcmp(seg1, seg2) )                       // match?
            {
            #define SEGLEN (s->endEA - s->startEA)
                // ignore seg1[0] which usually is an underscore
                msg( "    [-] Storing .%s segment. Size %d... ", seg1[0] == '.' ? &seg1[1] : seg1, SEGLEN);
                
                if( seg1[0] == '_' ) seg1[0] = '.';         // patch 1st character

                if( stintsegrange(s->startEA, s->endEA, seg1) == ERROR )
                    return ERROR;

                msg( "Done.\n" );                           // Success!

                segfound = true;                            // successfull search
                break;                                      // stop searching

            #undef SEGLEN
            }
        }

        if( !segfound ) {                                   // segment not found
            fatal( "Cannot find segment .%s", seg1[0] == '.' ? &seg1[1] : seg1 );
            return ERROR;
        }
    }

    return SUCCESS;                                         // success!
}
//-----------------------------------------------------------------------------------------------------------
