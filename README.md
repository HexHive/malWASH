# malWASH v2.0

Here's the source code of malWASH. Note that it is not stable. malWASH works great with 
Visual Studio 2010 compiler. You can create your own programs, compile them with VS and 
use the executables in malWASH. \*.pdb files can help IDA analysis and thus our plugin, 
so they recommended when they are available.

## Running malWASH

Let's assume that you want to split file **dir1\\dir2\\foo.exe**

1. Copy and paste **malWASH_intr** folder (located in evaluation/) under **dir1**: **dir1\\malWASH_intr** this directory must be on the parent directory of the binary.
   
2. Copy **plugin_bin/malwash_splitter.plw** in **%IDADIR%\\plugins**

3. Use IDA 6.3 to load **foo.exe** and press **Alt+S** to run plugin.

4. Configure parameters and press **OK**

5. If no errors occured you'll see the appropriate message in **Output Window**.
Otherwise, a detailed error will be displayed.

6. a file **malWASH_final.cpp** will be created under the same directory of foo.exe**

7. Feel free to modify the source files (e.g. adding processes to whitelist, etc.)

8. Compile the source file: **cl malWASH_final.cpp**

9. Launch a bunch of processes **as an Administrator** (this is required to mess with shared memory). 
If User Access Control (UAC) is disabled, you don't need that.

10. In order to see the progress of loader, execute **malWASH_final.exe**, in command line window

11. Run **malWASH_final.exe**. If everything is correct, You'll see success return codes from
remote threads at loader screen. Loader will close automatically; malWASH is fully distributed.

## Notes

1. Remote keylogger is probably the best sample to verify that malWASH really works. Take a look on the
remote keylogger sample for more details.

2. Please make sure that you're injecting code in 32-bit applications. malWASH is 32 bit,
you cannot inject 32 bit code in 64 bit code.

3. If program crashes, there are many reasons for that. The foremost is the shared addresses.
Feel free to change them (defined in emulator_source/malwash.h and plugin_source/malwash.h).
These number must be consistent. Change them and recompile plugin and emulator.

4. Emulator is embedded in malWASH_intr\\code_1 as character array. You can run 
emulator_source/malwash_exec.cpp, to get the hex-encoded emulator in **executer_raw.txt** file.
(remember to comment out the \#ifdef directive at line 574 ti get emulator as array)

5. This version is not stable; It might not work various environments: Tested under windows 8.1 pro x64
under VMWare v9.0.2. If you cannot execute it, contact me (ispo@purdue.edu) and I'll send you the VM image



--ispo

