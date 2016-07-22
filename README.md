# malWASH v2.0
Washing malware to evade dynamic analysis

>  \* \* \* **Important Notice** * * *
>  
>  Please read this information carefully, otherwise you'll have problems running malWASH
>  correctly.


## Introduction

malWASH is a dynamic diversification engine that executes an arbitrary program without 
being detected by dynamic analysis tools. In other words, it is a malware engine, that 
can make existing malware, to evade all existing behavioral and dynamic analysis detection 
methods. 

Note that malWASH is **research project** (i.e. not stable). The goal of this project is to 
demonstrate that this new generation of malware is possible. *It needs a lot of additional 
work to become a tool that can be used in the wild*.

malWASH works great with Visual Studio 2010 compiler. You can create your own programs, compile 
them with VS and use the executables in malWASH. *.pdb files can help IDA analysis and thus our 
plugin, so they recommended when they are available.

### How it works

The idea behind malWASH is that target malware is chopped into small components that are then 
executed in the context of other processes, hiding the behavior of the original malware in a 
stream of benign behavior of a large number of processes. A scheduler connects these components 
and transfers state between the different processes. The execution of the benign processes is
not impacted, while malWASH ensures that the executing program remains persistent, complicating 
any removal process.

For a detailed explanation on how malWASH works, please have a look at the related paper
(https://nebelwelt.net/publications/files/16WOOT.pdf), which appears in Usenix WOOT'16. 

The source code is well written and easily understandable. The comments are very explanatory
and have information that do not appear in the paper. So do not be afraid to read the source :)


## Running malWASH

Let's assume that you want to split binary **dir1\\dir2\\foo.exe**

1. Create a directory **malWASH_intr** under **dir1**: **dir1\\malWASH_intr** and copy the 
files **code_1** and **code_2**  from **source/auxiliary**. This directory must be on the 
parent directory of the binary.
   
2. Copy **plugin/malwash_splitter.plw** in **%IDADIR%\\plugins**

3. Use IDA 6.3 to load **foo.exe** and press **Alt+S** to run plugin.

4. Configure parameters and press **OK**

5. If no errors occured you'll see the appropriate message in **Output Window**.
Otherwise, a detailed error will be displayed.

6. a file **malWASH_final.cpp** will be created under the same directory of foo.exe.

7. Feel free to modify the source files (e.g. adding processes to whitelist, etc.)

8. Compile the source file: **cl malWASH_final.cpp**

9. Launch a bunch of processes **as an Administrator** (this is required to mess with 
shared memory). If User Access Control (UAC) is disabled, you don't need that.

10. In order to see the progress of loader, execute **malWASH_final.exe**, in command line window.

11. Run **malWASH_final.exe**. If everything is correct, You'll see success return codes from
remote threads at loader screen. Loader will close automatically; malWASH is fully distributed.


## Additional Notes

1. Remote keylogger is probably the best sample to verify that malWASH really works. Take a look on the
remote keylogger sample for more details.

2. Please make sure that you're injecting code in 32-bit applications. malWASH is 32 bit,
you cannot inject 32 bit code in 64 bit code.

3. If program crashes, there are many reasons for that. The foremost is the shared addresses.
Feel free to change them (defined in source/emulator/malwash.h and source/malwash.h).
These numbers must be consistent. Change them and recompile both plugin and emulator.

4. Emulator is embedded in malWASH_intr\\code_1 as character array. You can run 
source/emulator/malwash_exec.cpp, to get the hex-encoded emulator in **executer_raw.txt** file.
(remember to comment out the \#ifdef directive at line 574 to get emulator as array)

5. This version is not stable; It might not work under some environments: I tested it under Windows 
8.1 pro x64 in VMWare v9.0.2. If you cannot execute it, contact me (ispoleet@gmail.com) and I can send 
you the VM image.
