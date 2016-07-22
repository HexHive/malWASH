## malWASH evaluation
___

These are the malware samples that I used for the evaluation.

I injected them in Google Chrome Version 50.0.2661.94 m, under Windows 8.1 Pro 64-bit.

Please note that malWASH is not stable! When you kill infected processes, the 
killed emulator might leave open sockets, so it might affect future executions
of the same program. 

Plugin needs files inside ..\malWASH_intr, so please put this file in the right place first

I used Visual Studio 2010 to compile malware samples that I only had the source code:
basic_backdoor, keystroke_logger, mine_sweeper, simple_trojan.

For the rest I also had the compiled binary from the author along with the source, so I used that.
___

##### NOTES
1. for main() style arguments you need to include argv[0] as well.
2. plugin uses some internal netnodes. If you want run plugin for 2nd time, close and open database again.
3. Upon error, emulator executes an idle infinity loop. This is good for debugging.
___
