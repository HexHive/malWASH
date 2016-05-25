# malWASH v2.0

Here's the source code of malWASH. Note that it is not stable. malWASH works great with 
Visual Studio 2010 compiler. You can create your own programs, compile them with VS and 
use the executables in malWASH. *.pdb files can help IDA analysis and thus our plugin, 
so they recommended when they are available.

## running malWASH

Let's assume that you want to split file *dir1\\dir2\\foo.exe*
1. Copy and paste *malWASH_intr* directory (located in evaluation/) under *dir1*: *dir1\\malWASH_intr*
   this directory must be on the parent directory of the binary.
   
2. Copy *plugin_bin/malwash_splitter.plw* in *%IDADIR%\\plugins*

3. Use IDA 6.3 to load *foo.exe* and press *Alt+S* to run plugin.

4. Configure parameters and press *OK*

5. If no errors occured you'll see the appropriate message on *Output Window*.
Otherwise, a detailed error will be displayed.

6