# LdrpDebugFlags
 
LoaderLog
This is alternative implementation for https://github.com/TimMisiak/LoaderLog

Usage
LdrpDebugFlags.exe *<app path>*<cmd line>

if <cmd line> containing * symbols - need every * replace for **
This will create a log file in the current directory

LdrpDebugFlags can debug multiple processes in parallel. if we exec second instance of LdrpDebugFlags, while first is running - it create new process ( if app path is correct) but debug it will be first instace, while second just exit

process exit - after all debugged processes exit

tool is tested. worked executable ( and several logs ) is present. src if for view only. no vcxproj/sln files and some headers.

code designed for maximum performance and efficient.

