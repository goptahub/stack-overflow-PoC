nasm -f win32 decoder.s -o decoder.obj
link decoder.obj /SUBSYSTEM:CONSOLE /ENTRY:start /OUT:decoder.exe