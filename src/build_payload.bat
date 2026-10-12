nasm -f win32 payload.s -o payload.obj
link payload.obj /SUBSYSTEM:CONSOLE /ENTRY:start /OUT:payload.exe