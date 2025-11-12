@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc *.cpp /link /OUT:earlybird.exe /SUBSYSTEM:WINDOWS
del *.obj