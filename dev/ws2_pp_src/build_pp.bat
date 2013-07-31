@ECHO OFF
call "%ProgramFiles(x86)%\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" x86
CL /W3 /O1s /D_WINDOWS /D_MBCS /D_USRDLL /DNDEBUG /DWIN32 ws2_pp.c /link /DEF:ws2_pp.def /DLL /RELEASE /OPT:REF /OPT:ICF /ENTRY:DllMain /OUT:ws2_pp.dll kernel32.lib user32.lib
echo -------------------------------------------------------------------------------
pause