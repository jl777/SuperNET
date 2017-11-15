@echo off

@REM Check for Visual Studio
call set "VSPATH="
if defined VS140COMNTOOLS ( if not defined VSPATH (
 call set "VSPATH=%%VS140COMNTOOLS%%"
) )

@REM check if we already have the tools in the environment
if exist "%VCINSTALLDIR%" (
 goto compile
)

if not defined VSPATH (
 echo You need Microsoft Visual Studio 15 installed
 pause
 exit
)

@REM set up the environment
if exist "%VSPATH%..\..\vc\vcvarsall.bat" (
 call "%%VSPATH%%..\..\vc\vcvarsall.bat" amd64
 goto compile
)

echo Unable to set up the environment
pause
exit

:compile
rem MSBuild /help
MSBuild marketmaker.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64
MSBuild marketmaker.sln /t:Rebuild /p:Configuration=Release /p:Platform=x86

rem Using to add in marketmaker_release.7z
set host=%COMPUTERNAME%
IF "%host%"=="VM-81" (
    mkdir package_content\win32
    mkdir package_content\win64
    copy /y Release\marketmaker.exe package_content\win32
    copy /y x64\Release\marketmaker.exe package_content\win64
    cd package_content
    "C:\Program Files\7-Zip\7z.exe" a C:\komodo\marketmaker_release\marketmaker_release.7z win32\marketmaker.exe
    "C:\Program Files\7-Zip\7z.exe" a C:\komodo\marketmaker_release\marketmaker_release.7z win64\marketmaker.exe
    cd ..
    rd package_content /s /q
    )
