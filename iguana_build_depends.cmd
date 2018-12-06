@echo off
rem [ Decker] Automatically download and build depends script for marketmaker.
rem
rem 1. Requires installed CMake for Windows (!)
rem 2. Currently build only 64-bit release versions of .lib and .dll
rem 3. Libraries available: pthreads, nanomsg, curl

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
echo.
echo Decker will automatically download and build all needed *.dll and *.lib for you ;)

mkdir iguana_depends
mkdir x64\Release

rem --- libsodium ---
rem https://libsodium.gitbook.io/doc/installation

:compile_libsodium

if not exist iguana_depends\libsodium\bin\x64\Release\v140\dynamic\libsodium.lib (
cd iguana_depends
git clone https://github.com/jedisct1/libsodium
cd libsodium
cd "builds\msvc\vs2015" 
MSBuild libsodium.sln /t:Rebuild /p:Configuration=DynRelease /p:Platform=x64
MSBuild libsodium.sln /t:Rebuild /p:Configuration=DynDebug /p:Platform=x64
cd ../../..
cd ..
)

copy iguana_depends\libsodium\bin\x64\Release\v140\dynamic\libsodium.lib OSlibs\win\x64\release\libsodium.lib
copy iguana_depends\libsodium\bin\x64\Release\v140\dynamic\libsodium.exp OSlibs\win\x64\release\libsodium.exp
copy iguana_depends\libsodium\bin\x64\Release\v140\dynamic\libsodium.dll x64\Release\libsodium.dll

rem mkdir OSlibs\win\x64\debug
rem libs for configuration: Debug stored in OSlibs\win\x64 (check .sln)
copy iguana_depends\libsodium\bin\x64\Debug\v140\dynamic\libsodium.lib OSlibs\win\x64\libsodium.lib
copy iguana_depends\libsodium\bin\x64\Debug\v140\dynamic\libsodium.exp OSlibs\win\x64\libsodium.exp
copy iguana_depends\libsodium\bin\x64\Debug\v140\dynamic\libsodium.dll x64\Debug\libsodium.dll

mkdir includes\sodium
xcopy /E /Y iguana_depends\libsodium\src\libsodium\include\sodium includes\sodium
copy iguana_depends\libsodium\src\libsodium\include\sodium.h includes\