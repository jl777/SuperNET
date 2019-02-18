rem --- libsodium ---
:compile_libsodium
cd marketmaker_depends
git clone https://github.com/jedisct1/libsodium
cd libsodium\builds\msvc\vs2015
MSBuild libsodium.sln /t:Rebuild /p:Configuration=DynRelease /p:Platform=Win32
MSBuild libsodium.sln /t:Rebuild /p:Configuration=DynRelease /p:Platform=x64
cd ..\..\..\..\..
xcopy marketmaker_depends\libsodium\src\libsodium\include includes /O /X /E /H /K /Y
xcopy marketmaker_depends\libsodium\bin\x64\Release\v140\dynamic OSlibs\win\x64\release /O /X /E /H /K /Y
xcopy marketmaker_depends\libsodium\bin\Win32\Release\v140\dynamic OSlibs\win /O /X /E /H /K /Y
copy marketmaker_depends\libsodium\bin\x64\Release\v140\dynamic\libsodium.dll x64\Release
