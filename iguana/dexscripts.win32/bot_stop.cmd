@echo off
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
set /p PASSPHRASE=<passphrase
rem echo passphrase: "%PASSPHRASE%"
rem echo userpass: "%USERPASS%"
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"bot_stop\",\"botid\":1376557535}"