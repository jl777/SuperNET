@echo off
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"enable\",\"coin\":\"REVS\"}"
