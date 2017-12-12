@echo off
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"listunspent\",\"coin\":\"KMD\",\"address\":\"RSpP2Nffy379SwF1cAkooNg6vwPHpakCpC\"}"
