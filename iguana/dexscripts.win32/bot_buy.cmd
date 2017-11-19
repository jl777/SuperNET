@echo off
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
set /p PASSPHRASE=<passphrase
echo passphrase: "%PASSPHRASE%"
echo userpass: "%USERPASS%"
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"bot_buy\",\"base\":\"MNZ\",\"rel\":\"KMD\",\"maxprice\":0.20,\"relvolume\":10.0}"