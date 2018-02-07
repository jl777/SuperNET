@echo off
rem http://pad.supernet.org/electrum-servers
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
set /p PASSPHRASE=<passphrase
echo passphrase: "%PASSPHRASE%"
echo userpass: "%USERPASS%"
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"electrum\",\"coin\":\"KMD\",\"ipaddr\":\"electrum.cipig.net\",\"port\":10001}"
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"electrum\",\"coin\":\"MNZ\",\"ipaddr\":\"electrum.cipig.net\",\"port\":10002}"