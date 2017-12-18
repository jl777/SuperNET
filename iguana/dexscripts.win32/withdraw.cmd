@echo off
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
rem *** Change coin and outputs before use (!) ***
set COIN=KMD
set OUTPUTS=[{\"RDecker69MM5dhDBosUXPNTzfoGqxPQqHu\":0.00007777}]
curl -s --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"withdraw\",\"coin\":\"%COIN%\",\"outputs\":%OUTPUTS%}" > withdraw.txt
type withdraw.txt
