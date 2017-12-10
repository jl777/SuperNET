@echo off
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
rem *** Change coin and outputs before use (!) ***
set COIN=KMD
set SMARTADDRESS=RDecker69MM5dhDBosUXPNTzfoGqxPQqHu
set OUTPUTS=[{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871},{\"%SMARTADDRESS%\":1.002},{\"%SMARTADDRESS%\":0.00386871}]
curl -s --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"withdraw\",\"coin\":\"%COIN%\",\"outputs\":%OUTPUTS%}" > withdraw.txt
type withdraw.txt
timeout /t 5 /nobreak
for /f "tokens=4 delims=:," %%a in (' find "hex" "withdraw.txt" ') do (
rem echo [%%~a]
curl -s --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"sendrawtransaction\",\"coin\":\"%COIN%\",\"signedtx\":\"%%~a\"}"
)
