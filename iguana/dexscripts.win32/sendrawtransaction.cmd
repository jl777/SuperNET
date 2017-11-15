@echo off
set /p TMPUSERPASS=<userpass
set USERPASS=%TMPUSERPASS: =%
set HEX=your_signed_raw_tx
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"%USERPASS%\",\"method\":\"sendrawtransaction\",\"coin\":\"KMD\",\"signedtx\":%HEX%"\"}"
