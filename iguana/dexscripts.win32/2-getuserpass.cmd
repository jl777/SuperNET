@echo off
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":null,\"method\":\"enable\",\"coin\":\" \"}" -s > userpass.json
for /f "tokens=2 delims=:," %%a in (' find "userpass" "userpass.json" ') do (
echo UserPass: %%~a 
echo %%~a > userpass
)
del userpass.json