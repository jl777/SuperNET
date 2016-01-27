SET KEY_NAME=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe
FOR /F "skip=2 tokens=2,*" %%A IN ('reg query "%KEY_NAME%" /ve') DO set "CHROME_PATH=%%B"
REM echo %CHROME_PATH%

"%CHROME_PATH%" -allow-nacl-socket-api=localhost