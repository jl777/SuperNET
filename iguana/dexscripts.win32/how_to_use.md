## DexScripts for Windows. How to use? ##

**1. ** Before start you should put scripts and following binaries into one folder:
 
- curl.exe (required for all scripts)
- marketmaker.exe
- libcurl.dll (required to run marketmaker)
- nanomsg.dll (required to run marketmaker)

**2. ** Don't forget to put `coins.json` file into a same folder. This file is available it this repo.

**3. ** Type your passphrase into passphrase file in this folder (you should create file with name `passphrase` and without extension) and run `1-client.cmd`. This will run marketmaker. Next step is to obtain userpass needed for other scripts, you can simply copy and paste it from marketmaker output on startup into userpass file. 

![](./images/userpass.png)

Or run `2-getuserpass.cmd` to fill userpass file automatically.** NB!** To get userpass you shouldn't run any scripts between 1-client.cmd and 2-getuserpass.cmd launching.

Sample output of correct `2-getuserpass.cmd` usage is:

![](./images/userpass_usage.png)

You should see your userpass on screen, and after it will automatically copied in userpass file. It's important to all other scripts to have this password in userpass file. If output of `2-getuserpass.cmd` is not same as showed on screen above - wait some seconds and run `2-getuserpass.cmd` again. Also make sure that you have allowed marketmaker to accept incoming connections in your Windows Firewall (first time launched system should automatically asked for it).

**4.** For using other scripts please refer to barterDEX API. Or **barterDEX API Summary by Category** document by *shossain*.  

## F.A.Q. ##

**Q.** Is any simple way how i can display JSON results returned by all scripts, like orderbook and others, in human readable form?
**A.** Yes, you can use this service [JSON Editor Online](http://jsoneditoronline.org/), just copy and paste output of script in left column and see structured output in right.

**Q.** I see an output like this when i'm start `1-client.cmd` :

    bind(0.0.0.0) port.7783 failed: No error sock.1468. errno.0
    bind(0.0.0.0) port.7783 failed: No error sock.1516. errno.0
    bind(0.0.0.0) port.7783 failed: No error sock.1444. errno.0
    bind(0.0.0.0) port.7783 failed: No error sock.1484. errno.0
    bind(0.0.0.0) port.7783 failed: No error sock.1412. errno.0
    bind(0.0.0.0) port.7783 failed: No error sock.1524. errno.0
    bind(0.0.0.0) port.7783 failed: No error sock.1008. errno.0

And nothing works.

**A.** Before run `1-client.cmd` make sure in Task Manager that you haven't already running `marketmaker.exe`. If have - kill this process via Task Manager or via command line command `taskkill /f /im taskkill.exe` .

