## What's this?

This is a first build of **MarketMaker** app from barterDEX for Windows (64-bit) platform. This branch includes all that you need to build marketmaker for Windows. 64-bit build uses MSVC 2015 as a default C/C++ compiler, to build - simply open *marketmaker.sln* project file via File -> Open -> Project/Solution ... next choose Release / x64 configuration and build solution. Your binaries will be placed x64\Release folder. To run marketmaker you also need following dll libraries:

- libcurl.dll
- nanomsg.dll
- curl.exe (win64 curl binary, used is scripts)

It already included in this branch.

## How to use?

Please, refer to original barterDEX documentation and Komodo Platform + SuperNET resources to learn how to work this it. Later i will add some examples and useful links here.

Important, coins.json on Windows shouldn't contain coins which haven't running daemons. Add to coins.json only coins that you plan to use, in other case starting marketmaker will too long: about 4 seconds on each not-running coin.

Get the latest binary release from release section and step-by-step run cmd files:

- 1-client.cmd - this runs marketmaker with passphrase taken from a passphrase file.
- 2-getuserpass.cmd - this will save and output your userpass in userpass file for future use.
- 3-orderbook.cmd - to get an orderbook (if u downloaded binary release from release section - it's have only REVS in coins.json and orderbook will be shown at KMD/REVS coins pair).

Other scripts will be post later ... this is just for example that it works.

 