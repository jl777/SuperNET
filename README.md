#SuperNET Client Iguana

<<<<<<< HEAD
OS | Build Status 
-------------|------
Unix (Ubuntu 14.04) | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=Unix-jl777)](https://jenkinsmaster.sprnt.pw/job/Unix-jl777)
Chrome | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=PNaCl-jl777)](https://jenkinsmaster.sprnt.pw/job/PNaCl-jl777/)
Android | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=Android)](https://jenkinsmaster.sprnt.pw/job/Android/)
iOS | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=iOS)](https://jenkinsmaster.sprnt.pw/job/iOS/)
Windows 32 Bit | [![Build Status](https://jenkinsmaster.sprnt.pw/job/Win32/badge/icon)](https://jenkinsmaster.sprnt.pw/job/Win32/)
Windows 64 Bit | [![Build Status](https://jenkinsmaster.sprnt.pw/job/Win64-jl777/badge/icon)](https://jenkinsmaster.sprnt.pw/job/Win64-jl777/)
docs.supernet.org | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=docs.supernet.org-updating)](https://jenkinsmaster.sprnt.pw/job/docs.supernet.org-updating/)

---

Codebase is going under radical changes now and versions from mid-May should be used unless you are doing advanced testing. There will be four layers:

gecko: abstracted bitcoin compatible blockchains that run via basilisk lite mode or as iguana core full network peers. I will try to get a geckochain to simultaneously have both virtual basilisk nodes and private iguana nodes, but at first will probably need to choose which mode a new chain will be and transition between the two via special suspend and resume functions that allow migration from virtual to physical. Each specific geckochain will be able to be enhanced into a datachain.

basilisk: abstracted crypto transactions layer, which has a reference implementation for bitcoin protocol via the iguana nodes, but can be expanded to support any coin protocol that can support the required functions. Since it works with bitcoin protocol, any 2.0 coin with at least bitcoin level functionality should be able to create a basilisk interface.

iguana: most efficient bitcoin core implementation that can simultaneously be full peers for multiple bitcoin blockchains. Special support being added to virtualize blockchains so all can share the same peers. The iguana peers identify as a supernet node, regardless of which coin, so by having nodes that support multiple coins, supernet peers are propagated across all coins. non-iguana peers wont get any non-standard packets so it is interoperable with all the existing bitcoin and bitcoin clone networks

komodo: this is the top secret project I cant talk about publicly yet

> #TL;DR#
> 
> ```sudo apt-get update; sudo apt-get install git build-essential; git clone https://github.com/jl777/SuperNET; cd SuperNET; ./m_onetime m_unix;```
> 
> The above one line gets SuperNET installed, built and launched for unix. 
> 
> After that ```./m_unix``` updates to latest.
> *Continue below at "Running".*

**iguana is easy to build. Start by cloning (or downloading) this repository.**
*** all external dependencies have been removed, except for -lpthread and -lm


##For native (win32, win64)##
TOOL_DIR := /usr/local/gcc-4.8.0-qt-4.8.4-for-mingw32/win32-gcc/bin
MINGW := i586-mingw32
The above two definitions need to be changed to match the mingw install on your system. m_win32 and m_win64 just invokes the makefile in mingw32 and mingw64

##For chrome app##
You need to make sure the nacl sdk is properly installed and you are able to build the examples.
Now you will need to get the external libs, which can be built from scratch using naclports or there use the reference builds of libcurl.a and libz.a in the SuperNET/crypto777/pnacl_libs. You can just copy those over into $(NACL_SDK_ROOT)/<pepper_dir>/lib/pnacl.


#ONETIME#
Now you are ready to build.
I try to make the build process as simple as possible, so there are no `autoconf`, `autoreconf`, `configure`, `cmake`, `make`, to get properly installed and running and run, etc. You do need a C compiler, like gcc.

The **first time** you need to build libcrypto777.a and to do that you need to run:

For unix: ```./m_onetime m_unix```

For osx: ```./m_onetime m_osx```

For win32: ```./m_onetime m_win32```

For win64: ```./m_onetime m_win64```

#(RE)BUILD

Once libcrypto777.a is built, you can build the agents.

For pnacl: ```cd crypto777; make clean; make; cd ../iguana; make clean; make```

For unix: ```./m_unix```

For osx: ```./m_osx```

For win32: ```./m_win32```

For win64: ```./m_win64```


The m_(OS) is a standard I follow and should be self explanatory. within each is usually just a few lines, ie compile all the .c files and link with the standard libs.

To build just iguana, you can ```cd``` into SuperNET/iguana and do ```./m_unix``` (or ```./m_osx```, ...).

```./m_clean``` will remove the files created from the building

#RUNNING#

The native versions are command line applications: agents/iguana {JSON}
The chrome app pexe requires that the chrome is launched with a command line parameter (tools/chrome.localhost) and then browse to *http://127.0.0.1:7777* to see the pexe

#SUPERUGLYGUI#

Once iguana is running, you can see the superuglyGUI at *http://127.0.0.1:7778/?method*
by submitting API calls using the forms, you will see it go to some specific URL. You can also do a programmatic GET request to ```http://127.0.0.1:7778/api/<path to apicall>```

*http://127.0.0.1:7778/ramchain/block/height/0* -> full webpage

*http://127.0.0.1:7778/json/ramchain/block/height/0* -> JSON only

```curl --url "http://127.0.0.1:7778/ramchain/BTCD/block/height/0"``` --> full webpage returned (probably not what you want)
```curl --url "http://127.0.0.1:7778/api/ramchain/BTCD/block/height/0"``` --> returns just the json object from the api call

Internally, all paths convert the request into a standard SuperNET JSON request. you can use a POST command to directly submit such JSON requests:
```curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"ramchain\",\"method\":\"block\",\"coin\":\"BTCD\",\"height\":0}"```

Another approach is to use the bitcoin RPC syntax via:
 curl --url "http://127.0.0.1:7778" --data "{\"coin\":\"BTCD\",\"method\":\"getinfo\",\"params\":[]}"
the params:[] array is where the standard bitcoin parameters go, the only change that is needed is to specify the coin
alternatively {"agent":"SuperNET","method":"bitcoinrpc","coin":"BTCD"} will set the coin 
to use for bitcoin RPC calls. this will suffice in single coin environments

curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana",\"method\":\"test\"}"
curl --url "http://127.0.0.1:7778/iguana/test" -> html page with results
curl --url "http://127.0.0.1:7778/api/iguana/test" -> just json text
http://127.0.0.1:7778 -> superugly GUI
http://127.0.0.1:7778/iguana/test 
http://127.0.0.1:7778/api/iguana/test
postCall('{"agent":"iguana","method":"test"}'}
iguana_JSON("{\"agent\":\"iguana",\"method\":\"test\"}"); -> direct C function call


iguana can be invoked with a command line argument. if it is a name of a file, it will load it and check to see if it is valid JSON and if it is, it will use it. Otherwise the command line argument needs to be valid JSON to be used and it will process the JSON to initialize account passphrases, exchange apikeys, etc. A few special keys:

"wallet" -> passphrase used for the persistent privkey
"2fafile" -> secondary part (optional) for the persistent privkey
"numhelpers" -> number of helper threads (need at least 1)
"exchanges" -> { "name":"<name of exchange>", ... }
    "apikey", "apisecret", "userid", "tradepassword" these are as expected
    "pollgap" -> gap between each access to exchange for getting prices
    
on OSX mksquashfs is not native, you will need to install fuse: https://osxfuse.github.io/ and a squashfs for mac: https://github.com/vasi/squashfuse

    **********
    user feedback:
    A Note on Installation from pebwindkraft at bitco.in
=======================
Though I had xcode installed, aclocal didn’t work. I installed homebrew, and then:
# brew install autoconf
# brew install automake
# brew install gmp

2.) libsecp256
it complained, that libsecp256 was not there in includes, so I linked it.
Loretta:/Users/volker/SuperNET/includes # ln -s ../osx/libsecp256k1 .

3.) I had to change ulimit
During the syncing, I have many, many messages like this:
>>
>> cant create.(tmp/BTC/252000/.tmpmarker) errno.24 Too many open files
>> cant create.(tmp/BTC/18000/.tmpmarker) errno.24 Too many open files
>>
Loretta:/Users/volker/SuperNET # ulimit -n 100000


##### tests
in the SuperNET/iguana/tests directory, there is a jsoncmp.c file, which can be built into the jsoncmp executable via ./make_jsoncmp
once jsoncmp is built, then ./test shows how to use it
./jsoncmp <filename> {\"fields\":[{\"fieldA\":\"requiredvalueA\"},{\"fieldB\":\"requiredvalueB\"},...]}

the idea is to issue a curl command into a /tmp/file and then use jsoncmp to verify the exact value of one or more fields. it will print to stdout JSON with "error" or "result" and to stderr if there is an error
=======
Iguana is an app providing advanced benefits from cryptocurrencies and blockchain. Iguana itself combines a set of tools (from multi-currency wallet to real-time exchange) and backend technologies (The Multigateway, InstatDEX, Teleport, Telepathy, etc.) to reveal new types operations with cryptocurrencies, enhance personal security and anonymity, to accelerate transactions clearing procedure speed.
>>>>>>> Switched to pure HTML/CSS/JS

#Dev Notes
##Dependencies 
* Bootstrap v3.3.6
* Jquery v3.0.0

