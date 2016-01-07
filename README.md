iguana is easy to build. just make sure you have the dev versions of openssl and curl installed

gcc -O2 -o iguana *.c InstantDEX/*.c -lssl -lcrypto -lpthread -lcurl -lm

the above builds native iguana on unix/osx

then just run it and browse to http://127.0.0.1:7778/?method
you can use the gui to find the URL you need for an operation, then add /json to get just the json and not the entire webpage. alternatively a POST (ie via curl --data) with the JSON request will just return json

http://127.0.0.1:7778/ramchain/block/height/0 -> full webpage

http://127.0.0.1:7778/json/ramchain/block/height/0 -> JSON only

the superugly GUI is not stateless, there is a default coin that is used for any coin based API.
