Latest Readme is at http://pad.supernet.org/barterdex-readme

DEPENDENCIES
First of all you are going to need to have the komodod daemon and the assetchains running.
Install dependency packages:
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool libncurses5-dev unzip git python zlib1g-dev wget bsdmainutils automake libboost-all-dev libssl-dev libprotobuf-dev protobuf-compiler libqt4-dev libqrencode-dev libdb++-dev ntp ntpdate vim software-properties-common curl libcurl4-gnutls-dev cmake clang
Some Linux machines are now providing nanomsg package version 1.0. If it is available via package manager, you can install it from there. Else, you should use github repo of nanomsg and compile it yourself.
For Ubuntu 14.04 you need to install it yourself
cd /tmp
wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz -O nanomsg-1.0.0.tar.gz
tar -xzvf nanomsg-1.0.0.tar.gz
cd nanomsg-1.0.0
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
cmake --build .
sudo cmake --build . --target install
sudo ldconfig
Or the following for 16.04
git clone https://github.com/nanomsg/nanomsg
cd nanomsg
cmake .
make
sudo make install
sudo ldconfig
COMPILE LP NODE
To compile the BarterDEX you need to build iguana one time:
cd ~
git clone https://github.com/jl777/SuperNET
cd SuperNET/iguana
git checkout dev
./m_LP
IGUANA DAEMON STARTUP
Then launch the iguana daemon by executing: 
../agents/iguana &
Now iguana should be running and providing port 7778 API: 127.0.0.1:7778 page in the browser will show the API testpage, but for marketmaker these functions are not used very much. it is port 7779 that is used and the marketmaker program is what provides those functions.
BarterDEX EXCHANGE INSTALL
cd ~/SuperNET/iguana/exchanges 
./install
Now, move to ~/SuperNET/iguana/dexscripts:
cd ~/SuperNET/iguana/dexscripts
Now in the ~/SuperNET/iguana/dexscripts directory you will have example scripts that you can change without new git updates overwriting them. These scripts will have example commands that you will need to customize to work with the coins you want to trade. Of course, if a new update to a script is made and you dont run install again then you wont have the latest versions. 
For example: if you want to enable the JUMBLR coin, you need to edit the enable file:
nano ~SuperNET/iguana/dexscripts/enable
copy the default command and paste it below but with the coin edited to JUMBLR in this case:
curl --url "http://127.0.0.1:7779" --data "{\"userpass\":\"$userpass\",\"method\":\"enable\",\"coin\":\"JUMBLR\"}"
The same will happen for any other script in the dexscripts directory. You will need to edit the scripts to include or exclude the coins you want to trade.
IMPORTANT: All these scripts are expecting a userpass file, which contains the definition of the $userpass variable to authenticate API access. This avoids evil webpages that try to issue port 7779 calls to steal your money. At first you wont know the value of userpass. To find out, just run any API script. The first one will return all the required data, the "userpass" field is first and you can copy that value and put it into ~/SuperNET/iguana/dexscripts/userpass file. If you dont, all subsequent API calls will get authorization errors.The userpass variable is linked to each passphrase and that is defined in the passphrase file. Put your passphrase in that file. You can find templates for these two files in the iguana/exchanges dir. (you need to copy the edited version of these files to ~/SuperNET/iguana/dexscripts).
cd ~/SuperNET/iguana/dexscripts
./enable 
(look for the userpass passphrase that will be generated and copy it)
Now you have to paste the passphrase in both userpass and passphrase files:
nano ./userpass 
nano ./passphrase
( paste the passphrase generated into the files where it says: “<put the userpass value from the first API call here>”)
EXCHANGE CLIENT STARTUP
Next step is to actually start the marketmaker from ~/SuperNET/iguana/dexscripts. 
 cd ~/SuperNET/iguana/dexscripts
 ./client (for client mode) or
 ./run (for LPnode mode)
Assuming you created the userpass file properly, you can now issue barterDEX api calls using all the scripts in the dexscripts dir. Please look at these scripts, they are simple curl invocations of a couple lines. Nothing scary and should be self explanatory.
The help script displays all the api endpoints you should need. You can customize any of the dexscripts for your desired usage, make sure you edit them with the right coins, as if you issue a script for BTC it will do it for BTC instead of the coin you wanted. These scripts wont read your mind, they just do what is in them
FUNDING SMARTADDRESS
In order to start trading, you need to fund your smartaddress (as listed on the first API call return) from the getcoins API call. 
To see which is your smart address go to ~/SuperNET/iguana/dexscritps and execute:
./getcoins
To make sure you have utxo pairs for both the bob and alice usage, it is best to send utxo in triplets of X, 1.2 X and 0.01 X. So if X is 10, send 10, 12, and 0.1 coins using sendtoaddress to your smartaddress. This means you will have to send 3 different transactions to the same address with 3 different quantities
for example: 
If i want to fund my komodo smartaddress with 100 komodo i need to first send a tx with 100kmd then another tx with 120kmd and a third tx with only 10kmd
After this, it should appear in the inventory. To see the inventory you need to execute:
./inv
SETTING PRICE
 To set price you need to edit the ./setprice script in the dexscripts folder. This scripts contains a curl command that looks like this: 
curl --url "http://127.0.0.1:7779" --data "{\"userpass\":\"$userpass\",\"method\":\"setprice\",\"base\":\"REVS\",\"rel\":\"KMD\",\"price\":1.234}"
In this command you should edit the coin (in this case is REVS) and then set the price per coin based in Komodo. In the command above we are setting a price of 1.23KMD per REVS.
After you setprice (./setprice), then it will appear in orderbooks with that coin in either the base or rel.

