You need to build iguana onetime from ~/SuperNET/iguana:

./m_LP

Then launch it to run in background ../agents/iguana &

Now iguana should be running and providing port 7778 API: 127.0.0.1:7778 page in the browser will show the API testpage, but for marketmaker these functions are not used very much. it is port 7779 that is used and the marketmaker program is what provides those functions.

From ~/SuperNET/iguana/exchanges:

./install

From ~/SuperNET/iguana/dexscripts:

Now in the ~/SuperNET/iguana/dexscripts directory you will have example scripts that you can change without new git updates overwriting them. Of course, if a new update to a script is made and you dont run install again then you wont have the latest versions. All these scripts are expecting a userpass file, which contains the definition of the $userpass variable to authenticate API access. This avoids evil webpages that try to issue port 7779 calls to steal your money. The userpass variable is linked to each passphrase and that is defined in the randval file. Put your passphrase in that file. You can find templates for these two files in the iguana/exchanges dir.

Next step is to actually start the marketmaker from ~/SuperNET/iguana/dexscripts. Use ./run for LP node and ./client for client mode

At first you wont know the value of userpass. To find out, just run any API script. The first one will return all the required data, the "userpass" field is first and you can copy that value and put it into ~/SuperNET/iguana/dexscripts/userpass file. If you dont, all subsequent API calls will get authorization errors.

Assuming you created the userpass file properly, you can now issue barterDEX api calls using all the scripts in the dexscripts dir. Please look at these scripts, they are simple curl invocations of a couple lines. Nothing scary and should be self explanatory.

The help script displays all the api endpoints you should need. You can customize any of the dexscripts for your desired usage, make sure you edit them with the right coins, as if you issue a script for BTC it will do it for BTC instead of the coin you wanted. These scripts wont read your mind, they just do what is in them

In order to start trading, you need to fund your smartaddress (as listed on the first API call return) from the getcoins API call. To make sure you have utxo pairs for both the bob and alice usage, it is best to send utxo in triplets of X, 1.2 X and 0.01 X. So if X is 10, send 10, 12, and 0.1 coins using sendtoaddress to your smartaddress. After this, it should appear in the inventory. After you setprice, then it will appear in orderbooks with that coin in either the base or rel.

