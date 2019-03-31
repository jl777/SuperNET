# How to partcipate
Fork this repo.

Edit the `iguana/m_notary_testnet` file. Add a line with your IP address. 

Edit the `iguana/testnet.json` file. Add your pubkey and name.

Make a PR with edits to this repo. 

# How to start the notary

Clone this repo.

Install the dependencies
```
sudo apt-get install build-essential pkg-config libc6-dev m4 \
        g++-multilib autoconf libtool ncurses-dev unzip git python \
        zlib1g-dev wget bsdmainutils automake libboost-all-dev \
        libssl-dev libprotobuf-dev protobuf-compiler \
        libqrencode-dev libdb++-dev ntp ntpdate vim software-properties-common \
        curl libevent-dev libcurl4-gnutls-dev libsodium-dev cmake clang
```

You must install nanomsg as well. See https://github.com/KomodoPlatform/komodo/wiki/Installing-Komodo-Manually#install-nanomsg

Start PIZZA, BEER, TXSCLCC and KMD daemons with `-pubkey=` 

Open p2p ports for each coin. Open port 17711 for iguana. 

Fund `-pubkey=` address on all 3 nodes. Import privkey to all 3 nodes. 

If you need PIZZA or BEER, use the faucets at https://www.atomicexplorer.com/#/faucet/beer and https://www.atomicexplorer.com/#/faucet/pizza or ask in #notarynode channel. For TXSCLCC chain, please mine 1 block using 1 CPU thread to use for notarization and after mining a block you can stop mining TXSCLCC.

Create a file named `pubkey.txt` at `~/2019NNtestnet/iguana/pubkey.txt`. Contents should be 
```
pubkey=<pubkey>
```

Create a file named `passphrase.txt` at `~/2019NNtestnet/iguana/passphrase.txt`. Contents should be
```
passphrase=<WIF>
```

Wait until the PR is merged. 

Then use the following to start notarization.
```
cd ~/2019NNtestnet/iguana
./m_notary_testnet
```

# How to restart when new participants are added 

```
./m_notary_testnet
```
