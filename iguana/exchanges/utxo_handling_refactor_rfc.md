# UTXO handling refactoring

This document is written to suggest and discuss possible ways of refactoring UTXO handling code in MM2.0.

## Problems and Goals

BarterDEX main goal is to allow any user with any technical background to download app, send coins to address and be able to 
trade with any other user without knowledge about underlying technology. UX should be similar to centralized exchanges.  

Most of coins supported on BarterDEX are different bitcoin forks based on UTXO protocol: 
https://bitcoin.org/en/developer-guide#block-chain-overview.  

Current MM implementation is very dependent on set of UTXOs. As example when you want to deposit coins
to BarterDEX address you will get a message that you should send 3 small transactions instead of big one.
This is due to how MM handles address utxos. 
According to protocol https://github.com/SuperNETorg/komodo/wiki/barterDEX-Whitepaper-v2#overview-of-atomic-swaps-protocol
each side of swap (in case of success) requires at least 2 utxos: for Alice dexfee and payment OR Bob deposit and payment.
From Alice (buying side) these utxos are selected at time of *broadcasting* the order. MM also searchs for utxos that 
are *close* to the amount required for trade. If such utxos are not found order will either *fail* or cause *splitting*
to cut some big utxo to smaller pieces.  

Such things confuse the user a lot: let's imagine that one sent 5 BEER to his BarterDEX address and wants to buy 2 PIZZA
at 1:1 rate. His utxo will either split causing to pay additional fees (which might be very high sometimes) or he will
get message that he needs to send tx close to amount of he wants to trade (additional fees are also included).
This is not like centralized exchages work. Users expect that they are able to trade *ANY* amount which is lower or
equal to their deposit. 

Another drawback: address becomes full of small utxos after split and these are not usable for any trade,
my test addresses (on Jenkins CI) generate hundreds of unusable utxos in very short time.
It's painful and costly (in case of dynamic fee) to merge them back, MM doesn't do this automatically. 
 
1 more drawback: according to the set of found utxos MM can adjust trading amount and price to match the order.
Users won't like such behavior, they expect that they will spend exact quantity of a coin to receive exact number of another one.  

Also the orders do not match if price difference is larger than 10%. It's confusing when you see 1:1 selling order, 
place 2:1 buy, but it doesn't match. 

### Requirements we should meet
1. Disallow negotiation when 1 of the sides has insufficient funds to execute the trade.

### Goals. What's planned to do
1. Remove the selection and locking of specific utxos on order placing. Track the address balance and `virtually` lock the
amount required to trade. Available amount will be equal to `current_balance - locked_amount`.
1. Remove UTXO selection/verification on order broadcasting. Verify other side balance using Electrum.
1. Select the utxos when swap is already running - just before sending a transaction. 
Do not use single utxo as input for tx, select and merge multiple utxos of lower amount. e.g. payment amount is `3`, 
address has 3 utxo amounts: `2`, `1`, `1`. Use `2` and `1` utxo to send payment.
1. Trade *EXACT* amounts and prices that users set.


