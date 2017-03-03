

dpow API
===
need to create help/dpow.md file

## method: pending

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dpow\",\"method\":\"pending\",\"fiat\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dpow/pending?fiat={string}
```

field | value type | Description
--------- | ------- | -----------
fiat | string | no help info

## method: notarychains

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dpow\",\"method\":\"notarychains\"}"
```

```url
http://127.0.0.1:7778/api/dpow/notarychains
```

field | value type | Description
--------- | ------- | -----------

## method: active

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dpow\",\"method\":\"active\",\"maskhex\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dpow/active?maskhex={string}
```

field | value type | Description
--------- | ------- | -----------
maskhex | string | no help info

## method: ratify

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dpow\",\"method\":\"ratify\",\"minsigs\":\"{int}\",\"timestamp\":\"{int}\",\"ratified\":\"{array}\"}"
```

```url
http://127.0.0.1:7778/api/dpow/ratify?minsigs={int}&timestamp={int}&ratified={array}
```

field | value type | Description
--------- | ------- | -----------
minsigs | int | no help info
timestamp | int | no help info
ratified | array | no help info

## method: cancelratify

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dpow\",\"method\":\"cancelratify\"}"
```

```url
http://127.0.0.1:7778/api/dpow/cancelratify
```

field | value type | Description
--------- | ------- | -----------

## method: bindaddr

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dpow\",\"method\":\"bindaddr\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dpow/bindaddr?ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
ipaddr | string | no help info

## method: fundnotaries

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dpow\",\"method\":\"fundnotaries\",\"symbol\":\"{string}\",\"numblocks\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/dpow/fundnotaries?symbol={string}&numblocks={int}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
numblocks | int | no help info

pax API
===
need to create help/pax.md file

## method: start

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"pax\",\"method\":\"start\"}"
```

```url
http://127.0.0.1:7778/api/pax/start
```

field | value type | Description
--------- | ------- | -----------

passthru API
===
need to create help/passthru.md file

## method: paxfiats

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"passthru\",\"method\":\"paxfiats\",\"mask\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/passthru/paxfiats?mask={int}
```

field | value type | Description
--------- | ------- | -----------
mask | int | no help info

zcash API
===
need to create help/zcash.md file

## method: passthru

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"zcash\",\"method\":\"passthru\",\"function\":\"{string}\",\"hex\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/zcash/passthru?function={string}&hex={string}
```

field | value type | Description
--------- | ------- | -----------
function | string | no help info
hex | string | no help info

komodo API
===
need to create help/komodo.md file

## method: passthru

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"komodo\",\"method\":\"passthru\",\"function\":\"{string}\",\"hex\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/komodo/passthru?function={string}&hex={string}
```

field | value type | Description
--------- | ------- | -----------
function | string | no help info
hex | string | no help info

dex API
===
need to create help/dex.md file

## method: kvsearch

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"kvsearch\",\"symbol\":\"{string}\",\"key\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/kvsearch?symbol={string}&key={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
key | string | no help info

## method: kvupdate

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"kvupdate\",\"symbol\":\"{string}\",\"key\":\"{string}\",\"value\":\"{string}\",\"flags\":\"{int}\",\"unused\":\"{int}\",\"unusedb\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/dex/kvupdate?symbol={string}&key={string}&value={string}&flags={int}&unused={int}&unusedb={int}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
key | string | no help info
value | string | no help info
flags | int | no help info
unused | int | no help info
unusedb | int | no help info

## method: send

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"send\",\"hex\":\"{string}\",\"handler\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/send?hex={string}&handler={string}
```

field | value type | Description
--------- | ------- | -----------
hex | string | no help info
handler | string | no help info

## method: gettransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"gettransaction\",\"txid\":\"{hash}\",\"symbol\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/dex/gettransaction?txid={hash}&symbol={str}
```

field | value type | Description
--------- | ------- | -----------
txid | hash | no help info
symbol | str | no help info

## method: getinfo

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"getinfo\",\"symbol\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/getinfo?symbol={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info

## method: getnotaries

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"getnotaries\",\"symbol\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/getnotaries?symbol={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info

## method: alladdresses

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"alladdresses\",\"symbol\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/alladdresses?symbol={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info

## method: getbestblockhash

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"getbestblockhash\",\"symbol\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/getbestblockhash?symbol={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info

## method: getblockhash

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"getblockhash\",\"symbol\":\"{string}\",\"height\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/dex/getblockhash?symbol={string}&height={int}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
height | int | no help info

## method: getblock

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"getblock\",\"hash\":\"{hash}\",\"symbol\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/dex/getblock?hash={hash}&symbol={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
symbol | str | no help info

## method: sendrawtransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"sendrawtransaction\",\"symbol\":\"{string}\",\"signedtx\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/sendrawtransaction?symbol={string}&signedtx={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
signedtx | string | no help info

## method: gettxout

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"gettxout\",\"txid\":\"{hash}\",\"symbol\":\"{str}\",\"vout\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/dex/gettxout?txid={hash}&symbol={str}&vout={int}
```

field | value type | Description
--------- | ------- | -----------
txid | hash | no help info
symbol | str | no help info
vout | int | no help info

## method: importaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"importaddress\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/importaddress?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: validateaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"validateaddress\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/validateaddress?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: checkaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"checkaddress\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/checkaddress?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: listunspent

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"listunspent\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/listunspent?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: listtransactions

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"listtransactions\",\"symbol\":\"{string}\",\"address\":\"{string}\",\"count\":\"{float}\",\"skip\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/dex/listtransactions?symbol={string}&address={string}&count={float}&skip={float}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info
count | float | no help info
skip | float | no help info

## method: listunspent2

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"listunspent2\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/listunspent2?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: listtransactions2

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"listtransactions2\",\"symbol\":\"{string}\",\"address\":\"{string}\",\"count\":\"{float}\",\"skip\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/dex/listtransactions2?symbol={string}&address={string}&count={float}&skip={float}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info
count | float | no help info
skip | float | no help info

## method: gettxin

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"gettxin\",\"txid\":\"{hash}\",\"symbol\":\"{str}\",\"vout\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/dex/gettxin?txid={hash}&symbol={str}&vout={int}
```

field | value type | Description
--------- | ------- | -----------
txid | hash | no help info
symbol | str | no help info
vout | int | no help info

## method: listspent

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"listspent\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/listspent?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: getbalance

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"getbalance\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/getbalance?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: explorer

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"dex\",\"method\":\"explorer\",\"symbol\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/dex/explorer?symbol={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info

basilisk API
===
need to create help/basilisk.md file

## method: genesis_opreturn

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"genesis_opreturn\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/genesis_opreturn?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: history

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"history\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/history?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: paxfiats

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"paxfiats\",\"mask\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/paxfiats?mask={int}
```

field | value type | Description
--------- | ------- | -----------
mask | int | no help info

## method: balances

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"balances\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/balances?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: value

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"value\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/value?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: rawtx

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"rawtx\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/rawtx?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: refresh

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"refresh\",\"symbol\":\"{string}\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/refresh?symbol={string}&address={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
address | string | no help info

## method: utxorawtx

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"utxorawtx\",\"symbol\":\"{string}\",\"utxos\":\"{array}\",\"vals\":\"{object}\",\"ignore\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/utxorawtx?symbol={string}&utxos={array}&vals={object}&ignore={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
utxos | array | no help info
vals | object | no help info
ignore | string | no help info

## method: getmessage

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"getmessage\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/getmessage?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: sendmessage

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"sendmessage\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/sendmessage?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: geckoheaders

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"geckoheaders\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/geckoheaders?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: geckoblock

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"geckoblock\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/geckoblock?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: geckotx

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"geckotx\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/geckotx?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: geckoget

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"geckoget\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/geckoget?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: addrelay

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"addrelay\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/addrelay?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: dispatch

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"dispatch\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/dispatch?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: publish

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"publish\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/publish?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: subscribe

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"subscribe\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/subscribe?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: forward

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"forward\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/forward?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: mailbox

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"basilisk\",\"method\":\"mailbox\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/basilisk/mailbox?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

bitcoinrpc API
===
need to create help/bitcoinrpc.md file

## method: getinfo

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getinfo\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getinfo
```

field | value type | Description
--------- | ------- | -----------

## method: getblockcount

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getblockcount\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getblockcount
```

field | value type | Description
--------- | ------- | -----------

## method: getdifficulty

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getdifficulty\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getdifficulty
```

field | value type | Description
--------- | ------- | -----------

## method: getbestblockhash

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getbestblockhash\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getbestblockhash
```

field | value type | Description
--------- | ------- | -----------

## method: getblockhash

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getblockhash\",\"height\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getblockhash?height={int}
```

field | value type | Description
--------- | ------- | -----------
height | int | no help info

## method: getblock

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getblock\",\"blockhash\":\"{hash}\",\"verbose\":\"{int}\",\"remoteonly\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getblock?blockhash={hash}&verbose={int}&remoteonly={int}
```

field | value type | Description
--------- | ------- | -----------
blockhash | hash | no help info
verbose | int | no help info
remoteonly | int | no help info

## method: getrawtransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getrawtransaction\",\"txid\":\"{hash}\",\"verbose\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getrawtransaction?txid={hash}&verbose={int}
```

field | value type | Description
--------- | ------- | -----------
txid | hash | no help info
verbose | int | no help info

## method: gettransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"gettransaction\",\"txid\":\"{hash}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/gettransaction?txid={hash}
```

field | value type | Description
--------- | ------- | -----------
txid | hash | no help info

## method: gettxout

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"gettxout\",\"txid\":\"{hash}\",\"vout\":\"{int}\",\"mempool\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/gettxout?txid={hash}&vout={int}&mempool={int}
```

field | value type | Description
--------- | ------- | -----------
txid | hash | no help info
vout | int | no help info
mempool | int | no help info

## method: listunspent

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listunspent\",\"minconf\":\"{int}\",\"maxconf\":\"{int}\",\"array\":\"{array}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listunspent?minconf={int}&maxconf={int}&array={array}
```

field | value type | Description
--------- | ------- | -----------
minconf | int | no help info
maxconf | int | no help info
array | array | no help info

## method: decodescript

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"decodescript\",\"scriptstr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/decodescript?scriptstr={string}
```

field | value type | Description
--------- | ------- | -----------
scriptstr | string | no help info

## method: decoderawtransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"decoderawtransaction\",\"rawtx\":\"{string}\",\"suppress\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/decoderawtransaction?rawtx={string}&suppress={int}
```

field | value type | Description
--------- | ------- | -----------
rawtx | string | no help info
suppress | int | no help info

## method: validaterawtransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"validaterawtransaction\",\"rawtx\":\"{string}\",\"suppress\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/validaterawtransaction?rawtx={string}&suppress={int}
```

field | value type | Description
--------- | ------- | -----------
rawtx | string | no help info
suppress | int | no help info

## method: createrawtransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"createrawtransaction\",\"vins\":\"{array}\",\"vouts\":\"{object}\",\"locktime\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/createrawtransaction?vins={array}&vouts={object}&locktime={int}
```

field | value type | Description
--------- | ------- | -----------
vins | array | no help info
vouts | object | no help info
locktime | int | no help info

## method: validatepubkey

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"validatepubkey\",\"pubkey\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/validatepubkey?pubkey={string}
```

field | value type | Description
--------- | ------- | -----------
pubkey | string | no help info

## method: validateaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"validateaddress\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/validateaddress?address={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info

## method: walletlock

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"walletlock\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/walletlock
```

field | value type | Description
--------- | ------- | -----------

## method: walletpassphrase

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"walletpassphrase\",\"password\":\"{string}\",\"permanentfile\":\"{string}\",\"timeout\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/walletpassphrase?password={string}&permanentfile={string}&timeout={int}
```

field | value type | Description
--------- | ------- | -----------
password | string | no help info
permanentfile | string | no help info
timeout | int | no help info

## method: encryptwallet

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"encryptwallet\",\"passphrase\":\"{string}\",\"password\":\"{string}\",\"permanentfile\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/encryptwallet?passphrase={string}&password={string}&permanentfile={string}
```

field | value type | Description
--------- | ------- | -----------
passphrase | string | no help info
password | string | no help info
permanentfile | string | no help info

## method: walletpassphrasechange

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"walletpassphrasechange\",\"oldpassword\":\"{string}\",\"newpassword\":\"{string}\",\"oldpermanentfile\":\"{string}\",\"permanentfile\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/walletpassphrasechange?oldpassword={string}&newpassword={string}&oldpermanentfile={string}&permanentfile={string}
```

field | value type | Description
--------- | ------- | -----------
oldpassword | string | no help info
newpassword | string | no help info
oldpermanentfile | string | no help info
permanentfile | string | no help info

## method: dumpwallet

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"dumpwallet\",\"filename\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/dumpwallet?filename={string}
```

field | value type | Description
--------- | ------- | -----------
filename | string | no help info

## method: backupwallet

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"backupwallet\",\"filename\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/backupwallet?filename={string}
```

field | value type | Description
--------- | ------- | -----------
filename | string | no help info

## method: importwallet

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"importwallet\",\"filename\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/importwallet?filename={string}
```

field | value type | Description
--------- | ------- | -----------
filename | string | no help info

## method: getnewaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getnewaddress\",\"account\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getnewaddress?account={string}
```

field | value type | Description
--------- | ------- | -----------
account | string | no help info

## method: importprivkey

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"importprivkey\",\"wif\":\"{string}\",\"account\":\"{string}\",\"rescan\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/importprivkey?wif={string}&account={string}&rescan={int}
```

field | value type | Description
--------- | ------- | -----------
wif | string | no help info
account | string | no help info
rescan | int | no help info

## method: importaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"importaddress\",\"address\":\"{string}\",\"account\":\"{string}\",\"rescan\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/importaddress?address={string}&account={string}&rescan={int}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info
account | string | no help info
rescan | int | no help info

## method: dumpprivkey

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"dumpprivkey\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/dumpprivkey?address={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info

## method: listtransactions

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listtransactions\",\"account\":\"{string}\",\"count\":\"{int}\",\"skip\":\"{int}\",\"includewatchonly\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listtransactions?account={string}&count={int}&skip={int}&includewatchonly={int}
```

field | value type | Description
--------- | ------- | -----------
account | string | no help info
count | int | no help info
skip | int | no help info
includewatchonly | int | no help info

## method: listreceivedbyaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listreceivedbyaddress\",\"minconf\":\"{int}\",\"includeempty\":\"{int}\",\"flag\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listreceivedbyaddress?minconf={int}&includeempty={int}&flag={int}
```

field | value type | Description
--------- | ------- | -----------
minconf | int | no help info
includeempty | int | no help info
flag | int | no help info

## method: listreceivedbyaccount

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listreceivedbyaccount\",\"confirmations\":\"{int}\",\"includeempty\":\"{int}\",\"watchonly\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listreceivedbyaccount?confirmations={int}&includeempty={int}&watchonly={int}
```

field | value type | Description
--------- | ------- | -----------
confirmations | int | no help info
includeempty | int | no help info
watchonly | int | no help info

## method: listaccounts

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listaccounts\",\"minconf\":\"{int}\",\"includewatchonly\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listaccounts?minconf={int}&includewatchonly={int}
```

field | value type | Description
--------- | ------- | -----------
minconf | int | no help info
includewatchonly | int | no help info

## method: listaddressgroupings

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listaddressgroupings\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listaddressgroupings
```

field | value type | Description
--------- | ------- | -----------

## method: getreceivedbyaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getreceivedbyaddress\",\"address\":\"{string}\",\"minconf\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getreceivedbyaddress?address={string}&minconf={int}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info
minconf | int | no help info

## method: getreceivedbyaccount

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getreceivedbyaccount\",\"account\":\"{string}\",\"includeempty\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getreceivedbyaccount?account={string}&includeempty={int}
```

field | value type | Description
--------- | ------- | -----------
account | string | no help info
includeempty | int | no help info

## method: getbalance

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getbalance\",\"account\":\"{string}\",\"confirmations\":\"{int}\",\"includeempty\":\"{int}\",\"lastheight\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getbalance?account={string}&confirmations={int}&includeempty={int}&lastheight={int}
```

field | value type | Description
--------- | ------- | -----------
account | string | no help info
confirmations | int | no help info
includeempty | int | no help info
lastheight | int | no help info

## method: getaddressesbyaccount

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getaddressesbyaccount\",\"account\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getaddressesbyaccount?account={string}
```

field | value type | Description
--------- | ------- | -----------
account | string | no help info

## method: getaccount

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getaccount\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getaccount?address={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info

## method: getaccountaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getaccountaddress\",\"account\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getaccountaddress?account={string}
```

field | value type | Description
--------- | ------- | -----------
account | string | no help info

## method: setaccount

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"setaccount\",\"address\":\"{string}\",\"account\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/setaccount?address={string}&account={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info
account | string | no help info

## method: createmultisig

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"createmultisig\",\"M\":\"{int}\",\"pubkeys\":\"{array}\",\"ignore\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/createmultisig?M={int}&pubkeys={array}&ignore={string}
```

field | value type | Description
--------- | ------- | -----------
M | int | no help info
pubkeys | array | no help info
ignore | string | no help info

## method: addmultisigaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"addmultisigaddress\",\"M\":\"{int}\",\"pubkeys\":\"{array}\",\"account\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/addmultisigaddress?M={int}&pubkeys={array}&account={string}
```

field | value type | Description
--------- | ------- | -----------
M | int | no help info
pubkeys | array | no help info
account | string | no help info

## method: settxfee

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"settxfee\",\"amount\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/settxfee?amount={float}
```

field | value type | Description
--------- | ------- | -----------
amount | float | no help info

## method: checkwallet

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"checkwallet\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/checkwallet
```

field | value type | Description
--------- | ------- | -----------

## method: repairwallet

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"repairwallet\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/repairwallet
```

field | value type | Description
--------- | ------- | -----------

## method: signrawtransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"signrawtransaction\",\"rawtx\":\"{string}\",\"vins\":\"{array}\",\"privkeys\":\"{object}\",\"sighash\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/signrawtransaction?rawtx={string}&vins={array}&privkeys={object}&sighash={string}
```

field | value type | Description
--------- | ------- | -----------
rawtx | string | no help info
vins | array | no help info
privkeys | object | no help info
sighash | string | no help info

## method: signmessage

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"signmessage\",\"address\":\"{string}\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/signmessage?address={string}&message={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info
message | string | no help info

## method: verifymessage

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"verifymessage\",\"address\":\"{string}\",\"sig\":\"{string}\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/verifymessage?address={string}&sig={string}&message={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info
sig | string | no help info
message | string | no help info

## method: sendrawtransaction

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"sendrawtransaction\",\"rawtx\":\"{string}\",\"allowhighfees\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/sendrawtransaction?rawtx={string}&allowhighfees={int}
```

field | value type | Description
--------- | ------- | -----------
rawtx | string | no help info
allowhighfees | int | no help info

## method: sendfrom

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"sendfrom\",\"fromaccount\":\"{string}\",\"toaddress\":\"{string}\",\"amount\":\"{float}\",\"minconf\":\"{int}\",\"comment\":\"{string}\",\"comment2\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/sendfrom?fromaccount={string}&toaddress={string}&amount={float}&minconf={int}&comment={string}&comment2={string}
```

field | value type | Description
--------- | ------- | -----------
fromaccount | string | no help info
toaddress | string | no help info
amount | float | no help info
minconf | int | no help info
comment | string | no help info
comment2 | string | no help info

## method: sendmany

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"sendmany\",\"fromaccount\":\"{string}\",\"payments\":\"{array}\",\"minconf\":\"{int}\",\"comment\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/sendmany?fromaccount={string}&payments={array}&minconf={int}&comment={string}
```

field | value type | Description
--------- | ------- | -----------
fromaccount | string | no help info
payments | array | no help info
minconf | int | no help info
comment | string | no help info

## method: sendtoaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"sendtoaddress\",\"address\":\"{string}\",\"amount\":\"{float}\",\"comment\":\"{string}\",\"comment2\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/sendtoaddress?address={string}&amount={float}&comment={string}&comment2={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info
amount | float | no help info
comment | string | no help info
comment2 | string | no help info

## method: lockunspent

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"lockunspent\",\"flag\":\"{int}\",\"array\":\"{array}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/lockunspent?flag={int}&array={array}
```

field | value type | Description
--------- | ------- | -----------
flag | int | no help info
array | array | no help info

## method: listlockunspent

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listlockunspent\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listlockunspent
```

field | value type | Description
--------- | ------- | -----------

## method: submitblock

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"submitblock\",\"rawbytes\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/submitblock?rawbytes={string}
```

field | value type | Description
--------- | ------- | -----------
rawbytes | string | no help info

## method: listsinceblock

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"listsinceblock\",\"blockhash\":\"{hash}\",\"target\":\"{int}\",\"flag\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/listsinceblock?blockhash={hash}&target={int}&flag={int}
```

field | value type | Description
--------- | ------- | -----------
blockhash | hash | no help info
target | int | no help info
flag | int | no help info

## method: gettxoutsetinfo

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"gettxoutsetinfo\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/gettxoutsetinfo
```

field | value type | Description
--------- | ------- | -----------

## method: getrawchangeaddress

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"getrawchangeaddress\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/getrawchangeaddress
```

field | value type | Description
--------- | ------- | -----------

## method: move

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"move\",\"fromaccount\":\"{string}\",\"toaccount\":\"{string}\",\"amount\":\"{float}\",\"minconf\":\"{int}\",\"comment\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/bitcoinrpc/move?fromaccount={string}&toaccount={string}&amount={float}&minconf={int}&comment={string}
```

field | value type | Description
--------- | ------- | -----------
fromaccount | string | no help info
toaccount | string | no help info
amount | float | no help info
minconf | int | no help info
comment | string | no help info

iguana API
===
need to create help/iguana.md file

## method: splitfunds

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"splitfunds\",\"satoshis\":\"{int}\",\"duplicates\":\"{int}\",\"sendflag\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/splitfunds?satoshis={int}&duplicates={int}&sendflag={int}
```

field | value type | Description
--------- | ------- | -----------
satoshis | int | no help info
duplicates | int | no help info
sendflag | int | no help info

## method: makekeypair

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"makekeypair\"}"
```

```url
http://127.0.0.1:7778/api/iguana/makekeypair
```

field | value type | Description
--------- | ------- | -----------

## method: rates

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"rates\",\"unused\":\"{int}\",\"quotes\":\"{array}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/rates?unused={int}&quotes={array}
```

field | value type | Description
--------- | ------- | -----------
unused | int | no help info
quotes | array | no help info

## method: rate

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"rate\",\"base\":\"{string}\",\"rel\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/rate?base={string}&rel={string}
```

field | value type | Description
--------- | ------- | -----------
base | string | no help info
rel | string | no help info

## method: prices

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"prices\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"period\":\"{int}\",\"start\":\"{int}\",\"end\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/prices?exchange={string}&base={string}&rel={string}&period={int}&start={int}&end={int}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info
period | int | no help info
start | int | no help info
end | int | no help info

## method: snapshot

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"snapshot\",\"symbol\":\"{string}\",\"height\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/snapshot?symbol={string}&height={int}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
height | int | no help info

## method: dividends

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"dividends\",\"height\":\"{int}\",\"vals\":\"{array}\",\"symbol\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/dividends?height={int}&vals={array}&symbol={string}
```

field | value type | Description
--------- | ------- | -----------
height | int | no help info
vals | array | no help info
symbol | string | no help info

## method: passthru

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"passthru\",\"asset\":\"{string}\",\"function\":\"{string}\",\"hex\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/passthru?asset={string}&function={string}&hex={string}
```

field | value type | Description
--------- | ------- | -----------
asset | string | no help info
function | string | no help info
hex | string | no help info

## method: initfastfind

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"initfastfind\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/initfastfind?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: dpow

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"dpow\",\"symbol\":\"{string}\",\"pubkey\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/dpow?symbol={string}&pubkey={string}
```

field | value type | Description
--------- | ------- | -----------
symbol | string | no help info
pubkey | string | no help info

## method: peers

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"peers\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/peers?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: maxpeers

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"maxpeers\",\"activecoin\":\"{string}\",\"max\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/maxpeers?activecoin={string}&max={int}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
max | int | no help info

## method: getconnectioncount

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"getconnectioncount\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/getconnectioncount?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: addcoin

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"addcoin\",\"newcoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/addcoin?newcoin={string}
```

field | value type | Description
--------- | ------- | -----------
newcoin | string | no help info

## method: validate

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"validate\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/validate?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: removecoin

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"removecoin\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/removecoin?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: startcoin

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"startcoin\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/startcoin?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: pausecoin

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"pausecoin\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/pausecoin?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: stopcoin

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"stopcoin\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/stopcoin?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: addnode

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"addnode\",\"activecoin\":\"{string}\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/addnode?activecoin={string}&ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
ipaddr | string | no help info

## method: addnotary

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"addnotary\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/addnotary?ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
ipaddr | string | no help info

## method: persistent

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"persistent\",\"activecoin\":\"{string}\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/persistent?activecoin={string}&ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
ipaddr | string | no help info

## method: removenode

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"removenode\",\"activecoin\":\"{string}\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/removenode?activecoin={string}&ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
ipaddr | string | no help info

## method: oneshot

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"oneshot\",\"activecoin\":\"{string}\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/oneshot?activecoin={string}&ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
ipaddr | string | no help info

## method: nodestatus

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"nodestatus\",\"activecoin\":\"{string}\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/nodestatus?activecoin={string}&ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
ipaddr | string | no help info

## method: balance

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"balance\",\"activecoin\":\"{string}\",\"address\":\"{string}\",\"heightd\":\"{float}\",\"minconfd\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/balance?activecoin={string}&address={string}&heightd={float}&minconfd={float}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
address | string | no help info
heightd | float | no help info
minconfd | float | no help info

## method: spendmsig

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"spendmsig\",\"activecoin\":\"{string}\",\"vintxid\":\"{hash}\",\"vinvout\":\"{int}\",\"destaddress\":\"{string}\",\"destamount\":\"{float}\",\"destaddress2\":\"{string}\",\"destamount2\":\"{float}\",\"M\":\"{int}\",\"N\":\"{int}\",\"pubA\":\"{string}\",\"wifA\":\"{string}\",\"pubB\":\"{string}\",\"wifB\":\"{string}\",\"pubC\":\"{string}\",\"wifC\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/spendmsig?activecoin={string}&vintxid={hash}&vinvout={int}&destaddress={string}&destamount={float}&destaddress2={string}&destamount2={float}&M={int}&N={int}&pubA={string}&wifA={string}&pubB={string}&wifB={string}&pubC={string}&wifC={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
vintxid | hash | no help info
vinvout | int | no help info
destaddress | string | no help info
destamount | float | no help info
destaddress2 | string | no help info
destamount2 | float | no help info
M | int | no help info
N | int | no help info
pubA | string | no help info
wifA | string | no help info
pubB | string | no help info
wifB | string | no help info
pubC | string | no help info
wifC | string | no help info

## method: bundleaddresses

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"bundleaddresses\",\"activecoin\":\"{string}\",\"height\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/bundleaddresses?activecoin={string}&height={int}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
height | int | no help info

## method: bundlehashes

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"bundlehashes\",\"activecoin\":\"{string}\",\"height\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/bundlehashes?activecoin={string}&height={int}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
height | int | no help info

## method: PoSweights

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"PoSweights\",\"activecoin\":\"{string}\",\"height\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/PoSweights?activecoin={string}&height={int}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info
height | int | no help info

## method: stakers

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana\",\"method\":\"stakers\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/iguana/stakers?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

jumblr API
===
need to create help/jumblr.md file

## method: setpassphrase

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"jumblr\",\"method\":\"setpassphrase\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/jumblr/setpassphrase?passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
passphrase | string | no help info

InstantDEX API
===
need to create help/InstantDEX.md file

## method: allcoins

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"allcoins\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/allcoins
```

field | value type | Description
--------- | ------- | -----------

## method: available

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"available\",\"source\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/available?source={string}
```

field | value type | Description
--------- | ------- | -----------
source | string | no help info

## method: request

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"request\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"hexstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/request?hash={hash}&vals={array}&hexstr={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
hexstr | str | no help info

## method: incoming

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"incoming\",\"requestid\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/incoming?requestid={int}
```

field | value type | Description
--------- | ------- | -----------
requestid | int | no help info

## method: automatched

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"automatched\",\"requestid\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/automatched?requestid={int}
```

field | value type | Description
--------- | ------- | -----------
requestid | int | no help info

## method: accept

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"accept\",\"requestid\":\"{int}\",\"quoteid\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/accept?requestid={int}&quoteid={int}
```

field | value type | Description
--------- | ------- | -----------
requestid | int | no help info
quoteid | int | no help info

## method: buy

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"buy\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"price\":\"{float}\",\"volume\":\"{float}\",\"dotrade\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/buy?exchange={string}&base={string}&rel={string}&price={float}&volume={float}&dotrade={float}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info
price | float | no help info
volume | float | no help info
dotrade | float | no help info

## method: sell

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"sell\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"price\":\"{float}\",\"volume\":\"{float}\",\"dotrade\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/sell?exchange={string}&base={string}&rel={string}&price={float}&volume={float}&dotrade={float}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info
price | float | no help info
volume | float | no help info
dotrade | float | no help info

## method: withdraw

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"withdraw\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"destaddr\":\"{string}\",\"amount\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/withdraw?exchange={string}&base={string}&destaddr={string}&amount={float}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
destaddr | string | no help info
amount | float | no help info

## method: apikeypair

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"apikeypair\",\"exchange\":\"{string}\",\"apikey\":\"{string}\",\"apisecret\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/apikeypair?exchange={string}&apikey={string}&apisecret={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
apikey | string | no help info
apisecret | string | no help info

## method: setuserid

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"setuserid\",\"exchange\":\"{string}\",\"userid\":\"{string}\",\"tradepassword\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/setuserid?exchange={string}&userid={string}&tradepassword={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
userid | string | no help info
tradepassword | string | no help info

## method: balance

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"balance\",\"exchange\":\"{string}\",\"base\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/balance?exchange={string}&base={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info

## method: orderstatus

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"orderstatus\",\"exchange\":\"{string}\",\"orderid\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/orderstatus?exchange={string}&orderid={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
orderid | string | no help info

## method: cancelorder

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"cancelorder\",\"exchange\":\"{string}\",\"orderid\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/cancelorder?exchange={string}&orderid={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
orderid | string | no help info

## method: openorders

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"openorders\",\"exchange\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/openorders?exchange={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info

## method: tradehistory

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"tradehistory\",\"exchange\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/tradehistory?exchange={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info

## method: orderbook

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"depth\":\"{int}\",\"allfields\":\"{int}\",\"ignore\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/orderbook?exchange={string}&base={string}&rel={string}&depth={int}&allfields={int}&ignore={int}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info
depth | int | no help info
allfields | int | no help info
ignore | int | no help info

## method: pollgap

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"pollgap\",\"exchange\":\"{string}\",\"pollgap\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/pollgap?exchange={string}&pollgap={int}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
pollgap | int | no help info

## method: allexchanges

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"allexchanges\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/allexchanges
```

field | value type | Description
--------- | ------- | -----------

## method: allpairs

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"allpairs\",\"exchange\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/allpairs?exchange={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info

## method: supports

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"supports\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/InstantDEX/supports?exchange={string}&base={string}&rel={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info

tradebot API
===
need to create help/tradebot.md file

## method: liquidity

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"liquidity\",\"hash\":\"{hash}\",\"vals\":\"{array}\",\"targetcoin\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/liquidity?hash={hash}&vals={array}&targetcoin={str}
```

field | value type | Description
--------- | ------- | -----------
hash | hash | no help info
vals | array | no help info
targetcoin | str | no help info

## method: amlp

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"amlp\",\"blocktrail\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/amlp?blocktrail={string}
```

field | value type | Description
--------- | ------- | -----------
blocktrail | string | no help info

## method: notlp

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"notlp\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/notlp
```

field | value type | Description
--------- | ------- | -----------

## method: gensvm

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"gensvm\",\"base\":\"{string}\",\"rel\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/gensvm?base={string}&rel={string}
```

field | value type | Description
--------- | ------- | -----------
base | string | no help info
rel | string | no help info

## method: openliquidity

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"openliquidity\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/openliquidity
```

field | value type | Description
--------- | ------- | -----------

## method: aveprice

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"aveprice\",\"comment\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"basevolume\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/aveprice?comment={string}&base={string}&rel={string}&basevolume={float}
```

field | value type | Description
--------- | ------- | -----------
comment | string | no help info
base | string | no help info
rel | string | no help info
basevolume | float | no help info

## method: monitor

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"monitor\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"commission\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/monitor?exchange={string}&base={string}&rel={string}&commission={float}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info
commission | float | no help info

## method: monitorall

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"monitorall\",\"exchange\":\"{string}\",\"commission\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/monitorall?exchange={string}&commission={float}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
commission | float | no help info

## method: unmonitor

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"unmonitor\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/unmonitor?exchange={string}&base={string}&rel={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info

## method: accumulate

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"accumulate\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"price\":\"{float}\",\"volume\":\"{float}\",\"duration\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/accumulate?exchange={string}&base={string}&rel={string}&price={float}&volume={float}&duration={float}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info
price | float | no help info
volume | float | no help info
duration | float | no help info

## method: divest

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"divest\",\"exchange\":\"{string}\",\"base\":\"{string}\",\"rel\":\"{string}\",\"price\":\"{float}\",\"volume\":\"{float}\",\"duration\":\"{float}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/divest?exchange={string}&base={string}&rel={string}&price={float}&volume={float}&duration={float}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
base | string | no help info
rel | string | no help info
price | float | no help info
volume | float | no help info
duration | float | no help info

## method: activebots

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"activebots\",\"exchange\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/activebots?exchange={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info

## method: status

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"status\",\"exchange\":\"{string}\",\"botid\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/status?exchange={string}&botid={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
botid | string | no help info

## method: pause

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"pause\",\"exchange\":\"{string}\",\"botid\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/pause?exchange={string}&botid={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
botid | string | no help info

## method: stop

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"stop\",\"exchange\":\"{string}\",\"botid\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/stop?exchange={string}&botid={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
botid | string | no help info

## method: resume

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"resume\",\"exchange\":\"{string}\",\"botid\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/resume?exchange={string}&botid={string}
```

field | value type | Description
--------- | ------- | -----------
exchange | string | no help info
botid | string | no help info

## method: allbalances

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"allbalances\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/allbalances
```

field | value type | Description
--------- | ------- | -----------

## method: anchor

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"anchor\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/anchor
```

field | value type | Description
--------- | ------- | -----------

## method: portfolio

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"portfolio\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/portfolio
```

field | value type | Description
--------- | ------- | -----------

## method: goals

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"goals\",\"currencies\":\"{array}\",\"vals\":\"{object}\",\"targettime\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/tradebot/goals?currencies={array}&vals={object}&targettime={int}
```

field | value type | Description
--------- | ------- | -----------
currencies | array | no help info
vals | object | no help info
targettime | int | no help info

SuperNET API
===
need to create help/SuperNET.md file

## method: help

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"help\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/help
```

field | value type | Description
--------- | ------- | -----------

## method: utime2utc

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"utime2utc\",\"utime\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/utime2utc?utime={string}
```

field | value type | Description
--------- | ------- | -----------
utime | string | no help info

## method: utc2utime

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"utc2utime\",\"utc\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/utc2utime?utc={int}
```

field | value type | Description
--------- | ------- | -----------
utc | int | no help info

## method: getpeers

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"getpeers\",\"activecoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/getpeers?activecoin={string}
```

field | value type | Description
--------- | ------- | -----------
activecoin | string | no help info

## method: mypeers

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"mypeers\",\"supernet\":\"{array}\",\"rawpeers\":\"{array}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/mypeers?supernet={array}&rawpeers={array}
```

field | value type | Description
--------- | ------- | -----------
supernet | array | no help info
rawpeers | array | no help info

## method: stop

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"stop\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/stop
```

field | value type | Description
--------- | ------- | -----------

## method: saveconf

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"saveconf\",\"wallethash\":\"{hash}\",\"confjsonstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/saveconf?wallethash={hash}&confjsonstr={str}
```

field | value type | Description
--------- | ------- | -----------
wallethash | hash | no help info
confjsonstr | str | no help info

## method: layer

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"layer\",\"mypriv\":\"{hash}\",\"otherpubs\":\"{array}\",\"str\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/layer?mypriv={hash}&otherpubs={array}&str={str}
```

field | value type | Description
--------- | ------- | -----------
mypriv | hash | no help info
otherpubs | array | no help info
str | str | no help info

## method: bitcoinrpc

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"bitcoinrpc\",\"setcoin\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/bitcoinrpc?setcoin={string}
```

field | value type | Description
--------- | ------- | -----------
setcoin | string | no help info

## method: myipaddr

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"myipaddr\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/myipaddr?ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
ipaddr | string | no help info

## method: setmyipaddr

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"setmyipaddr\",\"ipaddr\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/setmyipaddr?ipaddr={string}
```

field | value type | Description
--------- | ------- | -----------
ipaddr | string | no help info

## method: login

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"login\",\"handle\":\"{string}\",\"password\":\"{string}\",\"permanentfile\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/login?handle={string}&password={string}&permanentfile={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
handle | string | no help info
password | string | no help info
permanentfile | string | no help info
passphrase | string | no help info

## method: logout

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"logout\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/logout
```

field | value type | Description
--------- | ------- | -----------

## method: activehandle

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"activehandle\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/activehandle
```

field | value type | Description
--------- | ------- | -----------

## method: encryptjson

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"encryptjson\",\"password\":\"{string}\",\"permanentfile\":\"{string}\",\"payload\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/encryptjson?password={string}&permanentfile={string}&payload={string}
```

field | value type | Description
--------- | ------- | -----------
password | string | no help info
permanentfile | string | no help info
payload | string | no help info

## method: decryptjson

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"decryptjson\",\"password\":\"{string}\",\"permanentfile\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/decryptjson?password={string}&permanentfile={string}
```

field | value type | Description
--------- | ------- | -----------
password | string | no help info
permanentfile | string | no help info

## method: html

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"html\",\"agentform\":\"{string}\",\"htmlfile\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/html?agentform={string}&htmlfile={string}
```

field | value type | Description
--------- | ------- | -----------
agentform | string | no help info
htmlfile | string | no help info

## method: rosetta

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"rosetta\",\"passphrase\":\"{string}\",\"pin\":\"{string}\",\"showprivkey\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/rosetta?passphrase={string}&pin={string}&showprivkey={string}
```

field | value type | Description
--------- | ------- | -----------
passphrase | string | no help info
pin | string | no help info
showprivkey | string | no help info

## method: keypair

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"keypair\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/keypair
```

field | value type | Description
--------- | ------- | -----------

## method: priv2pub

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"priv2pub\",\"privkey\":\"{hash}\",\"addrtype\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/priv2pub?privkey={hash}&addrtype={int}
```

field | value type | Description
--------- | ------- | -----------
privkey | hash | no help info
addrtype | int | no help info

## method: wif2priv

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"wif2priv\",\"wif\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/wif2priv?wif={string}
```

field | value type | Description
--------- | ------- | -----------
wif | string | no help info

## method: priv2wif

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"priv2wif\",\"priv\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/priv2wif?priv={string}
```

field | value type | Description
--------- | ------- | -----------
priv | string | no help info

## method: addr2rmd160

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"addr2rmd160\",\"address\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/addr2rmd160?address={string}
```

field | value type | Description
--------- | ------- | -----------
address | string | no help info

## method: rmd160conv

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"rmd160conv\",\"rmd160\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/rmd160conv?rmd160={string}
```

field | value type | Description
--------- | ------- | -----------
rmd160 | string | no help info

## method: cipher

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"cipher\",\"privkey\":\"{hash}\",\"destpubkey\":\"{hash}\",\"message\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/cipher?privkey={hash}&destpubkey={hash}&message={str}
```

field | value type | Description
--------- | ------- | -----------
privkey | hash | no help info
destpubkey | hash | no help info
message | str | no help info

## method: decipher

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"decipher\",\"privkey\":\"{hash}\",\"srcpubkey\":\"{hash}\",\"cipherstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/decipher?privkey={hash}&srcpubkey={hash}&cipherstr={str}
```

field | value type | Description
--------- | ------- | -----------
privkey | hash | no help info
srcpubkey | hash | no help info
cipherstr | str | no help info

## method: broadcastcipher

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"broadcastcipher\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/broadcastcipher?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: broadcastdecipher

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"broadcastdecipher\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/broadcastdecipher?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: multicastcipher

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"multicastcipher\",\"pubkey\":\"{hash}\",\"message\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/multicastcipher?pubkey={hash}&message={str}
```

field | value type | Description
--------- | ------- | -----------
pubkey | hash | no help info
message | str | no help info

## method: multicastdecipher

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"SuperNET\",\"method\":\"multicastdecipher\",\"privkey\":\"{hash}\",\"cipherstr\":\"{str}\"}"
```

```url
http://127.0.0.1:7778/api/SuperNET/multicastdecipher?privkey={hash}&cipherstr={str}
```

field | value type | Description
--------- | ------- | -----------
privkey | hash | no help info
cipherstr | str | no help info

mouse API
===
need to create help/mouse.md file

## method: image

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"mouse\",\"method\":\"image\",\"name\":\"{string}\",\"x\":\"{int}\",\"y\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/mouse/image?name={string}&x={int}&y={int}
```

field | value type | Description
--------- | ------- | -----------
name | string | no help info
x | int | no help info
y | int | no help info

## method: change

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"mouse\",\"method\":\"change\",\"name\":\"{string}\",\"x\":\"{int}\",\"y\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/mouse/change?name={string}&x={int}&y={int}
```

field | value type | Description
--------- | ------- | -----------
name | string | no help info
x | int | no help info
y | int | no help info

## method: click

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"mouse\",\"method\":\"click\",\"name\":\"{string}\",\"x\":\"{int}\",\"y\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/mouse/click?name={string}&x={int}&y={int}
```

field | value type | Description
--------- | ------- | -----------
name | string | no help info
x | int | no help info
y | int | no help info

## method: close

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"mouse\",\"method\":\"close\",\"name\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/mouse/close?name={string}
```

field | value type | Description
--------- | ------- | -----------
name | string | no help info

## method: leave

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"mouse\",\"method\":\"leave\",\"name\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/mouse/leave?name={string}
```

field | value type | Description
--------- | ------- | -----------
name | string | no help info

keyboard API
===
need to create help/keyboard.md file

## method: key

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"keyboard\",\"method\":\"key\",\"name\":\"{string}\",\"c\":\"{int}\"}"
```

```url
http://127.0.0.1:7778/api/keyboard/key?name={string}&c={int}
```

field | value type | Description
--------- | ------- | -----------
name | string | no help info
c | int | no help info

hash API
===
need to create help/hash.md file

## method: hex

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"hex\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/hex?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: unhex

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"unhex\",\"hexmsg\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/unhex?hexmsg={string}
```

field | value type | Description
--------- | ------- | -----------
hexmsg | string | no help info

## method: curve25519_pair

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"curve25519_pair\",\"element\":\"{hash}\",\"scalar\":\"{hash}\"}"
```

```url
http://127.0.0.1:7778/api/hash/curve25519_pair?element={hash}&scalar={hash}
```

field | value type | Description
--------- | ------- | -----------
element | hash | no help info
scalar | hash | no help info

## method: NXT

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"NXT\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/NXT?passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
passphrase | string | no help info

## method: curve25519

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"curve25519\",\"pubkey\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/curve25519?pubkey={string}
```

field | value type | Description
--------- | ------- | -----------
pubkey | string | no help info

## method: crc32

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"crc32\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/crc32?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: base64_encode

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"base64_encode\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/base64_encode?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: base64_decode

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"base64_decode\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/base64_decode?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: rmd160_sha256

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"rmd160_sha256\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/rmd160_sha256?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: sha256_sha256

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"sha256_sha256\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/sha256_sha256?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: sha224

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"sha224\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/sha224?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: sha256

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"sha256\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/sha256?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: sha384

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"sha384\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/sha384?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: sha512

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"sha512\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/sha512?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: rmd128

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"rmd128\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/rmd128?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: rmd160

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"rmd160\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/rmd160?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: rmd256

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"rmd256\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/rmd256?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: rmd320

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"rmd320\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/rmd320?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: sha1

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"sha1\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/sha1?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: md2

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"md2\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/md2?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: md4

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"md4\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/md4?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: md5

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"md5\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/md5?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: tiger192_3

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"tiger192_3\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/tiger192_3?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

## method: whirlpool

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hash\",\"method\":\"whirlpool\",\"message\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hash/whirlpool?message={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info

hmac API
===
need to create help/hmac.md file

## method: sha224

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"sha224\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/sha224?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: sha256

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"sha256\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/sha256?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: sha384

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"sha384\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/sha384?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: sha512

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"sha512\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/sha512?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: rmd128

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"rmd128\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/rmd128?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: rmd160

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"rmd160\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/rmd160?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: rmd256

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"rmd256\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/rmd256?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: rmd320

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"rmd320\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/rmd320?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: sha1

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"sha1\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/sha1?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: md2

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"md2\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/md2?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: md4

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"md4\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/md4?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: md5

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"md5\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/md5?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: tiger192_3

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"tiger192_3\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/tiger192_3?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

## method: whirlpool

put helpful info here


```shell
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"hmac\",\"method\":\"whirlpool\",\"message\":\"{string}\",\"passphrase\":\"{string}\"}"
```

```url
http://127.0.0.1:7778/api/hmac/whirlpool?message={string}&passphrase={string}
```

field | value type | Description
--------- | ------- | -----------
message | string | no help info
passphrase | string | no help info

end of help

