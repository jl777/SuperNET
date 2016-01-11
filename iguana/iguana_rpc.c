/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "iguana777.h"
#include "SuperNET.h"

struct iguana_txid *iguana_blocktx(struct iguana_info *coin,struct iguana_txid *tx,struct iguana_block *block,int32_t i)
{
    struct iguana_bundle *bp; uint32_t txidind;
    if ( i >= 0 && i < block->RO.txn_count )
    {
        if ( block->height >= 0 ) //
        {
            if ( (bp= coin->bundles[block->hdrsi]) != 0 )
            {
                if ( (txidind= block->RO.firsttxidind) > 0 )//bp->firsttxidinds[block->bundlei]) > 0 )
                {
                    if ( iguana_bundletx(coin,bp,block->bundlei,tx,txidind+i) == tx )
                        return(tx);
                    printf("error getting txidind.%d + i.%d from hdrsi.%d\n",txidind,i,block->hdrsi);
                    return(0);
                } else printf("iguana_blocktx null txidind\n");
            } else printf("iguana_blocktx no bp\n");
        }
    } else printf("i.%d vs txn_count.%d\n",i,block->RO.txn_count);
    return(0);
}

cJSON *iguana_blockjson(struct iguana_info *coin,struct iguana_block *block,int32_t txidsflag)
{
    char str[65]; int32_t i; struct iguana_txid *tx,T; cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"blockhash",bits256_str(str,block->RO.hash2));
    jaddnum(json,"height",block->height);
    jaddnum(json,"ipbits",block->fpipbits);
    jaddstr(json,"merkle_root",bits256_str(str,block->RO.merkle_root));
    jaddstr(json,"prev_block",bits256_str(str,block->RO.prev_block));
    jaddnum(json,"timestamp",block->RO.timestamp);
    jaddnum(json,"nonce",block->RO.nonce);
    jaddnum(json,"nBits",block->RO.bits);
    jaddnum(json,"version",block->RO.version);
    jaddnum(json,"numvouts",block->RO.numvouts);
    jaddnum(json,"numvins",block->RO.numvins);
    jaddnum(json,"recvlen",block->RO.recvlen);
    jaddnum(json,"hdrsi",block->hdrsi);
    jaddnum(json,"PoW",block->PoW);
    jaddnum(json,"bundlei",block->bundlei);
    jaddnum(json,"mainchain",block->mainchain);
    jaddnum(json,"valid",block->valid);
    jaddnum(json,"txn_count",block->RO.txn_count);
    if ( txidsflag != 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<block->RO.txn_count; i++)
        {
            if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                jaddistr(array,bits256_str(str,tx->txid));
        }
        jadd(json,"txids",array);
        //printf("add txids[%d]\n",block->txn_count);
    }
    return(json);
}

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout,char *asmstr)
{
    static bits256 zero;
    char scriptstr[8192+1],coinaddr[65]; int32_t i,M,N; uint8_t rmd160[20],msigs160[16][20],addrtype;
    cJSON *addrs,*json = cJSON_CreateObject();
    jaddnum(json,"value",dstr(vout->value));
    if ( asmstr[0] != 0 )
        jaddstr(json,"asm",asmstr);
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        if ( iguana_calcrmd160(coin,rmd160,msigs160,&M,&N,vout->pk_script,vout->pk_scriptlen,zero) > 0 )
            addrtype = coin->chain->p2shval;
        else addrtype = coin->chain->pubval;
        btc_convrmd160(coinaddr,addrtype,rmd160);
        jaddstr(json,"address",coinaddr);
        init_hexbytes_noT(scriptstr,vout->pk_script,vout->pk_scriptlen);
        jaddstr(json,"payscript",scriptstr);
        if ( N != 0 )
        {
            jaddnum(json,"M",M);
            jaddnum(json,"N",N);
            addrs = cJSON_CreateArray();
            for (i=0; i<N; i++)
            {
                btc_convrmd160(coinaddr,coin->chain->pubval,msigs160[i]);
                jaddistr(addrs,coinaddr);
            }
            jadd(json,"addrs",addrs);
        }
    }
    return(json);
}

cJSON *iguana_vinjson(struct iguana_info *coin,struct iguana_msgvin *vin)
{
    char scriptstr[8192+1],str[65]; cJSON *json = cJSON_CreateObject();
    jaddstr(json,"prev_hash",bits256_str(str,vin->prev_hash));
    jaddnum(json,"prev_vout",vin->prev_vout);
    jaddnum(json,"sequence",vin->sequence);
    if ( vin->script != 0 && vin->scriptlen*2+1 < sizeof(scriptstr) )
    {
        init_hexbytes_noT(scriptstr,vin->script,vin->scriptlen);
        jaddstr(json,"sigscript",scriptstr);
    }
    return(json);
}

//struct iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin,locktime,version,timestamp; uint16_t numvouts,numvins; } __attribute__((packed));

//struct iguana_msgvin { bits256 prev_hash; uint8_t *script; uint32_t prev_vout,scriptlen,sequence; } __attribute__((packed));

//struct iguana_spend { uint32_t spendtxidind; int16_t prevout; uint16_t tbd:14,external:1,diffsequence:1; } __attribute__((packed));

void iguana_vinset(struct iguana_info *coin,int32_t height,struct iguana_msgvin *vin,struct iguana_txid *tx,int32_t i)
{
    struct iguana_spend *s,*S; uint32_t spendind; struct iguana_bundle *bp;
    struct iguana_ramchaindata *rdata; struct iguana_txid *T; bits256 *X;
    memset(vin,0,sizeof(*vin));
    if ( height >= 0 && height < coin->chain->bundlesize*coin->bundlescount && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 && (rdata= bp->ramchain.H.data) != 0 )
    {
        S = (void *)(long)((long)rdata + rdata->Soffset);
        X = (void *)(long)((long)rdata + rdata->Xoffset);
        T = (void *)(long)((long)rdata + rdata->Toffset);
        spendind = (tx->firstvin + i);
        s = &S[spendind];
        if ( s->diffsequence == 0 )
            vin->sequence = 0xffffffff;
        vin->prev_vout = s->prevout;
        iguana_ramchain_spendtxid(coin,&vin->prev_hash,T,rdata->numtxids,X,rdata->numexternaltxids,s);
    }
}

int32_t iguana_voutset(struct iguana_info *coin,uint8_t *scriptspace,char *asmstr,int32_t height,struct iguana_msgvout *vout,struct iguana_txid *tx,int32_t i)
{
    struct iguana_unspent *u,*U; uint32_t unspentind,scriptlen = 0; struct iguana_bundle *bp;
    struct iguana_ramchaindata *rdata; struct iguana_pkhash *P,*p;
    memset(vout,0,sizeof(*vout));
    if ( height >= 0 && height < coin->chain->bundlesize*coin->bundlescount && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0  && (rdata= bp->ramchain.H.data) != 0 )
    {
        U = (void *)(long)((long)rdata + rdata->Uoffset);
        P = (void *)(long)((long)rdata + rdata->Poffset);
        unspentind = (tx->firstvout + i);
        u = &U[unspentind];
        if ( u->txidind != tx->txidind || u->vout != i || u->hdrsi != height / coin->chain->bundlesize )
            printf("iguana_voutset: txidind mismatch %d vs %d || %d vs %d || (%d vs %d)\n",u->txidind,u->txidind,u->vout,i,u->hdrsi,height / coin->chain->bundlesize);
        p = &P[u->pkind];
        vout->value = u->value;
        scriptlen = iguana_scriptgen(coin,scriptspace,asmstr,bp,p,u->type);
    }
    vout->pk_scriptlen = scriptlen;
    return(scriptlen);
}

cJSON *iguana_txjson(struct iguana_info *coin,struct iguana_txid *tx,int32_t height)
{
    struct iguana_msgvin vin; struct iguana_msgvout vout; int32_t i; char asmstr[512],str[65]; uint8_t space[8192];
    cJSON *vouts,*vins,*json;
    json = cJSON_CreateObject();
    jaddstr(json,"txid",bits256_str(str,tx->txid));
    if ( height >= 0 )
        jaddnum(json,"height",height);
    jaddnum(json,"version",tx->version);
    jaddnum(json,"timestamp",tx->timestamp);
    jaddnum(json,"locktime",tx->locktime);
    vins = cJSON_CreateArray();
    vouts = cJSON_CreateArray();
    for (i=0; i<tx->numvouts; i++)
    {
        iguana_voutset(coin,space,asmstr,height,&vout,tx,i);
        jaddi(vouts,iguana_voutjson(coin,&vout,asmstr));
    }
    jadd(json,"vouts",vouts);
    for (i=0; i<tx->numvins; i++)
    {
        iguana_vinset(coin,height,&vin,tx,i);
        jaddi(vins,iguana_vinjson(coin,&vin));
    }
    jadd(json,"vins",vins);
    return(json);
}

char *ramchain_coinparser(struct iguana_info *coin,char *method,cJSON *json)
{
    char *hashstr,*txidstr,*coinaddr,*txbytes,rmd160str[41],str[65]; int32_t len,height,i,n,valid = 0;
    cJSON *addrs,*retjson,*retitem; uint8_t rmd160[20],addrtype; bits256 hash2,checktxid;
    memset(&hash2,0,sizeof(hash2)); struct iguana_txid *tx,T; struct iguana_block *block = 0;
    if ( coin == 0 && (coin= iguana_coinselect()) == 0 )
        return(clonestr("{\"error\":\"ramchain_coinparser needs coin\"}"));
    if ( (coinaddr= jstr(json,"address")) != 0 )
    {
        if ( btc_addr2univ(&addrtype,rmd160,coinaddr) == 0 )
        {
            if ( addrtype == coin->chain->pubval || addrtype == coin->chain->p2shval )
                valid = 1;
            else return(clonestr("{\"error\":\"invalid addrtype\"}"));
        } else return(clonestr("{\"error\":\"cant convert address to rmd160\"}"));
    }
    if ( strcmp(method,"block") == 0 )
    {
        height = -1;
        if ( ((hashstr= jstr(json,"blockhash")) != 0 || (hashstr= jstr(json,"hash")) != 0) && strlen(hashstr) == sizeof(bits256)*2 )
            decode_hex(hash2.bytes,sizeof(hash2),hashstr);
        else
        {
            height = juint(json,"height");
            hash2 = iguana_blockhash(coin,height);
        }
        retitem = cJSON_CreateObject();
        if ( (block= iguana_blockfind(coin,hash2)) != 0 )
        {
            if ( (height >= 0 && block->height == height) || memcmp(hash2.bytes,block->RO.hash2.bytes,sizeof(hash2)) == 0 )
            {
                char str[65],str2[65]; printf("hash2.(%s) -> %s\n",bits256_str(str,hash2),bits256_str(str2,block->RO.hash2));
                return(jprint(iguana_blockjson(coin,block,juint(json,"txids")),1));
            }
        }
        else return(clonestr("{\"error\":\"cant find block\"}"));
    }
    else if ( strcmp(method,"tx") == 0 )
    {
        if ( ((txidstr= jstr(json,"txid")) != 0 || (txidstr= jstr(json,"hash")) != 0) && strlen(txidstr) == sizeof(bits256)*2 )
        {
            retitem = cJSON_CreateObject();
            decode_hex(hash2.bytes,sizeof(hash2),txidstr);
            if ( (tx= iguana_txidfind(coin,&height,&T,hash2)) != 0 )
            {
                jadd(retitem,"tx",iguana_txjson(coin,tx,height));
                return(jprint(retitem,1));
            }
            return(clonestr("{\"error\":\"cant find txid\"}"));
        }
        else return(clonestr("{\"error\":\"invalid txid\"}"));
    }
    else if ( strcmp(method,"rawtx") == 0 )
    {
        if ( ((txidstr= jstr(json,"txid")) != 0 || (txidstr= jstr(json,"hash")) != 0) && strlen(txidstr) == sizeof(bits256)*2 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),txidstr);
            if ( (tx= iguana_txidfind(coin,&height,&T,hash2)) != 0 )
            {
                if ( (len= iguana_txbytes(coin,coin->blockspace,sizeof(coin->blockspace),&checktxid,tx,height,0,0)) > 0 )
                {
                    txbytes = mycalloc('x',1,len*2+1);
                    init_hexbytes_noT(txbytes,coin->blockspace,len*2+1);
                    retitem = cJSON_CreateObject();
                    jaddstr(retitem,"txid",bits256_str(str,hash2));
                    jaddnum(retitem,"height",height);
                    jaddstr(retitem,"rawtx",txbytes);
                    myfree(txbytes,len*2+1);
                    return(jprint(retitem,1));
                } else return(clonestr("{\"error\":\"couldnt generate txbytes\"}"));
            }
            return(clonestr("{\"error\":\"cant find txid\"}"));
        }
        else return(clonestr("{\"error\":\"invalid txid\"}"));
    }
    else if ( strcmp(method,"txs") == 0 )
    {
        if ( ((hashstr= jstr(json,"block")) != 0 || (hashstr= jstr(json,"blockhash")) != 0) && strlen(hashstr) == sizeof(bits256)*2 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),hashstr);
            if ( (block= iguana_blockfind(coin,hash2)) == 0 )
                return(clonestr("{\"error\":\"cant find blockhash\"}"));
        }
        else if ( jobj(json,"height") != 0 )
        {
            height = juint(json,"height");
            hash2 = iguana_blockhash(coin,height);
            if ( (block= iguana_blockfind(coin,hash2)) == 0 )
                return(clonestr("{\"error\":\"cant find block at height\"}"));
        }
        else if ( valid == 0 )
            return(clonestr("{\"error\":\"txs needs blockhash or height or address\"}"));
        retitem = cJSON_CreateArray();
        if ( block != 0 )
        {
            for (i=0; i<block->RO.txn_count; i++)
            {
                if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                    jaddi(retitem,iguana_txjson(coin,tx,-1));
            }
        }
        else
        {
            init_hexbytes_noT(rmd160str,rmd160,20);
            jaddnum(retitem,"addrtype",addrtype);
            jaddstr(retitem,"rmd160",rmd160str);
            jaddstr(retitem,"txlist","get list of all tx for this address");
        }
        return(jprint(retitem,1));
    }
    else if ( strcmp(method,"status") == 0 )
    {
        retitem = cJSON_CreateObject();
        jaddstr(retitem,"status","coin status");
        return(jprint(retitem,1));
    }
    else
    {
        n = 0;
        if ( valid == 0 )
        {
            if ( (addrs= jarray(&n,json,"addrs")) == 0 )
                return(clonestr("{\"error\":\"need address or addrs\"}"));
        }
        for (i=0; i<=n; i++)
        {
            retitem = cJSON_CreateObject();
            if ( i > 0 )
                retjson = cJSON_CreateArray();
            if ( i > 0 )
            {
                if ( (coinaddr= jstr(jitem(addrs,i-1),0)) == 0 )
                    return(clonestr("{\"error\":\"missing address in addrs\"}"));
                if ( btc_addr2univ(&addrtype,rmd160,coinaddr) < 0 )
                {
                    free_json(retjson);
                    return(clonestr("{\"error\":\"illegal address in addrs\"}"));
                }
                if ( addrtype != coin->chain->pubval && addrtype != coin->chain->p2shval )
                    return(clonestr("{\"error\":\"invalid addrtype in addrs\"}"));
            }
            if ( strcmp(method,"utxo") == 0 )
            {
                jaddstr(retitem,"utxo","utxo entry");
            }
            else if ( strcmp(method,"unconfirmed") == 0 )
            {
                jaddstr(retitem,"unconfirmed","unconfirmed entry");
            }
            else if ( strcmp(method,"balance") == 0 )
            {
                jaddstr(retitem,"balance","balance entry");
            }
            else if ( strcmp(method,"totalreceived") == 0 )
            {
                jaddstr(retitem,"totalreceived","totalreceived entry");
            }
            else if ( strcmp(method,"totalsent") == 0 )
            {
                jaddstr(retitem,"totalsent","totalsent entry");
            }
            else if ( strcmp(method,"validate") == 0 )
            {
                jaddstr(retitem,"validate",coinaddr);
            }
            if ( n == 0 )
                return(jprint(retitem,1));
            else jaddi(retjson,retitem);
        }
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"illegal ramchain method or missing coin\"}"));
}

char *iguana_jsoncheck(char *retstr,int32_t freeflag)
{
    cJSON *retjson; char *errstr;
    if ( retstr != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (errstr= jstr(retjson,"error")) == 0 )
            {
                free_json(retjson);
                return(retstr);
            }
            free_json(retjson);
        }
        if ( freeflag != 0 )
            free(retstr);
    }
    return(0);
}

char *ramchain_parser(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr)
{
    char *symbol,*str,*retstr; int32_t height; cJSON *argjson,*obj; struct iguana_info *coin = 0;
    /*{"agent":"ramchain","method":"block","coin":"BTCD","hash":"<sha256hash>"}
    {"agent":"ramchain","method":"block","coin":"BTCD","height":345600}
    {"agent":"ramchain","method":"tx","coin":"BTCD","txid":"<sha txid>"}
    {"agent":"ramchain","method":"rawtx","coin":"BTCD","txid":"<sha txid>"}
    {"agent":"ramchain","method":"balance","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"balance","coin":"BTCD","addrs":["<coinaddress>",...]}
    {"agent":"ramchain","method":"totalreceived","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"totalsent","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"unconfirmed","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"utxo","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"utxo","coin":"BTCD","addrs":["<coinaddress0>", "<coinadress1>",...]}
    {"agent":"ramchain","method":"txs","coin":"BTCD","block":"<blockhash>"}
    {"agent":"ramchain","method":"txs","coin":"BTCD","height":12345}
    {"agent":"ramchain","method":"txs","coin":"BTCD","address":"<coinaddress>"}
    {"agent":"ramchain","method":"status","coin":"BTCD"}*/
    if ( (symbol= jstr(json,"coin")) != 0 && symbol[0] != 0 )
    {
        if ( coin == 0 )
            coin = iguana_coinfind(symbol);
        else if ( strcmp(symbol,coin->symbol) != 0 )
            return(clonestr("{\"error\":\"mismatched coin symbol\"}"));
    }
    if ( strcmp(method,"explore") == 0 )
    {
        obj = jobj(json,"search");
        if ( coin != 0 && obj != 0 )
        {
            argjson = cJSON_CreateObject();
            jaddstr(argjson,"agent","ramchain");
            jaddstr(argjson,"method","block");
            jaddnum(argjson,"txids",1);
            if ( is_cJSON_Number(obj) != 0 )
            {
                height = juint(obj,0);
                jaddnum(argjson,"height",height);
            }
            else if ( (str= jstr(obj,0)) != 0 )
                jaddstr(argjson,"hash",str);
            else return(clonestr("{\"error\":\"need number or string to search\"}"));
            if ( (retstr= iguana_jsoncheck(ramchain_coinparser(coin,"block",argjson),1)) != 0 )
            {
                free_json(argjson);
                return(retstr);
            }
            free_json(argjson);
            argjson = cJSON_CreateObject();
            jaddstr(argjson,"agent","ramchain");
            jaddstr(argjson,"method","tx");
            jaddstr(argjson,"txid",str);
            if ( (retstr= iguana_jsoncheck(ramchain_coinparser(coin,"tx",argjson),1)) != 0 )
            {
                free_json(argjson);
                return(retstr);
            }
            free_json(argjson);
            return(clonestr("{\"result\":\"explore search cant find height, blockhash, txid\"}"));
        }
        return(clonestr("{\"result\":\"explore no coin or search\"}"));
    }
    return(ramchain_coinparser(coin,method,json));
}


#define RPCARGS struct supernet_info *myinfo,struct iguana_info *coin,cJSON *params[],int32_t n,cJSON *json,char *remoteaddr

// MAP bitcoin RPC to SuperNET JSONstr
// MAP REST to SuperNET JSONstr
// misc
static char *help(RPCARGS)
{
    return(clonestr("{\"result\":\"return help string here\n"));
}

static char *stop(RPCARGS)
{
    return(iguana_coinjson(coin,"pausecoin",params[0]));
}

static char *sendalert(RPCARGS)
{
    return(0);
}

static char *SuperNET(RPCARGS)
{
    return(SuperNET_JSON(myinfo,json,remoteaddr));
}

static char *getrawmempool(RPCARGS)
{
    return(0);
}

// peers
static char *getconnectioncount(RPCARGS)
{
    int32_t i,num = 0; char buf[128];
    for (i=0; i<sizeof(coin->peers.active)/sizeof(*coin->peers.active); i++)
        if ( coin->peers.active[i].usock >= 0 )
            num++;
    sprintf(buf,"{\"result\":\"%d\"}",num);
    return(clonestr(buf));
}

static char *getpeerinfo(RPCARGS)
{
    cJSON *retjson; char buf[128];
    if ( (retjson= iguana_peersjson(coin,0)) != 0 )
        return(jprint(retjson,1));
    sprintf(buf,"{\"result\":\"%d\"}",coin->blocks.hwmchain.height + 1);
    return(clonestr("{\"error\":\"no peers\"}"));
}

static char *addnode(RPCARGS)
{
    // addnode	<node> <add/remove/onetry>	version 0.8 Attempts add or remove <node> from the addnode list or try a connection to <node> once.	N
    return(0);
}

// address and pubkeys
struct iguana_waddress *iguana_waddresscalc(struct iguana_info *coin,struct iguana_waddress *addr,bits256 privkey)
{
    memset(addr,0,sizeof(*addr));
    addr->privkey = privkey;
    if ( btc_priv2pub(addr->pubkey,addr->privkey.bytes) == 0 && btc_priv2wip(addr->wipstr,addr->privkey.bytes,coin->chain->wipval) == 0 && btc_pub2rmd(addr->rmd160,addr->pubkey) == 0 && btc_convrmd160(addr->coinaddr,coin->chain->pubval,addr->rmd160) == 0 )
    {
        addr->wiptype = coin->chain->wipval;
        addr->type = coin->chain->pubval;
        return(addr);
    }
    return(0);
}

int32_t iguana_addressvalidate(struct iguana_info *coin,char *coinaddr)
{
   // verify checksum bytes
    return(0);
}

static char *validateretstr(struct iguana_info *coin,char *coinaddr)
{
    char *retstr,buf[512]; cJSON *json;
    if ( iguana_addressvalidate(coin,coinaddr) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    sprintf(buf,"{\"agent\":\"ramchain\",\"coin\":\"%s\",\"method\":\"validate\",\"address\":\"%s\"}",coin->symbol,coinaddr);
    if ( (json= cJSON_Parse(buf)) != 0 )
        retstr = ramchain_coinparser(coin,"validate",json);
    else return(clonestr("{\"error\":\"internal error, couldnt parse validate\"}"));
    free_json(json);
    return(retstr);
}

static char *validateaddress(RPCARGS)
{
    char *coinaddr; cJSON *retjson;
    retjson = cJSON_CreateObject();
    if ( params[0] != 0 && (coinaddr= jstr(params[0],0)) != 0 )
        return(validateretstr(coin,coinaddr));
    return(clonestr("{\"error\":\"need coin address\"}"));
}

static char *validatepubkey(RPCARGS)
{
    char *pubkeystr,coinaddr[128]; cJSON *retjson;
    retjson = cJSON_CreateObject();
    if ( params[0] != 0 && (pubkeystr= jstr(params[0],0)) != 0 )
    {
        if ( btc_coinaddr(coinaddr,coin->chain->pubval,pubkeystr) == 0 )
            return(validateretstr(coin,coinaddr));
        return(clonestr("{\"error\":\"cant convert pubkey\"}"));
    }
    return(clonestr("{\"error\":\"need pubkey\"}"));
}

static char *createmultisig(RPCARGS)
{
    return(0);
}

// blockchain
static char *getinfo(RPCARGS)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",coin->statusstr);
    return(jprint(retjson,1));
}

static char *getbestblockhash(RPCARGS)
{
    char buf[512],str[65];
    sprintf(buf,"{\"result\":\"%s\"}",bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(clonestr(buf));
}

static char *getblockcount(RPCARGS)
{
    char buf[512];
    sprintf(buf,"{\"result\":\"%d\"}",coin->blocks.hwmchain.height + 1);
    return(clonestr(buf));
}

static char *getblock(RPCARGS)
{
    return(0);
}

static char *getblockhash(RPCARGS)
{
    return(0);
}

static char *gettransaction(RPCARGS)
{
    return(0);
}

static char *listtransactions(RPCARGS)
{
    return(0);
}

static char *getreceivedbyaddress(RPCARGS)
{
    return(0);
}

static char *listreceivedbyaddress(RPCARGS)
{
    return(0);
}

static char *listsinceblock(RPCARGS)
{
    return(0);
}

// waccount and waddress funcs
static char *getreceivedbyaccount(RPCARGS)
{
    return(0);
}

static char *listreceivedbyaccount(RPCARGS)
{
    return(0);
}

static char *addmultisigaddress(RPCARGS)
{
    return(0);
}

static char *getnewaddress(RPCARGS)
{
    struct iguana_waddress addr; char str[67],*account; cJSON *retjson = cJSON_CreateObject();
    if ( iguana_waddresscalc(coin,&addr,rand256(1)) == 0 )
    {
        jaddstr(retjson,"result",addr.coinaddr);
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"pubkey",str);
        jaddstr(retjson,"privkey",bits256_str(str,addr.privkey));
        jaddstr(retjson,"wip",addr.wipstr);
        init_hexbytes_noT(str,addr.rmd160,20);
        jaddstr(retjson,"rmd160",str);
        if ( params[0] != 0 && (account= jstr(params[0],0)) != 0 )
        {
            if ( iguana_waccountadd(coin,account,&addr) < 0 )
                jaddstr(retjson,"account","error adding to account");
            else jaddstr(retjson,"account",account);
        }
    } else jaddstr(retjson,"error","cant create address");
    return(jprint(retjson,1));
}

static char *makekeypair(RPCARGS)
{
    struct iguana_waddress addr; char str[67]; cJSON *retjson = cJSON_CreateObject();
    if ( iguana_waddresscalc(coin,&addr,rand256(1)) == 0 )
    {
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"result",str);
        jaddstr(retjson,"privkey",bits256_str(str,addr.privkey));
    } else jaddstr(retjson,"error","cant create address");
    return(jprint(retjson,1));
}

static char *getaccountaddress(RPCARGS)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr=0,addr; char str[67]; char *account; cJSON *retjson;
    if ( params[0] != 0 && (account= jstr(params[0],0)) != 0 )
    {
        if ( (wacct= iguana_waccountfind(coin,account)) == 0 )
        {
            if ( (waddr= iguana_waddresscalc(coin,&addr,rand256(1))) == 0 )
                return(clonestr("{\"error\":\"cant generate address\"}"));
            iguana_waccountswitch(coin,account,0,-1,addr.coinaddr);
        }
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",waddr->coinaddr);
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"pubkey",str);
        jaddstr(retjson,"privkey",bits256_str(str,waddr->privkey));
        jaddstr(retjson,"wip",waddr->wipstr);
        init_hexbytes_noT(str,waddr->rmd160,20);
        jaddstr(retjson,"rmd160",str);
        jaddstr(retjson,"account",account);
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"no account specified\"}"));
}

static char *setaccount(RPCARGS)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr=0,addr; int32_t ind=-1; char *account,*coinaddr;
    if ( params[0] != 0 && (coinaddr= jstr(params[0],0)) != 0 && params[1] != 0 && (account= jstr(params[1],0)) != 0 )
    {
        if ( iguana_addressvalidate(coin,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        if ( (wacct= iguana_waddressfind(coin,&ind,coinaddr)) == 0 )
        {
            if ( (waddr= iguana_waddresscalc(coin,&addr,rand256(1))) == 0 )
                return(clonestr("{\"error\":\"cant generate address\"}"));
        }
        iguana_waccountswitch(coin,account,wacct,ind,coinaddr);
        return(clonestr("{\"result\":\"account set\"}"));
    }
    return(clonestr("{\"error\":\"need address and account\"}"));
}

static char *getaccount(RPCARGS)
{
    struct iguana_waccount *wacct; char *coinaddr; cJSON *retjson; int32_t ind;
    if ( params[0] != 0 && (coinaddr= jstr(params[0],0)) != 0 )
    {
        if ( iguana_addressvalidate(coin,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        if ( (wacct= iguana_waddressfind(coin,&ind,coinaddr)) == 0 )
            return(clonestr("{\"result\":\"no account for address\"}"));
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",wacct->account);
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"need address\"}"));
}

static char *getaddressesbyaccount(RPCARGS)
{
    struct iguana_waccount *subset; struct iguana_waddress *waddr,*tmp; char *account; cJSON *retjson,*array;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( params[0] != 0 && (account= jstr(params[0],0)) != 0 )
    {
        if ( (subset= iguana_waccountfind(coin,account)) != 0 )
        {
            HASH_ITER(hh,subset->waddrs,waddr,tmp)
            {
                jaddistr(array,waddr->coinaddr);
            }
        } else jaddstr(retjson,"result","cant find account");
    } else jaddstr(retjson,"error","no account specified");
    jadd(retjson,"addresses",array);
    return(jprint(retjson,1));
}

static char *listaddressgroupings(RPCARGS)
{
    return(0);
}

static char *getbalance(RPCARGS)
{
    return(0);
}

// wallet
static char *listaccounts(RPCARGS)
{
    return(0);
}

static char *dumpprivkey(RPCARGS)
{
    return(0);
}

static char *importprivkey(RPCARGS)
{
    return(0);
}

static char *dumpwallet(RPCARGS)
{
    return(0);
}

static char *importwallet(RPCARGS)
{
    return(0);
}

static char *walletpassphrase(RPCARGS)
{
    return(0);
}

static char *walletpassphrasechange(RPCARGS)
{
    return(0);
}

static char *walletlock(RPCARGS)
{
    return(0);
}

static char *encryptwallet(RPCARGS)
{
    return(0);
}

static char *checkwallet(RPCARGS)
{
    return(0);
}

static char *repairwallet(RPCARGS)
{
    return(0);
}

static char *backupwallet(RPCARGS)
{
    return(0);
}

// messages
static char *signmessage(RPCARGS)
{
    return(0);
}

static char *verifymessage(RPCARGS)
{
    return(0);
}

// unspents
static char *listunspent(RPCARGS)
{
    return(0);
}

static char *lockunspent(RPCARGS)
{
    return(0);
}

static char *listlockunspent(RPCARGS)
{
    return(0);
}

static char *gettxout(RPCARGS)
{
    return(0);
}

static char *gettxoutsetinfo(RPCARGS)
{
    return(0);
}

// payments
static char *sendtoaddress(RPCARGS)
{
    char *coinaddr,*comment=0,*comment2=0; double amount = -1.;
    //sendtoaddress	<bitcoinaddress> <amount> [comment] [comment-to]	<amount> is a real and is rounded to 8 decimal places. Returns the transaction ID <txid> if successful.	Y
    if ( params[0] != 0 && (coinaddr= jstr(params[0],0)) != 0 &&  params[1] != 0 && is_cJSON_Number(params[1]) != 0 )
    {
        if ( iguana_addressvalidate(coin,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        amount = jdouble(params[1],0);
        comment = jstr(params[2],0);
        comment2 = jstr(params[3],0);
        printf("need to generate send %.8f to %s [%s] [%s]\n",dstr(amount),coinaddr,comment!=0?comment:"",comment2!=0?comment2:"");
    }
    return(clonestr("{\"error\":\"need address and amount\"}"));
}

static char *movecmd(RPCARGS)
{
    return(0);
}

static char *sendfrom(RPCARGS)
{
    return(0);
}

static char *sendmany(RPCARGS)
{
    return(0);
}

static char *settxfee(RPCARGS)
{
    return(0);
}

// rawtransaction
static char *getrawtransaction(RPCARGS)
{
    return(0);
}

static char *createrawtransaction(RPCARGS)
{
    return(0);
}

static char *decoderawtransaction(RPCARGS)
{
    return(0);
}

static char *decodescript(RPCARGS)
{
    return(0);
}

static char *signrawtransaction(RPCARGS)
{
    return(0);
}

static char *sendrawtransaction(RPCARGS)
{
    return(0);
}

static char *resendtx(RPCARGS)
{
    return(0);
}

static char *getrawchangeaddress(RPCARGS)
{
    return(0);
}

#define true 1
#define false 0
struct RPC_info { char *name; char *(*rpcfunc)(RPCARGS); int32_t flag0,flag1; } RPCcalls[] =
{
     { "help",                   &help,                   true,   true },
     { "stop",                   &stop,                   true,   true },
     { "getbestblockhash",       &getbestblockhash,       true,   false },
     { "getblockcount",          &getblockcount,          true,   false },
     { "getconnectioncount",     &getconnectioncount,     true,   false },
     { "getpeerinfo",            &getpeerinfo,            true,   false },
     { "getinfo",                &getinfo,                true,   false },
     { "getnewaddress",          &getnewaddress,          true,   false },
     { "getnewpubkey",           &makekeypair,           true,   false },
     { "getaccountaddress",      &getaccountaddress,      true,   false },
     { "setaccount",             &setaccount,             true,   false },
     { "getaccount",             &getaccount,             false,  false },
     { "getaddressesbyaccount",  &getaddressesbyaccount,  true,   false },
     { "sendtoaddress",          &sendtoaddress,          false,  false },
     { "getreceivedbyaddress",   &getreceivedbyaddress,   false,  false },
     { "getreceivedbyaccount",   &getreceivedbyaccount,   false,  false },
     { "listreceivedbyaddress",  &listreceivedbyaddress,  false,  false },
     { "listreceivedbyaccount",  &listreceivedbyaccount,  false,  false },
     { "backupwallet",           &backupwallet,           true,   false },
     { "walletpassphrase",       &walletpassphrase,       true,   false },
     { "walletpassphrasechange", &walletpassphrasechange, false,  false },
     { "walletlock",             &walletlock,             true,   false },
     { "encryptwallet",          &encryptwallet,          false,  false },
     { "validateaddress",        &validateaddress,        true,   false },
     { "validatepubkey",         &validatepubkey,         true,   false },
     { "getbalance",             &getbalance,             false,  false },
     { "move",                   &movecmd,                false,  false },
     { "sendfrom",               &sendfrom,               false,  false },
     { "sendmany",               &sendmany,               false,  false },
     { "addmultisigaddress",     &addmultisigaddress,     false,  false },
     { "getblock",               &getblock,               false,  false },
     { "getblockhash",           &getblockhash,           false,  false },
     { "gettransaction",         &gettransaction,         false,  false },
     { "listtransactions",       &listtransactions,       false,  false },
     { "listaddressgroupings",   &listaddressgroupings,   false,  false },
     { "signmessage",            &signmessage,            false,  false },
     { "verifymessage",          &verifymessage,          false,  false },
      { "listaccounts",           &listaccounts,           false,  false },
     { "settxfee",               &settxfee,               false,  false },
     { "listsinceblock",         &listsinceblock,         false,  false },
     { "dumpprivkey",            &dumpprivkey,            false,  false },
     { "SuperNET",               &SuperNET,               false,  false },
     { "dumpwallet",             &dumpwallet,             true,   false },
     { "importwallet",           &importwallet,           false,  false },
     { "importprivkey",          &importprivkey,          false,  false },
     { "listunspent",            &listunspent,            false,  false },
     { "getrawtransaction",      &getrawtransaction,      false,  false },
     { "createrawtransaction",   &createrawtransaction,   false,  false },
     { "decoderawtransaction",   &decoderawtransaction,   false,  false },
     { "decodescript",           &decodescript,           false,  false },
     { "signrawtransaction",     &signrawtransaction,     false,  false },
     { "sendrawtransaction",     &sendrawtransaction,     false,  false },
     { "checkwallet",            &checkwallet,            false,  true},
     { "repairwallet",           &repairwallet,           false,  true},
     { "resendtx",               &resendtx,               false,  true},
     { "makekeypair",            &makekeypair,            false,  true},
     { "sendalert",              &sendalert,              false,  false},
     //
    { "createmultisig",              &createmultisig,              false,  false},
    { "addnode",              &addnode,              false,  false},
     { "getrawmempool",              &getrawmempool,              false,  false},
     { "getrawchangeaddress",              &getrawchangeaddress,              false,  false},
     { "listlockunspent",              &listlockunspent,              false,  false},
     { "lockunspent",              &lockunspent,              false,  false},
     { "gettxout",              &gettxout,              false,  false},
     { "gettxoutsetinfo",              &gettxoutsetinfo,              false,  false}
#ifdef PEGGY
    //{ "peggytx",                &peggytx,                true,   false },
    //{ "peggypayments",          &peggypayments,          true,   false },
    //{ "getpeggyblock",          &getpeggyblock,          true,   false },
#endif
   // { "addredeemscript",        &addredeemscript,        false,  false },
    //  { "getrawmempool",          &getrawmempool,          true,   false },
    //    { "getdifficulty",          &getdifficulty,          true,   false },
    //    { "getsubsidy",             &getsubsidy,             true,   false },
    //    { "getmininginfo",          &getmininginfo,          true,   false },
    //    { "getstakinginfo",         &getstakinginfo,         true,   false },
    // { "getblockbynumber",       &getblockbynumber,       false,  false },
    //{ "getwork",                &getwork,                true,   false },
    //{ "getworkex",              &getworkex,              true,   false },
    // { "keypoolrefill",          &keypoolrefill,          true,   false },
    //{ "getblocktemplate",       &getblocktemplate,       true,   false },
    //{ "submitblock",            &submitblock,            false,  false },
    // { "getcheckpoint",          &getcheckpoint,          true,   false },
    // { "reservebalance",         &reservebalance,         false,  true},
};

char *iguana_bitcoinrpc(struct supernet_info *myinfo,struct iguana_info *coin,char *method,cJSON *params[16],int32_t n,cJSON *json,char *remoteaddr)
{
    int32_t i;
    for (i=0; i<sizeof(RPCcalls)/sizeof(*RPCcalls); i++)
    {
        if ( strcmp(RPCcalls[i].name,method) == 0 )
            return((*RPCcalls[i].rpcfunc)(myinfo,coin,params,n,json,remoteaddr));
    }
    return(clonestr("{\"error\":\"invalid coin address\"}"));
}

char *iguana_bitcoinRPC(struct iguana_info *coin,struct supernet_info *myinfo,char *jsonstr,char *remoteaddr)
{
    cJSON *json,*params[16],*array; char *method; int32_t i,n; char *retstr = 0;
    memset(params,0,sizeof(params));
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (method= jstr(json,"method")) != 0 )
        {
            if ( (array= jarray(&n,json,"params")) == 0 )
            {
                n = 1;
                params[0] = jobj(json,"params");
            }
            else
            {
                params[0] = jitem(array,0);
                if ( n > 1 )
                    for (i=1; i<n; i++)
                        params[i] = jitem(array,i);
            }
            retstr = iguana_bitcoinrpc(myinfo,coin,method,params,n,json,remoteaddr);
        }
        free_json(json);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"cant parse jsonstr\"}");
    return(retstr);
}
