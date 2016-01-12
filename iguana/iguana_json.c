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

cJSON *iguana_peerjson(struct iguana_info *coin,struct iguana_peer *addr)
{
    cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"ipaddr",addr->ipaddr);
    jaddnum(json,"protover",addr->protover);
    jaddnum(json,"relay",addr->relayflag);
    jaddnum(json,"height",addr->height);
    jaddnum(json,"rank",addr->rank);
    jaddnum(json,"usock",addr->usock);
    if ( addr->dead != 0 )
        jaddnum(json,"dead",addr->dead);
    jaddnum(json,"ready",addr->ready);
    jaddnum(json,"recvblocks",addr->recvblocks);
    jaddnum(json,"recvtotal",addr->recvtotal);
    jaddnum(json,"lastcontact",addr->lastcontact);
    if ( addr->numpings > 0 )
        jaddnum(json,"aveping",addr->pingsum/addr->numpings);
    array = cJSON_CreateObject();
    jaddnum(array,"version",addr->msgcounts.version);
    jaddnum(array,"verack",addr->msgcounts.verack);
    jaddnum(array,"getaddr",addr->msgcounts.getaddr);
    jaddnum(array,"addr",addr->msgcounts.addr);
    jaddnum(array,"inv",addr->msgcounts.inv);
    jaddnum(array,"getdata",addr->msgcounts.getdata);
    jaddnum(array,"notfound",addr->msgcounts.notfound);
    jaddnum(array,"getblocks",addr->msgcounts.getblocks);
    jaddnum(array,"getheaders",addr->msgcounts.getheaders);
    jaddnum(array,"headers",addr->msgcounts.headers);
    jaddnum(array,"tx",addr->msgcounts.tx);
    jaddnum(array,"block",addr->msgcounts.block);
    jaddnum(array,"mempool",addr->msgcounts.mempool);
    jaddnum(array,"ping",addr->msgcounts.ping);
    jaddnum(array,"pong",addr->msgcounts.pong);
    jaddnum(array,"reject",addr->msgcounts.reject);
    jaddnum(array,"filterload",addr->msgcounts.filterload);
    jaddnum(array,"filteradd",addr->msgcounts.filteradd);
    jaddnum(array,"filterclear",addr->msgcounts.filterclear);
    jaddnum(array,"merkleblock",addr->msgcounts.merkleblock);
    jaddnum(array,"alert",addr->msgcounts.alert);
    jadd(json,"msgcounts",array);
    return(json);
}

cJSON *iguana_peersjson(struct iguana_info *coin,int32_t addronly)
{
    cJSON *retjson,*array; int32_t i; struct iguana_peer *addr;
    if ( coin == 0 )
        return(0);
    array = cJSON_CreateArray();
    for (i=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        if ( addr->usock >= 0 && addr->ipbits != 0 && addr->ipaddr[0] != 0 )
        {
            if ( addronly != 0 )
                jaddistr(array,addr->ipaddr);
            else jaddi(array,iguana_peerjson(coin,addr));
        }
    }
    if ( addronly == 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"peers",array);
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(retjson);
    }
    else return(array);
}

char *iguana_coinjson(struct iguana_info *coin,char *method,cJSON *json)
{
    int32_t i,max,retval,num=0; char buf[1024]; struct iguana_peer *addr; char *ipaddr; cJSON *retjson = 0;
    //printf("iguana_coinjson(%s)\n",jprint(json,0));
    if ( strcmp(method,"peers") == 0 )
        return(jprint(iguana_peersjson(coin,0),1));
    else if ( strcmp(method,"getconnectioncount") == 0 )
    {
        for (i=0; i<sizeof(coin->peers.active)/sizeof(*coin->peers.active); i++)
            if ( coin->peers.active[i].usock >= 0 )
                num++;
        sprintf(buf,"{\"result\":\"%d\"}",num);
        return(clonestr(buf));
    }
    else if ( strcmp(method,"addnode") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            iguana_possible_peer(coin,ipaddr);
            return(clonestr("{\"result\":\"addnode submitted\"}"));
        } else return(clonestr("{\"error\":\"addnode needs ipaddr\"}"));
    }
    else if ( strcmp(method,"removenode") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            for (i=0; i<IGUANA_MAXPEERS; i++)
            {
                if ( strcmp(coin->peers.active[i].ipaddr,ipaddr) == 0 )
                {
                    coin->peers.active[i].rank = 0;
                    coin->peers.active[i].dead = (uint32_t)time(NULL);
                    return(clonestr("{\"result\":\"node marked as dead\"}"));
                }
            }
            return(clonestr("{\"result\":\"node wasnt active\"}"));
        } else return(clonestr("{\"error\":\"removenode needs ipaddr\"}"));
    }
    else if ( strcmp(method,"oneshot") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            iguana_possible_peer(coin,ipaddr);
            return(clonestr("{\"result\":\"addnode submitted\"}"));
        } else return(clonestr("{\"error\":\"addnode needs ipaddr\"}"));
    }
    else if ( strcmp(method,"nodestatus") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            for (i=0; i<coin->MAXPEERS; i++)
            {
                addr = &coin->peers.active[i];
                if ( strcmp(addr->ipaddr,ipaddr) == 0 )
                    return(jprint(iguana_peerjson(coin,addr),1));
            }
            return(clonestr("{\"result\":\"nodestatus couldnt find ipaddr\"}"));
        } else return(clonestr("{\"error\":\"nodestatus needs ipaddr\"}"));
    }
    else if ( strcmp(method,"maxpeers") == 0 )
    {
        retjson = cJSON_CreateObject();
        if ( (max= juint(json,"max")) <= 0 )
            max = 1;
        else if ( max > IGUANA_MAXPEERS )
            max = IGUANA_MAXPEERS;
        if ( max > coin->MAXPEERS )
        {
            for (i=max; i<coin->MAXPEERS; i++)
                if ( (addr= coin->peers.ranked[i]) != 0 )
                    addr->dead = 1;
        }
        coin->MAXPEERS = max;
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(jprint(retjson,1));
    }
    else if ( strcmp(method,"getrawmempool") == 0 )
    {
        return(clonestr("{\"result\":\"no rampool yet\"}"));
    }
    else if ( strcmp(method,"sendalert") == 0 )
    {
        return(clonestr("{\"result\":\"no sendalert yet\"}"));
    }
    else if ( strcmp(method,"startcoin") == 0 )
    {
        coin->active = 1;
        return(clonestr("{\"result\":\"coin started\"}"));
    }
    else if ( strcmp(method,"pausecoin") == 0 )
    {
        coin->active = 0;
        return(clonestr("{\"result\":\"coin paused\"}"));
    }
    else if ( strcmp(method,"addcoin") == 0 )
    {
        if ( (retval= iguana_launchcoin(coin->symbol,json)) > 0 )
            return(clonestr("{\"result\":\"coin added\"}"));
        else if ( retval == 0 )
            return(clonestr("{\"result\":\"coin already there\"}"));
        else return(clonestr("{\"error\":\"error adding coin\"}"));
    }
    return(clonestr("{\"error\":\"unhandled request\"}"));
}

char *iguana_parser(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr)
{
    char *coinstr,SYM[16]; int32_t j,k,l,r,rr; struct iguana_peer *addr;
    cJSON *retjson = 0,*array; int32_t i,n; struct iguana_info *coin; char *symbol;
    printf("remoteaddr.(%s)\n",remoteaddr!=0?remoteaddr:"local");
    if ( remoteaddr == 0 || remoteaddr[0] == 0 || strcmp(remoteaddr,"127.0.0.1") == 0 ) // local (private) api
    {
        if ( strcmp(method,"list") == 0 )
        {
            retjson = cJSON_CreateObject();
            array = cJSON_CreateArray();
            for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            {
                if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                    jaddistr(array,Coins[i]->symbol);
            }
            jadd(retjson,"coins",array);
            return(jprint(retjson,1));
        }
        else if ( strcmp(method,"allpeers") == 0 )
        {
            retjson = cJSON_CreateObject();
            array = cJSON_CreateArray();
            for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            {
                if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                    jaddi(array,iguana_peersjson(Coins[i],0));
            }
            jadd(retjson,"allpeers",array);
            return(jprint(retjson,1));
        }
        else
        {
            if ( (symbol= jstr(json,"coin")) != 0 && strlen(symbol) < sizeof(SYM)-1 )
            {
                strcpy(SYM,symbol);
                touppercase(SYM);
                if ( (coin= iguana_coinfind(SYM)) == 0 )
                {
                    if ( strcmp(method,"addcoin") == 0 )
                        coin = iguana_coinadd(SYM);
                }
                if ( coin != 0 )
                    return(iguana_coinjson(coin,method,json));
                else return(clonestr("{\"error\":\"cant get coin info\"}"));
            }
        }
    }
    array = 0;
    if ( strcmp(method,"getpeers") == 0 )
    {
        if ( (coinstr= jstr(json,"coin")) != 0 )
        {
            if ( (array= iguana_peersjson(iguana_coinfind(coinstr),1)) == 0 )
                return(clonestr("{\"error\":\"coin not found\"}"));
        }
        else
        {
            n = 0;
            array = cJSON_CreateArray();
            r = rand();
            for (i=0; i<IGUANA_MAXCOINS; i++)
            {
                j = (r + i) % IGUANA_MAXCOINS;
                if ( (coin= Coins[j]) != 0 )
                {
                    rr = rand();
                    for (k=0; k<IGUANA_MAXPEERS; k++)
                    {
                        l = (rr + k) % IGUANA_MAXPEERS;
                        addr = &coin->peers.active[l];
                        if ( addr->usock >= 0 && addr->supernet != 0 )
                        {
                            jaddistr(array,addr->ipaddr);
                            if ( ++n >= 64 )
                                break;
                        }
                    }
                }
            }
        }
        if ( array != 0 )
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"agent","SuperNET");
            jaddstr(retjson,"method","mypeers");
            jaddstr(retjson,"result","peers found");
            jadd(retjson,"peers",array);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"no peers found\"}"));
    }
    else if ( strcmp(method,"mypeers") == 0 )
    {
        printf("mypeers from %s\n",remoteaddr!=0?remoteaddr:"local");
    }
    return(clonestr("{\"result\":\"stub processed generic json\"}"));
}

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

/*
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
        else if ( strcmp(method,"validateaddress") == 0 )
        {
            jaddstr(retitem,"validate",coinaddr);
        }
        if ( n == 0 )
            return(jprint(retitem,1));
        else jaddi(retjson,retitem);
    }
    return(jprint(retjson,1));
}
*/

char *iguana_listsinceblock(struct supernet_info *myinfo,struct iguana_info *coin,bits256 blockhash,int32_t target)
{
    cJSON *retitem = cJSON_CreateObject();
    return(jprint(retitem,1));
}

char *iguana_getinfo(struct supernet_info *myinfo,struct iguana_info *coin)
{
    cJSON *retitem = cJSON_CreateObject();
    jaddstr(retitem,"result",coin->statusstr);
    return(jprint(retitem,1));
}

char *iguana_getbestblockhash(struct supernet_info *myinfo,struct iguana_info *coin)
{
    cJSON *retitem = cJSON_CreateObject();
    char str[65]; jaddstr(retitem,"result",bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(jprint(retitem,1));
}

char *iguana_getblockcount(struct supernet_info *myinfo,struct iguana_info *coin)
{
    cJSON *retitem = cJSON_CreateObject();
    jaddnum(retitem,"result",coin->blocks.hwmchain.height);
    return(jprint(retitem,1));
}

char *ramchain_coinparser(struct supernet_info *myinfo,struct iguana_info *coin,char *method,cJSON *json)
{
    //char *hashstr,*txidstr,*coinaddr,*txbytes,rmd160str[41],str[65]; int32_t len,height,i,n,valid = 0;
    //cJSON *addrs,*retjson,*retitem; uint8_t rmd160[20],addrtype; bits256 hash2,checktxid;
    //memset(&hash2,0,sizeof(hash2)); struct iguana_txid *tx,T; struct iguana_block *block = 0;
    if ( coin == 0 && (coin= iguana_coinselect()) == 0 )
        return(clonestr("{\"error\":\"ramchain_coinparser needs coin\"}"));
    if ( strcmp(method,"status") == 0 || strcmp(method,"getinfo") == 0 )
        return(iguana_getinfo(myinfo,coin));
    else if ( strcmp(method,"getbestblockhash") == 0 )
        return(iguana_getbestblockhash(myinfo,coin));
    else if ( strcmp(method,"getblockcount") == 0 )
        return(iguana_getblockcount(myinfo,coin));
    else if ( strcmp(method,"validatepubkey") == 0 )
        return(iguana_validatepubkey(myinfo,coin,jstr(json,"pubkey")));
    else if ( strcmp(method,"listtransactions") == 0 )
        return(iguana_listtransactions(myinfo,coin,jstr(json,"account"),juint(json,"count"),juint(json,"from")));
    else if ( strcmp(method,"getreceivedbyaddress") == 0 )
        return(iguana_getreceivedbyaddress(myinfo,coin,jstr(json,"address"),juint(json,"minconf")));
    else if ( strcmp(method,"listreceivedbyaddress") == 0 )
        return(iguana_listreceivedbyaddress(myinfo,coin,juint(json,"minconf"),juint(json,"includeempty")));
    else if ( strcmp(method,"listsinceblock") == 0 )
        return(iguana_listsinceblock(myinfo,coin,jbits256(json,"blockhash"),juint(json,"target")));
    else if ( strcmp(method,"getreceivedbyaccount") == 0 )
        return(iguana_getreceivedbyaccount(myinfo,coin,jstr(json,"account"),juint(json,"minconf")));
    else if ( strcmp(method,"listreceivedbyaccount") == 0 )
        return(iguana_listreceivedbyaccount(myinfo,coin,jstr(json,"account"),juint(json,"includeempty")));
    else if ( strcmp(method,"getnewaddress") == 0 )
        return(iguana_getnewaddress(myinfo,coin,jstr(json,"account")));
    else if ( strcmp(method,"makekeypair") == 0 )
        return(iguana_makekeypair(myinfo,coin));
    else if ( strcmp(method,"getaccountaddress") == 0 )
        return(iguana_getaccountaddress(myinfo,coin,jstr(json,"account")));
    else if ( strcmp(method,"setaccount") == 0 )
        return(iguana_setaccount(myinfo,coin,jstr(json,"account")));
    else if ( strcmp(method,"getaccount") == 0 )
        return(iguana_getaccount(myinfo,coin,jstr(json,"account")));
    else if ( strcmp(method,"getaddressesbyaccount") == 0 )
        return(iguana_getaddressesbyaccount(myinfo,coin,jstr(json,"account")));
    else if ( strcmp(method,"listaddressgroupings") == 0 )
        return(iguana_listaddressgroupings(myinfo,coin));
    else if ( strcmp(method,"getbalance") == 0 )
        return(iguana_getbalance(myinfo,coin,jstr(json,"account"),juint(json,"minconf")));
    else if ( strcmp(method,"listaccounts") == 0 )
        return(iguana_listaccounts(myinfo,coin,juint(json,"minconf")));
    else if ( strcmp(method,"dumpprivkey") == 0 )
        return(iguana_dumpprivkey(myinfo,coin,jstr(json,"address")));
    else if ( strcmp(method,"importprivkey") == 0 )
        return(iguana_importprivkey(myinfo,coin,jstr(json,"wip")));
    else if ( strcmp(method,"dumpwallet") == 0 )
        return(iguana_dumpwallet(myinfo,coin));
    else if ( strcmp(method,"importwallet") == 0 )
        return(iguana_importwallet(myinfo,coin,jstr(json,"wallet")));
    else if ( strcmp(method,"walletpassphrase") == 0 )
        return(iguana_walletpassphrase(myinfo,coin,jstr(json,"passphrase"),juint(json,"timeout")));
    else if ( strcmp(method,"walletpassphrasechange") == 0 )
        return(iguana_walletpassphrasechange(myinfo,coin,jstr(json,"oldpassphrase"),jstr(json,"newpassphrase")));
    else if ( strcmp(method,"walletlock") == 0 )
        return(iguana_walletlock(myinfo,coin));
    else if ( strcmp(method,"encryptwallet") == 0 )
        return(iguana_encryptwallet(myinfo,coin,jstr(json,"passphrase")));
    else if ( strcmp(method,"checkwallet") == 0 )
        return(iguana_checkwallet(myinfo,coin));
    else if ( strcmp(method,"repairwallet") == 0 )
        return(iguana_repairwallet(myinfo,coin));
    else if ( strcmp(method,"backupwallet") == 0 )
        return(iguana_backupwallet(myinfo,coin,jstr(json,"filename")));
    else if ( strcmp(method,"signmessage") == 0 )
        return(iguana_signmessage(myinfo,coin,jstr(json,"address"),jstr(json,"message")));
    else if ( strcmp(method,"verifymessage") == 0 )
        return(iguana_verifymessage(myinfo,coin,jstr(json,"address"),jstr(json,"sig"),jstr(json,"message")));
    else if ( strcmp(method,"listunspent") == 0 )
        return(iguana_listunspent(myinfo,coin,juint(json,"minconf"),juint(json,"maxconf")));
    else if ( strcmp(method,"lockunspent") == 0 )
        return(iguana_lockunspent(myinfo,coin,jstr(json,"filename")));
    else if ( strcmp(method,"listlockunspent") == 0 )
        return(iguana_listlockunspent(myinfo,coin,jstr(json,"unlock"),jobj(json,"array")));
    else if ( strcmp(method,"gettxout") == 0 )
        return(iguana_gettxout(myinfo,coin,jbits256(json,"txid"),juint(json,"vout"),juint(json,"mempool")));
    else if ( strcmp(method,"gettxoutsetinfo") == 0 )
        return(iguana_gettxoutsetinfo(myinfo,coin));
    else if ( strcmp(method,"sendtoaddress") == 0 )
        return(iguana_sendtoaddress(myinfo,coin,jstr(json,"address"),jdouble(json,"amount"),jstr(json,"comment"),jstr(json,"comment2")));
    else if ( strcmp(method,"move") == 0 )
        return(iguana_move(myinfo,coin,jstr(json,"fromaccount"),jstr(json,"toaccount"),jdouble(json,"amount"),juint(json,"minconf"),jstr(json,"comment")));
    else if ( strcmp(method,"sendfrom") == 0 )
        return(iguana_sendfrom(myinfo,coin,jstr(json,"fromaccount"),jstr(json,"toaddress"),jdouble(json,"amount"),juint(json,"minconf"),jstr(json,"comment"),jstr(json,"comment2")));
    else if ( strcmp(method,"sendmany") == 0 )
        return(iguana_sendmany(myinfo,coin,jstr(json,"fromaccount"),jobj(json,"payments"),juint(json,"minconf"),jstr(json,"comment")));
    else if ( strcmp(method,"settxfee") == 0 )
        return(iguana_settxfee(myinfo,coin,jdouble(json,"amount")));
    else if ( strcmp(method,"getrawtransaction") == 0 )
        return(iguana_getrawtransaction(myinfo,coin,jbits256(json,"txid"),juint(json,"verbose")));
    else if ( strcmp(method,"createrawtransaction") == 0 )
        return(iguana_createrawtransaction(myinfo,coin,jobj(json,"vins"),jobj(json,"vouts")));
    else if ( strcmp(method,"decoderawtransaction") == 0 )
        return(iguana_decoderawtransaction(myinfo,coin,jstr(json,"rawtx")));
    else if ( strcmp(method,"decodescript") == 0 )
        return(iguana_decodescript(myinfo,coin,jstr(json,"script")));
    else if ( strcmp(method,"signrawtransaction") == 0 )
        return(iguana_signrawtransaction(myinfo,coin,jstr(json,"rawtx"),jobj(json,"vins"),jobj(json,"privkeys")));
    else if ( strcmp(method,"sendrawtransaction") == 0 )
        return(iguana_sendrawtransaction(myinfo,coin,jstr(json,"rawtx")));
    else if ( strcmp(method,"getrawchangeaddress") == 0 )
        return(iguana_getrawchangeaddress(myinfo,coin,jstr(json,"account")));
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
            if ( (retstr= iguana_jsoncheck(ramchain_coinparser(myinfo,coin,"block",argjson),1)) != 0 )
            {
                free_json(argjson);
                return(retstr);
            }
            free_json(argjson);
            argjson = cJSON_CreateObject();
            jaddstr(argjson,"agent","ramchain");
            jaddstr(argjson,"method","tx");
            jaddstr(argjson,"txid",str);
            if ( (retstr= iguana_jsoncheck(ramchain_coinparser(myinfo,coin,"tx",argjson),1)) != 0 )
            {
                free_json(argjson);
                return(retstr);
            }
            free_json(argjson);
            return(clonestr("{\"result\":\"explore search cant find height, blockhash, txid\"}"));
        }
        return(clonestr("{\"result\":\"explore no coin or search\"}"));
    }
    return(ramchain_coinparser(myinfo,coin,method,json));
}
