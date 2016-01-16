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


/*
 //char *hashstr,*txidstr,*coinaddr,*txbytes,rmd160str[41],str[65]; int32_t len,height,i,n,valid = 0;
 //cJSON *addrs,*retjson,*retitem; uint8_t rmd160[20],addrtype; bits256 hash2,checktxid;
 //memset(&hash2,0,sizeof(hash2)); struct iguana_txid *tx,T; struct iguana_block *block = 0;
 
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

/*
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
 }*/


