/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
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


//#define uthash_malloc(size) iguana_memalloc(&coin->RThashmem,size,1)
//#define uthash_free(ptr,size)

#include "iguana777.h"
#include "exchanges/bitcoin.h"


int32_t iguana_unspentind2txid(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *spentheightp,bits256 *txidp,int32_t *voutp,int16_t hdrsi,uint32_t unspentind)
{
    struct iguana_ramchaindata *rdata=0; struct iguana_bundle *bp=0; struct iguana_unspent *U,*u; struct iguana_txid *T,*t;
    *voutp = *spentheightp = -1;
    memset(txidp,0,sizeof(*txidp));
    if ( hdrsi == coin->bundlescount-1 )
        rdata = coin->RTramchain.H.data;
    else if ( (bp= coin->bundles[hdrsi]) != 0 )
        rdata = bp->ramchain.H.data;
    while ( rdata != 0 && unspentind > 0 && unspentind < rdata->numunspents )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        u = &U[unspentind];
        if ( u->txidind > 0 && u->txidind < rdata->numtxids )
        {
            T = RAMCHAIN_PTR(rdata,Toffset);
            t = &T[u->txidind];
            if ( unspentind >= t->firstvout )
            {
                *txidp = t->txid;
                *spentheightp = (hdrsi * coin->chain->bundlesize) + t->bundlei;
                *voutp = unspentind - t->firstvout;
                return(0);
            }
        }
        else if ( bp == 0 && (bp= coin->bundles[hdrsi]) != 0 )
            rdata = bp->ramchain.H.data;
        else break;
    }
    return(-1);
    //{"txid":"e34686afc17ec37a8438f0c9a7e48f98d0c625c7917a59c2d7fa22b53d570115","vout":1,"address":"16jsjc1YvzDXqKf7PorMhTyK8ym3ra3uxm","scriptPubKey":"76a9143ef4734c1141725c095342095f6e0e7748b6c16588ac","amount":0.01000000,"timestamp":0,"height":419261,"confirmations":1729,"checkind":4497018,"account":"default","spendable":true,"spent":{"hdrsi":209,"pkind":2459804,"unspentind":4497018,"prevunspentind":0,"satoshis":"1000000","txidind":1726947,"vout":1,"type":2,"fileid":0,"scriptpos":0,"scriptlen":25},"spentheight":419713,"dest":{"spentfrom":"22651e62f248fe2e72053d650f177e4b246ee016605102a40419e603b2bbeac8","vin":0,"timestamp":0,"vouts":[{"1KRhTPvoxyJmVALwHFXZdeeWFbcJSbkFPu":0.00010000}, {"1GQHQ7vwVpGeir2kKrYATsLtrkUQSc7FGY":0.00980000}],"total":0.00990000,"ratio":1}}
    cJSON *retarray,*item,*uitem,*sitem; char *retstr; int32_t i,n,retval = -1;
    *voutp = *spentheightp = -1;
    memset(txidp,0,sizeof(*txidp));
    if ( (retstr= bitcoinrpc_listunspent(myinfo,coin,0,0,0,0,0)) != 0 )
    {
        if ( (retarray= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(retarray)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(retarray,i);
                    if ( (uitem= jobj(item,"unspent")) != 0 )
                    {
                        if ( juint(uitem,"hdrsi") == hdrsi && juint(uitem,"unspentind") == unspentind )
                        {
                            *txidp = jbits256(item,"txid");
                            *voutp = jint(item,"vout");
                            *spentheightp = 0;
                            retval = 0;
                            break;
                        }
                    }
                    else if ( (sitem= jobj(item,"spent")) != 0 )
                    {
                        if ( juint(sitem,"hdrsi") == hdrsi && juint(sitem,"unspentind") == unspentind )
                        {
                            *txidp = jbits256(item,"txid");
                            *voutp = jint(item,"vout");
                            *spentheightp = jint(item,"spentheight");
                            retval = 1;
                            break;
                        }
                    }
                }
            }
            free_json(retarray);
        }
        free(retstr);
    }
    return(retval);
}

int32_t iguana_unspentindfind(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,uint8_t *spendscript,int32_t *spendlenp,uint64_t *valuep,int32_t *heightp,bits256 txid,int32_t vout,int32_t lasthdrsi,int32_t mempool)
{
    struct iguana_txid *tp,TX; struct gecko_memtx *memtx; struct iguana_pkhash *P; struct iguana_unspent *U; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; int64_t RTspend; int64_t value; int32_t pkind,hdrsi,firstvout,spentheight,flag=0,unspentind = -1;
    //portable_mutex_lock(&coin->RTmutex);
    if ( valuep != 0 )
        *valuep = 0;
    if ( coinaddr != 0 )
        coinaddr[0] = 0;
    if ( coin->fastfind != 0 && (firstvout= iguana_txidfastfind(coin,heightp,txid,lasthdrsi)) >= 0 )
        unspentind = (firstvout + vout);
    else if ( (tp= iguana_txidfind(coin,heightp,&TX,txid,lasthdrsi)) != 0 )
        unspentind = (tp->firstvout + vout);
    if ( coinaddr != 0 && unspentind > 0 && (hdrsi= *heightp/coin->chain->bundlesize) >= 0 && hdrsi < coin->bundlescount && (bp= coin->bundles[hdrsi]) != 0 && (rdata= bp->ramchain.H.data) != 0 && unspentind < rdata->numunspents )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        P = RAMCHAIN_PTR(rdata,Poffset);
        pkind = U[unspentind].pkind;
        if ( pkind > 0 && pkind < rdata->numpkinds )
        {
            RTspend = 0;
            flag++;
            if ( iguana_spentflag(myinfo,coin,&RTspend,&spentheight,bp == coin->current ? &coin->RTramchain : &bp->ramchain,bp->hdrsi,unspentind,0,1,coin->longestchain,U[unspentind].value) == 0 ) //
            {
                if ( valuep != 0 )
                    *valuep = U[unspentind].value;
                bitcoin_address(coinaddr,iguana_addrtype(coin,U[unspentind].type),P[pkind].rmd160,sizeof(P[pkind].rmd160));
                if ( spendscript != 0 && spendlenp != 0 )
                    *spendlenp = iguana_voutscript(coin,bp,spendscript,0,&U[unspentind],&P[pkind],1);
            }
        }
    }
    if ( flag == 0 && mempool != 0 )
    {
        if ( (memtx= gecko_unspentfind(0,coin,txid)) != 0 && vout < memtx->numoutputs )
        {
            memcpy(&value,gecko_valueptr(memtx,vout),sizeof(value));
            if ( value > 0 )
            {
                *valuep = value;
                if ( spendlenp != 0 )
                {
                    *spendlenp = 1;
                    spendscript = 0;
                    printf("mempool unspentind doesnt support scriptlenp yet\n");
                }
            }
        }
    }
    //portable_mutex_unlock(&coin->RTmutex);
    return(unspentind);
}

char *iguana_inputaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,int16_t *spent_hdrsip,uint32_t *unspentindp,cJSON *vinobj)
{
    bits256 txid; int32_t vout,checkind,height;
    *unspentindp = 0;
    *spent_hdrsip = -1;
    if ( jobj(vinobj,"txid") != 0 && jobj(vinobj,"vout") != 0 )
    {
        txid = jbits256(vinobj,"txid");
        vout = jint(vinobj,"vout");
        height = jint(vinobj,"height");
        checkind = jint(vinobj,"checkind");
        if ( (height != 0 && checkind != 0) || (checkind= iguana_unspentindfind(myinfo,coin,coinaddr,0,0,0,&height,txid,vout,coin->bundlescount-1,0)) > 0 )
        {
            *spent_hdrsip = (height / coin->chain->bundlesize);
            *unspentindp = checkind;
            return(coinaddr);
        }
        else
        {
            char str[65];
            printf("error finding (%s/%d) height.%d checkind.%d\n",bits256_str(str,txid),vout,height,checkind);
        }
    }
    return(0);
}

cJSON *ramchain_unspentjson(struct iguana_unspent *up,uint32_t unspentind)
{
    cJSON *item = cJSON_CreateObject();
    jaddnum(item,"hdrsi",up->hdrsi);
    jaddnum(item,"pkind",up->pkind);
    jaddnum(item,"unspentind",unspentind);
    jaddnum(item,"prevunspentind",up->prevunspentind);
    jadd64bits(item,"satoshis",up->value);
    jaddnum(item,"txidind",up->txidind);
    jaddnum(item,"vout",up->vout);
    jaddnum(item,"type",up->type);
    jaddnum(item,"fileid",up->fileid);
    jaddnum(item,"scriptpos",up->scriptpos);
    jaddnum(item,"scriptlen",up->scriptlen);
    return(item);
}

cJSON *ramchain_spentjson(struct iguana_info *coin,int32_t spentheight,int32_t hdrsi,int32_t unspentind,bits256 txid,int32_t vout,int64_t uvalue)
{
    char coinaddr[64]; bits256 hash2,*X; struct iguana_txid T,*tx,*spentT,*spent_tx; struct iguana_bundle *bp; int32_t j,i,ind; struct iguana_block *block; int64_t total = 0; struct iguana_unspent *U,*u; struct iguana_pkhash *P; struct iguana_spend *S,*s; struct iguana_ramchaindata *rdata; cJSON *addrs,*item,*voutobj;
    item = cJSON_CreateObject();
    hash2 = iguana_blockhash(coin,spentheight);
    if ( (block= iguana_blockfind("spent",coin,hash2)) != 0 && (bp= coin->bundles[spentheight/coin->chain->bundlesize]) != 0 && (rdata= bp->ramchain.H.data) != 0 )
    {
        X = RAMCHAIN_PTR(rdata,Xoffset);
        S = RAMCHAIN_PTR(rdata,Soffset);
        U = RAMCHAIN_PTR(rdata,Uoffset);
        P = RAMCHAIN_PTR(rdata,Poffset);
        spentT = RAMCHAIN_PTR(rdata,Toffset);
        for (i=0; i<block->RO.txn_count; i++)
        {
            if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
            {
                // struct iguana_txid { bits256 txid; uint32_t txidind:29,firstvout:28,firstvin:28,bundlei:11,locktime,version,timestamp,extraoffset; uint16_t numvouts,numvins; } __attribute__((packed));
                // struct iguana_spend { uint64_t scriptpos:48,scriptlen:16; uint32_t spendtxidind,sequenceid; int16_t prevout; uint16_t fileid:15,external:1; } __attribute__((packed)); // numsigs:4,numpubkeys:4,p2sh:1,sighash:4
                s = &S[tx->firstvin];
                for (j=0; j<tx->numvins; j++,s++)
                {
                    if ( s->prevout == vout )
                    {
                        if ( s->external != 0 )
                        {
                            ind = s->spendtxidind & 0xfffffff;
                            if ( bits256_cmp(X[ind],txid) != 0 )
                                continue;
                        }
                        else
                        {
                            spent_tx = &spentT[s->spendtxidind];
                            if ( bits256_cmp(spent_tx->txid,txid) != 0 )
                                continue;
                        }
                        jaddbits256(item,"spentfrom",tx->txid);
                        jaddnum(item,"vin",j);
                        jaddnum(item,"timestamp",tx->timestamp);
                        u = &U[tx->firstvout];
                        addrs = cJSON_CreateArray();
                        for (j=0; j<tx->numvouts; j++,u++)
                        {
                            voutobj = cJSON_CreateObject();
                            bitcoin_address(coinaddr,iguana_addrtype(coin,u->type),P[u->pkind].rmd160,sizeof(P[u->pkind].rmd160));
                            jaddnum(voutobj,coinaddr,dstr(u->value));
                            jaddi(addrs,voutobj);
                            total += u->value;
                        }
                        jadd(item,"vouts",addrs);
                        jaddnum(item,"total",dstr(total));
                        jaddnum(item,"ratio",dstr(uvalue) / dstr(total+coin->txfee));
                        return(item);
                    }
                }
            }
        }
    }
    jaddstr(item,"error","couldnt find spent info");
    return(item);
}

cJSON *iguana_unspentjson(struct supernet_info *myinfo,struct iguana_info *coin,int32_t hdrsi,uint32_t unspentind,struct iguana_txid *T,struct iguana_unspent *up,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t spentheight,char *remoteaddr)
{
    /*{
     "txid" : "d54994ece1d11b19785c7248868696250ab195605b469632b7bd68130e880c9a",
     "vout" : 1,
     "address" : "mgnucj8nYqdrPFh2JfZSB1NmUThUGnmsqe",
     "account" : "test label",
     "scriptPubKey" : "76a9140dfc8bafc8419853b34d5e072ad37d1a5159f58488ac",
     "amount" : 0.00010000,
     "confirmations" : 6210,
     "spendable" : true
     },*/
    //struct iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; uint16_t hdrsi:12,type:4,vout; } __attribute__((packed));
    struct iguana_waccount *wacct; struct iguana_waddress *waddr; int32_t height; char scriptstr[8192],asmstr[sizeof(scriptstr)+1024]; cJSON *item; uint32_t checkind;
    item = cJSON_CreateObject();
    jaddbits256(item,"txid",T[up->txidind].txid);
    jaddnum(item,"vout",up->vout);
    jaddstr(item,"address",coinaddr);
    if ( iguana_scriptget(coin,scriptstr,asmstr,sizeof(scriptstr),hdrsi,unspentind,T[up->txidind].txid,up->vout,rmd160,up->type,pubkey33) != 0 )
        jaddstr(item,"scriptPubKey",scriptstr);
    jaddnum(item,"amount",dstr(up->value));
    jaddnum(item,"timestamp",T[up->txidind].timestamp);
    if ( (checkind= iguana_unspentindfind(myinfo,coin,0,0,0,0,&height,T[up->txidind].txid,up->vout,coin->bundlescount-1,0)) != 0 )
    {
        jaddnum(item,"height",height);
        jaddnum(item,"confirmations",coin->blocks.hwmchain.height - height + 1);
        jaddnum(item,"checkind",checkind);
    }
    if ( remoteaddr == 0 || remoteaddr[0] == 0 )
    {
        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
        {
            jaddstr(item,"account",wacct->account);
            jadd(item,"spendable",jtrue());
        } else jadd(item,"spendable",jfalse());
    }
    if ( spentheight > 0 )
    {
        jadd(item,"spent",ramchain_unspentjson(up,unspentind));
        jaddnum(item,"spentheight",spentheight);
        jadd(item,"dest",ramchain_spentjson(coin,spentheight,hdrsi,unspentind,T[up->txidind].txid,up->vout,up->value));

    } else jadd(item,"unspent",ramchain_unspentjson(up,unspentind));
    return(item);
}

struct iguana_pkhash *iguana_pkhashfind(struct iguana_info *coin,struct iguana_ramchain **ramchainp,int64_t *depositsp,uint32_t *lastunspentindp,struct iguana_pkhash *p,uint8_t rmd160[20],int32_t firsti,int32_t endi)
{
    uint8_t *PKbits; struct iguana_pkhash *P; uint32_t pkind,numpkinds,i; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata; struct iguana_account *ACCTS;
    *depositsp = 0;
    *ramchainp = 0;
    *lastunspentindp = 0;
    for (i=firsti; i<coin->bundlescount&&i<=endi; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( 0 && coin->RTramchain_busy != 0 )
            {
                printf("iguana_pkhashfind: unexpected access when RTramchain_busy\n");
                return(0);
            }
            ramchain = &bp->ramchain;//(bp != coin->current) ? &bp->ramchain : &coin->RTramchain;
            if ( (rdata= ramchain->H.data) != 0 )
            {
                numpkinds = rdata->numpkinds;
                PKbits = RAMCHAIN_PTR(rdata,PKoffset);
                P = RAMCHAIN_PTR(rdata,Poffset);
                if ( bp == coin->current )
                    ACCTS = ramchain->A;
                else ACCTS = RAMCHAIN_PTR(rdata,Aoffset);
                if ( (pkind= iguana_sparseaddpk(PKbits,rdata->pksparsebits,rdata->numpksparse,rmd160,P,0,ramchain)) > 0 && pkind < numpkinds )
                {
                    *ramchainp = ramchain;
                    *depositsp = ACCTS[pkind].total;
                    *lastunspentindp = ACCTS[pkind].lastunspentind;
                    //printf("[%d] return pkind.%u of %u P.%p %.8f last.%u ACCTS.%p %p\n",i,pkind,numpkinds,P,dstr(*depositsp),*lastunspentindp,ACCTS,ramchain->A);
                    if ( P != 0 )
                        *p = P[pkind];
                    return(p);
                } else if ( pkind != 0 )
                    printf("[%d] not found pkind.%d vs num.%d RT.%d rdata.%p\n",i,pkind,rdata->numpkinds,bp->isRT,rdata);
            } else if ( coin->spendvectorsaved > 1 && bp != coin->current )
                printf("%s.[%d] skip null rdata isRT.%d\n",coin->symbol,i,bp->isRT);
        }
    }
    return(0);
}

int32_t iguana_uheight(struct iguana_info *coin,int32_t bundleheight,struct iguana_txid *T,int32_t numtxids,struct iguana_unspent *up)
{
    if ( up->txidind > 0 && up->txidind < numtxids )
        return(bundleheight + T[up->txidind].bundlei);
    else return(bundleheight);
}

int32_t iguana_datachain_scan(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t rmd160[20])
{
    int64_t deposits,crypto777_payment; uint32_t lastunspentind,unspentind; int32_t i,j,num,uheight; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata; struct iguana_pkhash *P,p; struct iguana_unspent *U,*u; struct iguana_txid *T,*tx;
    for (i=num=0; i<coin->bundlescount; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            ramchain = 0;
            if ( iguana_pkhashfind(coin,&ramchain,&deposits,&lastunspentind,&p,rmd160,i,i) != 0 )
            {
                if ( ramchain != 0 && (rdata= ramchain->H.data) != 0 )
                {
                    unspentind = lastunspentind;
                    U = RAMCHAIN_PTR(rdata,Uoffset);
                    T = RAMCHAIN_PTR(rdata,Toffset);
                    P = RAMCHAIN_PTR(rdata,Poffset);
                    while ( unspentind > 0 )
                    {
                        tx = &T[U[unspentind].txidind];
                        u = &U[tx->firstvout];
                        uheight = iguana_uheight(coin,ramchain->height,T,rdata->numtxids,u);
                        for (crypto777_payment=j=0; j<tx->numvouts; j++,u++)
                        {
                            //u = &U[tx->firstvout + j];
                            crypto777_payment = datachain_update(myinfo,0,coin,tx->timestamp,bp,P[u->pkind].rmd160,crypto777_payment,u->type,uheight,(((uint64_t)bp->hdrsi << 32) | unspentind),u->value,u->fileid,u->scriptpos,u->scriptlen,tx->txid,j);
                        }
                        num++;
                        unspentind = U[unspentind].prevunspentind;
                    }
                }
            }
        }
    }
    return(num);
}

int64_t iguana_pkhashbalance(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int64_t *spentp,int64_t *unspents,int32_t *nump,struct iguana_ramchain *ramchain,struct iguana_pkhash *p,uint32_t lastunspentind,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t hdrsi,int32_t lastheight,int32_t minconf,int32_t maxconf,char *remoteaddr)
{
    struct iguana_unspent *U; struct iguana_utxo *U2; int32_t max,uheight,spentheight; uint32_t pkind=0,unspentind; int64_t spent = 0,checkval,deposits = 0; struct iguana_txid *T; struct iguana_account *A2; struct iguana_ramchaindata *rdata = 0; int64_t RTspend = 0; //struct iguana_spend *S;
    max = *nump;
    *spentp = *nump = 0;
    if ( 0 && coin->RTramchain_busy != 0 )
    {
        printf("iguana_pkhashbalance: unexpected access when RTramchain_busy\n");
        return(0);
    }
    if ( ramchain->Uextras == 0 || (rdata= ramchain->H.data) == 0 )
    {
        if ( ramchain->height < (coin->bundlescount-1)*coin->chain->bundlesize )
        {
            //printf("iguana_pkhashbalance.[%d] %d: unexpected null spents.%p or rdata.%p\n",ramchain->height,(coin->bundlescount-1)*coin->chain->bundlesize,ramchain->Uextras,rdata);
        } else iguana_volatilesalloc(coin,ramchain,0);
        return(0);
    }
    unspentind = lastunspentind;
    U = RAMCHAIN_PTR(rdata,Uoffset);
    T = RAMCHAIN_PTR(rdata,Toffset);
    RTspend = 0;
    if ( lastheight == 0 )
        lastheight = IGUANA_MAXHEIGHT;
    while ( unspentind > 0 )
    {
        uheight = iguana_uheight(coin,ramchain->height,T,rdata->numtxids,&U[unspentind]);
        if ( lastheight <= 0 || uheight < lastheight )
        {
            deposits += U[unspentind].value;
            if ( iguana_spentflag(myinfo,coin,&RTspend,&spentheight,ramchain,hdrsi,unspentind,lastheight,minconf,maxconf,U[unspentind].value) == 0 )
            {
                if ( *nump < max && unspents != 0 )
                {
                    unspents[*nump << 1] = ((uint64_t)hdrsi << 32) | unspentind;
                    unspents[(*nump << 1) + 1] = U[unspentind].value;
                }
                //printf("+%.8f ",dstr(U[unspentind].value));
                (*nump)++;
                if ( array != 0 )
                    jaddi(array,iguana_unspentjson(myinfo,coin,hdrsi,unspentind,T,&U[unspentind],rmd160,coinaddr,pubkey33,spentheight,remoteaddr));
            }
            else
            {
                //printf("-%.8f ",dstr(U[unspentind].value));
                spent += U[unspentind].value;
            }
            if ( p->pkind != U[unspentind].pkind )
                printf("warning: [%d] p->pkind.%u vs U->pkind.%u for u%d\n",hdrsi,p->pkind,U[unspentind].pkind,unspentind);
        } // else printf("skip uheight.%d lastheight.%d\n",uheight,lastheight);
        pkind = p->pkind;
        unspentind = U[unspentind].prevunspentind;
    }
    if ( lastheight > 0 && (A2= ramchain->A2) != 0 && (U2= ramchain->Uextras) != 0 )
    {
        //S = RAMCHAIN_PTR(rdata,Soffset);
        unspentind = A2[pkind].lastunspentind;
        checkval = 0;
        while ( unspentind > 0 )
        {
            uheight = iguana_uheight(coin,ramchain->height,T,rdata->numtxids,&U[unspentind]);
            if ( uheight < lastheight )
            {
                checkval += U[unspentind].value;
                //printf("u%u %.8f spentflag.%d prev.%u fromheight.%d\n",unspentind,dstr(U[unspentind].value),U2[unspentind].spentflag,U2[unspentind].prevunspentind,U2[unspentind].fromheight);
            }
            unspentind = U2[unspentind].prevunspentind;
        }
        if ( 0 && llabs(spent - checkval - RTspend) > SMALLVAL )
            printf("spend %s: [%d] deposits %.8f spent %.8f check %.8f (%.8f) vs A2[%u] %.8f\n",lastheight==IGUANA_MAXHEIGHT?"checkerr":"",hdrsi,dstr(deposits),dstr(spent),dstr(checkval)+dstr(RTspend),dstr(*spentp),pkind,dstr(A2[pkind].total));
    }
    (*spentp) = spent;
    //printf("(%s) spent %.8f, RTspent %.8f deposits %.8f\n",coinaddr,dstr(spent),dstr(RTspend),dstr(deposits));
    return(deposits - spent);
}

int32_t iguana_pkhasharray(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,int64_t *totalp,struct iguana_pkhash *P,int32_t max,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t lastheight,int64_t *unspents,int32_t *numunspentsp,int32_t maxunspents,char *remoteaddr)
{
    int32_t i,n,m,numunspents; int64_t spent,deposits,netbalance,total; uint32_t lastunspentind; struct iguana_pkhash *p,_p; struct iguana_ramchain *ramchain; struct iguana_bundle *bp;
    if ( 0 && coin->RTramchain_busy != 0 )
    {
        printf("iguana_pkhasharray: unexpected access when RTramchain_busy\n");
        return(-1);
    }
    numunspents = numunspentsp != 0 ? *numunspentsp : 0;
    if ( lastheight == 0 )
        lastheight = IGUANA_MAXHEIGHT;
    if ( max > coin->bundlescount )
        max = coin->bundlescount;
    //printf("minconf.%d maxconf.%d max.%d addr.%s last.%d maxunspents.%d\n",minconf,maxconf,max,coinaddr,lastheight,maxunspents);
    for (total=n=i=0; i<max; i++)
    {
        if ( (bp= coin->bundles[i]) == 0 )
            continue;
        if ( 0 )
        {
            if ( lastheight > 0 && bp->bundleheight > lastheight )
            {
                //printf("lastheight.%d less than %d\n",lastheight,bp->bundleheight+bp->n);
                break;
            }
            if ( (coin->blocks.hwmchain.height - (bp->bundleheight + bp->n - 1)) > maxconf )
            {
                //printf("%d more than minconf.%d\n",(coin->blocks.hwmchain.height - (bp->bundleheight + bp->n - 1)),maxconf);
                continue;
            }
            if ( (coin->blocks.hwmchain.height - bp->bundleheight) < minconf )
            {
                //printf("%d less than minconf.%d\n",(coin->blocks.hwmchain.height - bp->bundleheight),minconf);
                break;
            }
        }
        if ( iguana_pkhashfind(coin,&ramchain,&deposits,&lastunspentind,P != 0 ? &P[n] : &_p,rmd160,i,i) != 0 )
        {
            m = maxunspents >> 1;
            p = (P == 0) ? &_p : &P[n];
            if ( (netbalance= iguana_pkhashbalance(myinfo,coin,array,&spent,unspents != 0 ? &unspents[numunspents << 1] : 0,&m,ramchain,p,lastunspentind,rmd160,coinaddr,pubkey33,i,lastheight,minconf,maxconf,remoteaddr)) != deposits-spent && lastheight == IGUANA_MAXHEIGHT && minconf == 1 && maxconf > coin->blocks.hwmchain.height )
            {
                printf("pkhash balance mismatch from m.%d check %.8f vs %.8f spent %.8f [%.8f]\n",m,dstr(netbalance),dstr(deposits),dstr(spent),dstr(deposits)-dstr(spent));
            }
            else
            {
                //printf("%s pkhash balance.[%d] from m.%d check %.8f vs %.8f spent %.8f [%.8f]\n",coinaddr,i,m,dstr(netbalance),dstr(deposits),dstr(spent),dstr(deposits)-dstr(spent));
                total += netbalance;
                n++;
            }
            if ( maxunspents > 0 )
            {
                maxunspents -= m;
                if ( maxunspents <= 0 )
                    break;
            }
            numunspents += m;
            //printf("%d: balance %.8f, lastunspent.%u m.%d num.%d max.%d\n",i,dstr(total),lastunspentind,m,numunspents,maxunspents);
        }
    }
    if ( numunspentsp != 0 )
        *numunspentsp = numunspents;
    //printf("numunspents.%d max.%d\n",numunspents,maxunspents);
    *totalp += total;
    return(n);
}

int64_t iguana_unspents(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,uint8_t *rmdarray,int32_t numrmds,int32_t lastheight,int64_t *unspents,int32_t *numunspentsp,char *remoteaddr)
{
    int64_t total=0,sum=0; struct iguana_pkhash *P; uint8_t *addrtypes,*pubkeys; int32_t i,numunspents,maxunspents,flag = 0; char coinaddr[64];
    //portable_mutex_lock(&coin->RTmutex);
    while ( 0 && coin->RTramchain_busy != 0 )
    {
        fprintf(stderr,"iguana_pkhasharray: %s unexpected access when RTramchain_busy\n",coin->symbol);
        sleep(1);
    }
    numunspents = 0;
    maxunspents = *numunspentsp;
    if ( rmdarray == 0 )
        rmdarray = iguana_walletrmds(myinfo,coin,&numrmds), flag++;
    if ( numrmds > 0 && rmdarray != 0 )
    {
        addrtypes = &rmdarray[numrmds * 20], pubkeys = &rmdarray[numrmds * 21];
        P = calloc(coin->bundlescount,sizeof(*P));
        for (i=0; i<numrmds; i++)
        {
            bitcoin_address(coinaddr,addrtypes[i],&rmdarray[i * 20],20);
            *numunspentsp = 0;
            iguana_pkhasharray(myinfo,coin,array,minconf,maxconf,&total,P,coin->bundlescount,&rmdarray[i * 20],coinaddr,&pubkeys[33*i],lastheight,&unspents[numunspents << 1],numunspentsp,maxunspents,remoteaddr);
            //printf("iguana_unspents: i.%d of %d: %s %.8f numunspents.%d\n",i,numrmds,coinaddr,dstr(total),*numunspentsp);
            maxunspents -= *numunspentsp;
            numunspents += *numunspentsp;
            sum += total;
        }
        //printf("sum %.8f\n",dstr(sum));
        free(P);
    }
    *numunspentsp = numunspents;
    if ( flag != 0 && rmdarray != 0 )
        free(rmdarray);
    //portable_mutex_unlock(&coin->RTmutex);
    return(sum);
}

uint8_t *iguana_rmdarray(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp,cJSON *array,int32_t firsti)
{
    int32_t i,n,flag=0,j=0; char *coinaddr,rmdstr[41]; uint8_t *addrtypes,*rmdarray = 0;
    *numrmdsp = 0;
    if ( array == 0 || cJSON_GetArraySize(array) == 0 )
        array = iguana_getaddressesbyaccount(myinfo,coin,"*");
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        *numrmdsp = n - firsti;
        rmdarray = calloc(1,(n-firsti) * (21 + 33));
        addrtypes = &rmdarray[(n-firsti) * 20];
        for (i=firsti; i<n; i++)
        {
            if ( (coinaddr= jstr(jitem(array,i),0)) != 0 )
            {
                bitcoin_addr2rmd160(&addrtypes[j],&rmdarray[20 * j],coinaddr);
                init_hexbytes_noT(rmdstr,&rmdarray[20 * j],20);
                //printf("(%s %s) ",coinaddr,rmdstr);
                j++;
            }
        }
        //printf("rmdarray[%d]\n",n);
    }
    if ( flag != 0 )
        free_json(array);
    return(rmdarray);
}

int64_t *iguana_PoS_weights(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_pkhash **Ptrp,int64_t *supplyp,int32_t *numacctsp,int32_t *nonzp,int32_t *errsp,int32_t lastheight)
{
    int64_t balance,total,supply,*weights=0; uint32_t pkind; int32_t numrmds,minconf,neg,numunspents,nonz,num=0; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; struct iguana_pkhash *refP; uint8_t rmd160[20],*rmdarray; cJSON *array; char coinaddr[64]; //struct iguana_account *A2; struct iguana_utxo *U2;
    *supplyp = 0;
    *numacctsp = *nonzp = 0;
    *errsp = 1;
    (*Ptrp) = 0;
    if ( (bp= coin->bundles[lastheight / coin->chain->bundlesize]) == 0 || bp == coin->current )
        return(0);
    if ( (rdata= bp->ramchain.H.data) == 0 )
        return(0);
    (*Ptrp) = refP = RAMCHAIN_PTR(rdata,Poffset);
    if ( (num= rdata->numpkinds) > 0 )
    {
        weights = calloc(num,sizeof(*weights));
        minconf = coin->blocks.hwmchain.height - lastheight;
        for (pkind=1; pkind<num; pkind++)
        {
            total = 0;
            memcpy(rmd160,refP[pkind].rmd160,sizeof(rmd160));
            array = cJSON_CreateArray();
            bitcoin_address(coinaddr,coin->chain->pubtype,rmd160,sizeof(rmd160));
            jaddistr(array,coinaddr);
            //bitcoin_address(coinaddr,coin->chain->p2shtype,rmd160,sizeof(rmd160));
            //jaddistr(array,coinaddr);
            if ( (rmdarray= iguana_rmdarray(myinfo,coin,&numrmds,array,0)) != 0 )
            {
                numunspents = 0;
                balance = iguana_unspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight,0,&numunspents,0);
                free(rmdarray);
                weights[pkind] += balance;
                if ( weights[pkind] != balance )
                    printf("PKIND.%d %s %.8f += %.8f\n",pkind,coinaddr,dstr(weights[pkind]),dstr(balance));
            }
            free_json(array);
        }
    }
    nonz = neg = 0;
    supply = 0;
    for (pkind=1; pkind<num; pkind++)
        if ( weights[pkind] != 0 )
        {
            nonz++;
            if ( weights[pkind] < 0 )
                neg++, weights[pkind] = 0;
            else supply += weights[pkind];
        }
    *numacctsp = num;
    *errsp = neg;
    *nonzp = nonz;
    *supplyp = supply;
    printf("ht.%d [%d] numaddrs.%d nonz.%d neg.%d supply %.8f\n",lastheight,lastheight/coin->chain->bundlesize,num,nonz,neg,dstr(supply));
    return(weights);
}

bits256 iguana_staker_hash2(bits256 refhash2,uint8_t *refrmd160,uint8_t *rmd160,int64_t weight)
{
    bits256 hash2;
    vcalc_sha256cat(hash2.bytes,refhash2.bytes,sizeof(refhash2),rmd160,20);
    return(mpz_div64(hash2,weight));
}

int _cmp_hashes(const void *a,const void *b)
{
#define hasha (*(bits256 *)a)
#define hashb (*(bits256 *)b)
    return(bits256_cmp(hasha,hashb));
#undef hasha
#undef hashb
}

int32_t iguana_staker_sort(struct iguana_info *coin,bits256 *hash2p,uint8_t *refrmd160,struct iguana_pkhash *refP,int64_t *weights,int32_t numweights,bits256 *sortbuf)
{
    int32_t i,j,n = 0; bits256 ind,refhash2 = *hash2p;
    memset(sortbuf,0,sizeof(*sortbuf) * 2 * numweights);
    for (i=0; i<numweights; i++)
    {
        if ( weights[i] > 0 )
        {
            memset(&ind,0,sizeof(ind));
            for (j=0; j<20; j++)
                ind.bytes[j] = refP[i].rmd160[j];
            ind.ulongs[3] = weights[i];
            ind.uints[5] = i;
            sortbuf[n << 1] = iguana_staker_hash2(refhash2,refrmd160,ind.bytes,weights[i]);
            sortbuf[(n << 1) + 1] = ind;
            n++;
        }
    }
    if ( n > 0 )
        qsort(sortbuf,n,sizeof(*sortbuf)*2,_cmp_hashes);
    vcalc_sha256cat(hash2p->bytes,refhash2.bytes,sizeof(refhash2),sortbuf[1].bytes,20);
    memcpy(refrmd160,sortbuf[1].bytes,20);
    {
        char str[65],coinaddr[64];
        bitcoin_address(coinaddr,coin->chain->pubtype,refrmd160,20);
        printf("winner.%s %.8f: %s\n",coinaddr,dstr(sortbuf[1].ulongs[3]),bits256_str(str,sortbuf[0]));
    }
    return((int32_t)sortbuf[1].uints[5]);
}

int32_t iguana_unspent_check(struct supernet_info *myinfo,struct iguana_info *coin,uint16_t hdrsi,uint32_t unspentind)
{
    bits256 txid; int32_t vout,spentheight;
    memset(&txid,0,sizeof(txid));
    if ( iguana_unspentind2txid(myinfo,coin,&spentheight,&txid,&vout,hdrsi,unspentind) == 0 )
    {
        //char str[65]; printf("verify %s/v%d is not already used\n",bits256_str(str,txid),vout);
        if ( basilisk_addspend(myinfo,coin->symbol,txid,vout,0) != 0 )
        {
            char str[65]; printf("iguana_unspent_check found unspentind (%u %d) %s\n",hdrsi,unspentind,bits256_str(str,txid));
            return(1);
        } else return(0);
    }
    printf("iguana_unspent_check: couldnt find (%d %d)\n",hdrsi,unspentind);
    return(-1);
}

int32_t iguana_addr_unspents(struct supernet_info *myinfo,struct iguana_info *coin,int64_t *sump,int64_t *unspents,int32_t max,char *coinaddr,char *remoteaddr,int32_t lastheight)
{
    int32_t n,k,numunspents,minconf = 0; int64_t total; uint8_t rmd160[20],pubkey[65],addrtype;
    total = 0;
    n = numunspents = 0;
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    iguana_pkhasharray(myinfo,coin,0,minconf,coin->longestchain,&total,0,coin->bundlescount,rmd160,coinaddr,pubkey,lastheight,unspents,&n,max-1000,remoteaddr);
    /*if ( n > 0 )
    {
        candidates = unspents;
        for (j=0; j<n; j++)
        {
            hdrsi = (int32_t)(candidates[j << 1] >> 32);
            unspentind = (int32_t)candidates[j << 1];
            if ( iguana_unspent_check(myinfo,coin,hdrsi,unspentind) == 0 )
            {
                //printf("(%d u%d) %.8f not in mempool\n",hdrsi,unspentind,dstr(candidates[(j << 1) + 1]));
                //for (k=0; k<numunspents; k++)
                //    if ( &unspents[k<<1] != &candidates[j<<1] && unspents[k << 1] == candidates[j << 1] )
                //        break;
                //if ( k == numunspents )
                {
                    //unspents[numunspents << 1] = candidates[j << 1];
                    //unspents[(numunspents << 1) + 1] = candidates[(j << 1) + 1];
                    printf("[%d u%d %.8f] ",hdrsi,unspentind,dstr(unspents[(numunspents << 1) + 1]));
                    (*sump) += unspents[(numunspents << 1) + 1];
                    unspents += 2;
                    numunspents++;
                } else printf("found duplicate unspent j.%d numunspents.%d\n",j,numunspents);
            } else printf("found spent unspent j.%d numunspents.%d\n",j,numunspents);
        }
    }*/
    numunspents = n;
    for (k=0; k<n; k++)
        (*sump) += unspents[(k << 1) + 1];
    return(numunspents);
}

int32_t iguana_unspentslists(struct supernet_info *myinfo,struct iguana_info *coin,int64_t *totalp,int64_t *unspents,int32_t max,int64_t required,int32_t minconf,cJSON *addresses,char *remoteaddr)
{
    int64_t sum = 0; int32_t k,i,j,r,numunspents,numaddrs; uint8_t pubkey[65]; char *coinaddr,str[65]; struct iguana_waddress *waddr; struct iguana_waccount *wacct; struct basilisk_unspent *bu;
    *totalp = 0;
    if ( (numaddrs= cJSON_GetArraySize(addresses)) == 0 )
    {
        printf("null addresses.(%s)\n",jprint(addresses,0));
        return(0);
    }
    memset(pubkey,0,sizeof(pubkey));
    //remains = required * 1.1 + coin->txfee;
    for (i=numunspents=0; i<numaddrs; i++)
    {
        if ( (coinaddr= jstri(addresses,i)) != 0 )
        {
            //printf("i.%d coinaddr.(%s) minconf.%d longest.%d diff.%d\n",i,coinaddr,minconf,coin->longestchain,coin->blocks.hwmchain.height - minconf);
            if ( coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 )
            {
                numunspents = iguana_addr_unspents(myinfo,coin,&sum,unspents,max,coinaddr,remoteaddr,coin->blocks.hwmchain.height - minconf);
            }
            else
            {
                if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 && waddr->numunspents > 0 )
                {
                    r = (rand() % waddr->numunspents);
                    for (j=0; j<waddr->numunspents; j++)
                    {
                        i = ((j + r) % waddr->numunspents);
                        bu = &waddr->unspents[i];
                        if ( basilisk_addspend(myinfo,coin->symbol,bu->txid,bu->vout,0) == 0 )
                        {
                            for (k=0; k<numunspents; k++)
                            {
                                // filterout duplicates here
                            }
                            unspents[0] = ((uint64_t)bu->hdrsi << 32) | bu->unspentind;
                            unspents[1] = bu->value;
                            sum += bu->value;
                            printf("ADD unspent, mark spent\n");
                            basilisk_addspend(myinfo,coin->symbol,bu->txid,bu->vout,1);
                            unspents++;
                            numunspents++;
                        } else printf("skip pending txid.%s/v%d\n",bits256_str(str,bu->txid),bu->vout);
                    }
                }
            }
            if ( numunspents > max || sum > required )
                break;
            //printf("n.%d max.%d total %.8f\n",n,max,dstr(total));
        }
    }
    *totalp = sum;
    return(numunspents);
}

int32_t iguana_uvaltxid(struct supernet_info *myinfo,bits256 *txidp,struct iguana_info *coin,int16_t hdrsi,uint32_t unspentind)
{
    struct iguana_bundle *bp; struct iguana_unspent *U,*u; struct iguana_txid *T; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata;
    if ( (bp= coin->bundles[hdrsi]) == 0 )
        return(-1);
    ramchain = (bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
    if ( (rdata= ramchain->H.data) != 0 )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        T = RAMCHAIN_PTR(rdata,Toffset);
        if ( unspentind > 0 && unspentind < rdata->numunspents )
        {
            u = &U[unspentind];
            if ( u->txidind > 0 && u->txidind < rdata->numtxids )
            {
                *txidp = T[u->txidind].txid;
                return(unspentind - T[u->txidind].firstvout);
            }
        }
    }
    return(-1);
}

int64_t iguana_unspentavail(struct supernet_info *myinfo,struct iguana_info *coin,uint64_t hdrsi_unspentind,int32_t minconf,int32_t maxconf)
{
    struct iguana_ramchain *ramchain; struct iguana_bundle *bp; int64_t RTspend; int32_t hdrsi,spentheight,spentflag; struct iguana_unspent *U,*u; uint32_t unspentind; struct iguana_ramchaindata *rdata;
    if ( (bp= coin->bundles[hdrsi_unspentind>>32]) == 0 )
        return(-1);
    hdrsi = (int16_t)(hdrsi_unspentind >> 32);
    unspentind = (uint32_t)hdrsi_unspentind;
    ramchain = (bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
    if ( (rdata= ramchain->H.data) == 0 )
        return(0);
    if ( (spentflag= iguana_spentflag(myinfo,coin,&RTspend,&spentheight,ramchain,hdrsi,unspentind,0,minconf,maxconf,0)) > 0 )
    {
        printf("[%d].u%d was already spent ht.%d\n",bp->hdrsi,(uint32_t)unspentind,spentheight);
        return(-1);
    }
    else if ( spentflag == 0 )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        if ( unspentind > 0 && unspentind < rdata->numunspents )
        {
            u = &U[unspentind];
            return(u->value);
        }
        else
        {
            printf("illegal unspentind.%u vs %u [%d]\n",unspentind,rdata->numunspents,bp->hdrsi);
            return(-2);
        }
    }
    else return(0);
}

#define UTXOADDR_ITEMSIZE 32
#define iguana_utxotable_numinds(ind) (((ind) == 0xffff) ? coin->utxoaddrlastcount : (coin->utxoaddroffsets[(ind) + 1] - coin->utxoaddroffsets[ind]))

int32_t iguana_rwutxoaddr(int32_t rwflag,uint16_t ind,uint8_t *serialized,struct iguana_utxoaddr *utxoaddr)
{
    uint32_t pkind=0; int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[0],sizeof(utxoaddr->hdrsi),&utxoaddr->hdrsi);
    if ( rwflag == 0 )
    {
        utxoaddr->rmd160[0] = (ind & 0xff);
        utxoaddr->rmd160[1] = ((ind >> 8) & 0xff);
        memcpy(&utxoaddr->rmd160[2],&serialized[2],18);
    } else memcpy(&serialized[2],&utxoaddr->rmd160[2],18);
    len += 18;
    if ( rwflag != 0 )
        pkind = utxoaddr->pkind;
    len += iguana_rwnum(rwflag,&serialized[20],sizeof(pkind),&pkind);
    if ( rwflag == 0 )
        utxoaddr->pkind = pkind;
    len += iguana_rwnum(rwflag,&serialized[24],sizeof(utxoaddr->histbalance),&utxoaddr->histbalance);
    return(len);
}

int64_t iguana_utxoaddrtablefind(struct iguana_info *coin,int16_t search_hdrsi,uint32_t search_pkind,uint8_t rmd160[20])
{
    struct iguana_utxoaddr UA; int32_t ind,num,i; uint8_t *ptr;
    memset(&UA,0,sizeof(UA));
    ind = rmd160[0] + ((int32_t)rmd160[1] << 8);
    if ( (num= iguana_utxotable_numinds(ind)) > 0 )
    {
        for (i=0; i<num; i++)
        {
            ptr = &coin->utxoaddrtable[(coin->utxoaddroffsets[ind] + i) * UTXOADDR_ITEMSIZE];
            iguana_rwutxoaddr(0,ind,ptr,&UA);
            if ( (UA.pkind == search_pkind && UA.hdrsi == search_hdrsi) || memcmp(UA.rmd160,rmd160,20) == 0 )
                return(UA.histbalance);
        }
        printf("ind.%04x no [%d] p%u after num.%d\n",ind,search_hdrsi,search_pkind,num);
    }
    return(0);
}

struct iguana_utxoaddr *iguana_utxoaddrfind(int32_t createflag,struct iguana_info *coin,int16_t hdrsi,uint32_t pkind,uint8_t rmd160[20],struct iguana_utxoaddr **prevp)
{
    struct iguana_utxoaddr *utxoaddr; char coinaddr[64];
    HASH_FIND(hh,coin->utxoaddrs,rmd160,sizeof(utxoaddr->rmd160),utxoaddr);
    if ( utxoaddr == 0 && createflag != 0 )
    {
        utxoaddr = calloc(1,sizeof(*utxoaddr));
        ++coin->utxoaddrind;
        utxoaddr->hdrsi = hdrsi;
        utxoaddr->pkind = pkind;
        if ( coin->utxoaddrtable != 0 && coin->utxoaddroffsets != 0 )
        {
            utxoaddr->searchedhist = 1;
            utxoaddr->histbalance = iguana_utxoaddrtablefind(coin,hdrsi,pkind,rmd160);
        }
        memcpy(utxoaddr->rmd160,rmd160,sizeof(utxoaddr->rmd160));
        HASH_ADD_KEYPTR(hh,coin->utxoaddrs,utxoaddr->rmd160,sizeof(utxoaddr->rmd160),utxoaddr);
        if ( prevp != 0 )
        {
            utxoaddr->hh.prev = *prevp;
            if ( *prevp != 0 )
                (*prevp)->hh.next = utxoaddr;
            *prevp = utxoaddr;
        }
        HASH_FIND(hh,coin->utxoaddrs,rmd160,sizeof(utxoaddr->rmd160),utxoaddr);
        if ( utxoaddr == 0 )
        {
            int32_t i; for (i=0; i<20; i++)
                printf("%02x",utxoaddr->rmd160[i]);
            bitcoin_address(coinaddr,coin->chain->pubtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
            printf(" %d of %d: %s %.8f\n",coin->utxoaddrind,coin->utxodatasize,coinaddr,dstr(utxoaddr->histbalance));
            printf("failed to find just added %d of %d\n",coin->utxoaddrind,coin->utxodatasize);
        }
    }
    return(utxoaddr);
}

int64_t iguana_bundle_unspents(struct iguana_info *coin,struct iguana_bundle *bp,int32_t maketable,struct iguana_utxoaddr **prevp)
{
    struct iguana_utxoaddr *utxoaddr; uint32_t unspentind,pkind; struct iguana_ramchaindata *rdata=0; struct iguana_pkhash *P; struct iguana_unspent *U; struct iguana_utxo *U2=0; int64_t value,balance = 0;
    if ( bp == 0 || (rdata= bp->ramchain.H.data) == 0 || (U2= bp->ramchain.Uextras) == 0 )
    {
        printf("missing ptr bp.%p rdata.%p U2.%p\n",bp,rdata,U2);
        return(0);
    }
    U = RAMCHAIN_PTR(rdata,Uoffset);
    P = RAMCHAIN_PTR(rdata,Poffset);
    for (unspentind=1; unspentind<rdata->numunspents; unspentind++)
    {
        value = U[unspentind].value;
        //printf("[%d] u%d: (p%u %.8f) from.%d lock.%d prev.%u spent.%d\n",bp->hdrsi,unspentind,U[unspentind].pkind,dstr(value),U2[unspentind].fromheight,U2[unspentind].lockedflag,U2[unspentind].prevunspentind,U2[unspentind].spentflag);
        if ( U2[unspentind].fromheight == 0 && U2[unspentind].lockedflag == 0 && U2[unspentind].prevunspentind == 0 && U2[unspentind].spentflag == 0 && value != 0 )
        {
            if ( value <= 0 )
                printf("[%d] u%u negative value %.8f??\n",bp->hdrsi,unspentind,dstr(value));
            else
            {
                balance += value;
                if ( maketable != 0 )
                {
                    if ( (pkind= U[unspentind].pkind) < rdata->numpkinds && pkind > 0 )
                    {
                        if ( (utxoaddr= iguana_utxoaddrfind(1,coin,bp->hdrsi,pkind,P[pkind].rmd160,prevp)) != 0 )
                        {
                            //printf("%.8f ",dstr(value));
                            utxoaddr->histbalance += value;
                        }
                        else printf("cant find pkind.%u for unspentind.%u hdrsi.%d\n",pkind,unspentind,bp->hdrsi);
                    } else printf("illegal pkind.%u for unspentind.%u hdrsi.%d\n",pkind,unspentind,bp->hdrsi);
                }
            }
        } // else printf("[%d] u%u spent %.8f\n",bp->hdrsi,unspentind,dstr(value));
    }
    return(balance);
}

static int _utxoaddr_cmp(const void *a,const void *b)
{
#define item_a ((uint8_t *)a)
#define item_b ((uint8_t *)b)
    uint16_t hdrsi_a,hdrsi_b; uint32_t pkind_a,pkind_b;
    iguana_rwnum(0,&item_a[0],sizeof(hdrsi_a),&hdrsi_a);
    iguana_rwnum(0,&item_a[20],sizeof(pkind_a),&pkind_a);
    iguana_rwnum(0,&item_b[0],sizeof(hdrsi_b),&hdrsi_b);
    iguana_rwnum(0,&item_b[20],sizeof(pkind_b),&pkind_b);
	if ( hdrsi_b > hdrsi_a )
		return(1);
	else if ( hdrsi_b < hdrsi_a )
		return(-1);
    else
    {
        if ( pkind_b > pkind_a )
            return(1);
        else if ( pkind_b < pkind_a )
            return(-1);
        else return(0);
    }
#undef item_a
#undef item_b
}

void iguana_utxoaddr_purge(struct iguana_info *coin)
{
    struct iguana_utxoaddr *utxoaddr,*tmp;
    if ( coin->utxoaddrs != 0 )
    {
        printf("free %s utxoaddrs\n",coin->symbol);
        HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
        {
            if ( utxoaddr != 0 )
            {
                HASH_DELETE(hh,coin->utxoaddrs,utxoaddr);
                free(utxoaddr);
            }
        }
        coin->utxoaddrs = 0;
    }
}

int32_t iguana_utxoaddr_save(struct iguana_info *coin,char *fname,int64_t balance,uint32_t *counts,uint32_t *offsets,uint8_t *table)
{
    FILE *fp; bits256 hash; int32_t retval = -1;
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(&balance,1,sizeof(balance),fp);
        fwrite(&counts[0xffff],1,sizeof(counts[0xffff]),fp);
        fwrite(&coin->utxoaddrind,1,sizeof(coin->utxoaddrind),fp);
        vcalc_sha256cat(hash.bytes,(void *)offsets,(int32_t)(0x10000 * sizeof(*offsets)),table,(int32_t)((coin->utxoaddrind+1) * UTXOADDR_ITEMSIZE));
        if ( fwrite(hash.bytes,1,sizeof(hash),fp) == sizeof(hash) )
        {
            if ( fwrite(offsets,1,0x10000 * sizeof(*offsets),fp) == 0x10000 * sizeof(*offsets) )
            {
                if ( fwrite(table,1,(coin->utxoaddrind+1) * UTXOADDR_ITEMSIZE,fp) != (coin->utxoaddrind+1) * UTXOADDR_ITEMSIZE )
                    printf("error writing %s table\n",fname);
                else retval = 0;
            } else printf("error writing %s offsets\n",fname);
        } else printf("error writing %s hash\n",fname);
        fclose(fp);
    } else printf("error creating %s\n",fname);
    return(retval);
}

int32_t iguana_utxoaddr_map(struct iguana_info *coin,char *fname)
{
    uint32_t ind,total=0,offset,size=0,last=0,lastcount=0,count,prevoffset=0;
    if ( (coin->utxoaddrfileptr= OS_mapfile(fname,&coin->utxoaddrfilesize,0)) != 0 && coin->utxoaddrfilesize > sizeof(bits256)+0x10000*sizeof(*coin->utxoaddroffsets) )
    {
        memcpy(&coin->histbalance,coin->utxoaddrfileptr,sizeof(coin->histbalance));
        memcpy(&coin->utxoaddrlastcount,(void *)((long)coin->utxoaddrfileptr+sizeof(int64_t)),sizeof(coin->utxoaddrlastcount));
        memcpy(&coin->utxoaddrind,(void *)((long)coin->utxoaddrfileptr+sizeof(int64_t)+sizeof(uint32_t)),sizeof(coin->utxoaddrind));
        coin->utxoaddroffsets = (void *)((long)coin->utxoaddrfileptr + sizeof(int64_t) + 2*sizeof(uint32_t) + sizeof(bits256));
        for (ind=total=count=0; ind<0x10000; ind++)
        {
            if ( (offset= coin->utxoaddroffsets[ind]) != 0 )
            {
                count = offset - prevoffset;
                prevoffset = offset;
                total += count;
            }
        }
        size = (uint32_t)((total+1)*UTXOADDR_ITEMSIZE);
        size += sizeof(int64_t) + 2*sizeof(uint32_t) + sizeof(bits256);
        size += 0x10000 * sizeof(*coin->utxoaddroffsets);
        if ( size <= coin->utxoaddrfilesize )
        {
            lastcount = (uint32_t)(coin->utxoaddrfilesize - size);
            if ( (lastcount % UTXOADDR_ITEMSIZE) == 0 )
            {
                lastcount /= UTXOADDR_ITEMSIZE;
                coin->utxoaddrlastcount = lastcount;
                coin->utxoaddrtable = (void *)&coin->utxoaddroffsets[0x10000];
                //iguana_utxoaddr_purge(coin);
            }
        }
    }
    printf("%.8f LASTCOUNT %d vs total %d, last %d vs lastcount %d, size.%d %ld\n",dstr(coin->histbalance),coin->utxoaddrlastcount,total,last,lastcount,size,coin->utxoaddrfilesize);
    return(total + 1 + lastcount);
}

int32_t iguana_utxoaddr_check(struct supernet_info *myinfo,struct iguana_info *coin,int32_t lastheight,int64_t *unspents,int32_t max,struct iguana_utxoaddr *utxoaddr)
{
    static int32_t good,bad;
    char coinaddr[64]; int64_t sum,checkbalance; int32_t iter,i,numunspents = 0;
    sum = 0;
    for (iter=0; iter<2; iter++)
    {
        bitcoin_address(coinaddr,iter == 0 ? coin->chain->pubtype : coin->chain->p2shtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
        numunspents += iguana_addr_unspents(myinfo,coin,&sum,&unspents[numunspents],max-numunspents,coinaddr,0,lastheight);
        if ( sum == utxoaddr->histbalance )
        {
            checkbalance = iguana_utxoaddrtablefind(coin,0,0,utxoaddr->rmd160);
            if ( checkbalance != sum )
                printf("%s checkbalance %.8f vs sum %.8f\n",coinaddr,dstr(checkbalance),dstr(sum));
            break;
        }
    }
    if ( sum != utxoaddr->histbalance || checkbalance != sum )
    {
        bad++;
        for (i=0; i<numunspents; i++)
            printf("(%lld %lld %.8f) ",(long long)(unspents[i<<1]>>32)&0xffffffff,(long long)unspents[i<<1]&0xffffffff,dstr(unspents[(i<<1)+1]));
        for (i=0; i<20; i++)
            printf("%02x",utxoaddr->rmd160[i]);
        bitcoin_address(coinaddr,coin->chain->pubtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
        printf(" %s: sum %.8f != %.8f numunspents.%d diff %.8f\n",coinaddr,dstr(sum),dstr(utxoaddr->histbalance),numunspents,dstr(utxoaddr->histbalance)-dstr(sum));
        return(-1);
    }
    good++;
    if ( ((good + bad) % 1000) == 0 )
        printf("utxoaddr validate good.%d bad.%d\n",good,bad);
    return(0);
}

int32_t iguana_utxoaddr_validate(struct supernet_info *myinfo,struct iguana_info *coin,int32_t lastheight)
{
    int64_t *unspents; uint8_t *item; struct iguana_bundle *bp; struct iguana_utxoaddr UA; int32_t i,num,max,ind,total,errs=0;
    if ( coin->utxoaddrtable == 0 )
    {
        printf("no utxoaddrtable to validate?\n");
        return(-1);
    }
    for (i=0; i<coin->bundlescount; i++)
        if ( (bp= coin->bundles[i]) != 0 && bp != coin->current )
        {
            iguana_volatilespurge(coin,&bp->ramchain);
            /*sprintf(fname,"%s/%s/accounts/debits.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
            OS_removefile(fname,0);
            sprintf(fname,"%s/%s/accounts/lastspends.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
            OS_removefile(fname,0);*/
            iguana_volatilesmap(coin,&bp->ramchain);
        }
    total = 0;
    max = 1024 * 1024;
    if ( strcmp("BTC",coin->symbol) == 0 )
        max *= 1024;
    unspents = calloc(1,max);
    max /= sizeof(*unspents);
    memset(&UA,0,sizeof(UA));
    for (ind=0; ind<0x10000; ind++)
    {
        if ( (num= iguana_utxotable_numinds(ind)) > 0 )
        {
            for (i=0; i<num; i++)
            {
                item = &coin->utxoaddrtable[(coin->utxoaddroffsets[ind] + i) * UTXOADDR_ITEMSIZE];
                iguana_rwutxoaddr(0,ind,item,&UA);
                errs += iguana_utxoaddr_check(myinfo,coin,lastheight,unspents,max,&UA);
                total++;
                if ( (total % 10000) == 0 )
                    fprintf(stderr,".");
            }
        }
    }
    free(unspents);
    return(errs);
}

int64_t iguana_utxoaddr_gen(struct supernet_info *myinfo,struct iguana_info *coin,int32_t maxheight)
{
    char fname[1024],fname2[1024],coinaddr[64],checkaddr[64]; struct iguana_utxoaddr *utxoaddr,UA,*tmp,*last=0; uint16_t hdrsi; uint8_t *table,item[UTXOADDR_ITEMSIZE]; uint32_t *counts,*offsets,offset,n; int32_t errs,height=0,j,k,ind,tablesize=0; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata=0; int64_t checkbalance=0,balance = 0;
    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
    {
        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight )
            height = bp->bundleheight + bp->n;
    }
    sprintf(fname2,"%s/%s/utxoaddrs.%d",GLOBAL_DBDIR,coin->symbol,height), OS_portable_path(fname2);
    if ( iguana_utxoaddr_map(coin,fname2) != 0 )
    {
        errs = 0;//iguana_utxoaddr_validate(myinfo,coin,height);
        printf("HIST BALANCE %.8f errs %d\n",dstr(coin->histbalance),errs);
        if ( coin->histbalance > 0 )
            return(coin->histbalance);
    }
    printf("utxoaddr_gen.%d\n",maxheight);
    iguana_utxoaddr_purge(coin);
    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight && (rdata= bp->ramchain.H.data) != 0 )
        {
            tablesize += rdata->numpkinds;
        }
    printf("allocate UTXOADDRS[%d]\n",tablesize);
    coin->utxodatasize = tablesize;
    coin->utxoaddrind = 0;
    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
    {
        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight )
        {
            balance += iguana_bundle_unspents(coin,bp,1,&last);
            fprintf(stderr,"(%d %.8f) ",hdrsi,dstr(balance));
            height = bp->bundleheight + bp->n;
        }
    }
    sprintf(fname,"%s/%s/utxoaddrs",GLOBAL_DBDIR,coin->symbol), OS_portable_path(fname);
    fprintf(stderr,"%d bundles for iguana_utxoaddr_gen.[%d] max.%d ht.%d\n",hdrsi,coin->utxoaddrind,coin->utxodatasize,maxheight);
    counts = calloc(0x10000,sizeof(*counts));
    HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
    {
        if ( utxoaddr->histbalance > 0 )
        {
            checkbalance += utxoaddr->histbalance;
            ind = utxoaddr->rmd160[0] + ((int32_t)utxoaddr->rmd160[1] << 8);
            counts[ind]++;
        } else printf("error neg or zero balance %.8f\n",dstr(utxoaddr->histbalance));
    }
    printf("checkbalance %.8f vs %.8f\n",dstr(checkbalance),dstr(balance));
    if ( checkbalance == balance )
    {
        table = calloc(coin->utxoaddrind+1,UTXOADDR_ITEMSIZE);
        offsets = calloc(0x10000,sizeof(*offsets));
        offset = 0;
        for (ind=0; ind<0x10000; ind++)
        {
            n = counts[ind];
            offsets[ind] = offset;
            counts[ind] = 0;
            offset += n;
        }
        HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
        {
            if ( utxoaddr->histbalance > 0 )
            {
                bitcoin_address(coinaddr,coin->chain->pubtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
                memset(item,0,UTXOADDR_ITEMSIZE);
                ind = utxoaddr->rmd160[0] + ((int32_t)utxoaddr->rmd160[1] << 8);
                iguana_rwutxoaddr(1,ind,item,utxoaddr);
                memcpy(&table[(offsets[ind] + counts[ind]) * UTXOADDR_ITEMSIZE],item,UTXOADDR_ITEMSIZE);
                iguana_rwutxoaddr(0,ind,&table[(offsets[ind] + counts[ind]) * UTXOADDR_ITEMSIZE],&UA);
                iguana_rwutxoaddr(1,ind,item,&UA);
                bitcoin_address(checkaddr,coin->chain->pubtype,UA.rmd160,sizeof(UA.rmd160));
                if ( strcmp(checkaddr,coinaddr) != 0 )
                    printf("rw coinaddr error %s != %s\n",coinaddr,checkaddr);
                //else printf("ind.%04x %s %.8f %.8f %d\n",ind,coinaddr,dstr(UA.histbalance),dstr(utxoaddr->histbalance),counts[ind]);
                if ( memcmp(&table[(offsets[ind] + counts[ind]) * UTXOADDR_ITEMSIZE],item,UTXOADDR_ITEMSIZE) != 0 )
                    printf("rwutxoaddr cmp error\n");
                counts[ind]++;
            } else printf("error neg or zero balance %.8f\n",dstr(utxoaddr->histbalance));
        }
        offset = 1;
        for (ind=0; ind<0x10000; ind++)
            offset += counts[ind];
        if ( offset == coin->utxoaddrind+1 )
        {
            for (ind=0; ind<0x10000; ind++)
            {
                if ( counts[ind] > 0 )
                {
                    qsort(&table[offsets[ind] * UTXOADDR_ITEMSIZE],counts[ind],UTXOADDR_ITEMSIZE,_utxoaddr_cmp);
continue;
                    for (j=0; j<counts[ind]; j++)
                    {
                        iguana_rwutxoaddr(0,ind,&table[(offsets[ind]+j) * UTXOADDR_ITEMSIZE],&UA);
                        for (k=0; k<20; k++)
                            printf("%02x",UA.rmd160[k]);
                        bitcoin_address(coinaddr,coin->chain->pubtype,UA.rmd160,sizeof(UA.rmd160));
                        printf(" [%4d] p%-5d %12.8f ind.%04x %d %s\n",UA.hdrsi,UA.pkind,dstr(UA.histbalance),ind,j,coinaddr);
                    }
                }
            }
            if ( iguana_utxoaddr_save(coin,fname,balance,counts,offsets,table) == 0 )
            {
                if ( OS_copyfile(fname,fname2,1) < 0 )
                    printf("error copying file %s to %s\n",fname,fname2);
                else
                {
                    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
                    {
                        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight )
                            bp->balancefinish = (uint32_t)time(NULL);
                    }
                }
            } else printf("error saving %s\n",fname);
        } else printf("table has %d vs %d\n",offset,coin->utxoaddrind+1);
        free(offsets);
        free(table);
        iguana_utxoaddr_purge(coin);
        if ( iguana_utxoaddr_map(coin,fname) != 0 )
        {
            errs = iguana_utxoaddr_validate(myinfo,coin,height);
            printf("%s HIST BALANCE %.8f errs %d\n",fname,dstr(coin->histbalance),errs);
            if ( errs != 0 )
            {
                printf("delete bad utxoaddr files\n");
                OS_removefile(fname,0);
                OS_removefile(fname2,0);
            }
            return(coin->histbalance);
        }
    }
    coin->histbalance = balance;
    free(counts);
    return(balance);
}

void iguana_utxoaddrs_purge(struct iguana_info *coin)
{
    struct iguana_utxoaddr *utxoaddr,*tmp;
    coin->RTdebits = coin->RTdebits = 0;
    HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
    {
        if ( utxoaddr != 0 )
            utxoaddr->RTcredits = utxoaddr->RTdebits = 0;
    }
}
