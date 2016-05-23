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

int32_t iguana_unspentindfind(struct iguana_info *coin,char *coinaddr,uint8_t *spendscript,int32_t *spendlenp,uint64_t *valuep,int32_t *heightp,bits256 txid,int32_t vout,int32_t lasthdrsi)
{
    struct iguana_txid *tp,TX; struct iguana_pkhash *P; struct iguana_unspent *U; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; int64_t RTspend; int32_t pkind,hdrsi,firstvout,spentheight,unspentind = -1;
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
        //U = (void *)(long)((long)rdata + rdata->Uoffset);
        //P = (void *)(long)((long)rdata + rdata->Poffset);
        pkind = U[unspentind].pkind;
        if ( pkind > 0 && pkind < rdata->numpkinds )
        {
            RTspend = 0;
            if ( iguana_spentflag(coin,&RTspend,&spentheight,bp == coin->current ? &coin->RTramchain : &bp->ramchain,bp->hdrsi,unspentind,0,1,coin->longestchain,U[unspentind].value) == 0 )
            {
                if ( valuep != 0 )
                    *valuep = U[unspentind].value;
                bitcoin_address(coinaddr,iguana_addrtype(coin,U[unspentind].type),P[pkind].rmd160,sizeof(P[pkind].rmd160));
                if ( spendscript != 0 && spendlenp != 0 )
                    *spendlenp = iguana_voutscript(coin,bp,spendscript,0,&U[unspentind],&P[pkind],1);
            }
        }
    }
    return(unspentind);
}

char *iguana_inputaddress(struct iguana_info *coin,char *coinaddr,int16_t *spent_hdrsip,uint32_t *unspentindp,cJSON *vinobj)
{
    bits256 txid; int32_t vout,checkind,height;
    *unspentindp = 0;
    *spent_hdrsip = -1;
    if ( jobj(vinobj,"txid") != 0 && jobj(vinobj,"vout") != 0 )
    {
        txid = jbits256(vinobj,"txid");
        vout = jint(vinobj,"vout");
        if ( (checkind= iguana_unspentindfind(coin,coinaddr,0,0,0,&height,txid,vout,coin->bundlescount-1)) > 0 )
        {
            *spent_hdrsip = (height / coin->chain->bundlesize);
            *unspentindp = checkind;
            return(coinaddr);
        }
        else
        {
            char str[65];
            printf("error finding (%s/%d)\n",bits256_str(str,txid),vout);
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

cJSON *iguana_unspentjson(struct supernet_info *myinfo,struct iguana_info *coin,int32_t hdrsi,uint32_t unspentind,struct iguana_txid *T,struct iguana_unspent *up,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33)
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
    if ( (checkind= iguana_unspentindfind(coin,0,0,0,0,&height,T[up->txidind].txid,up->vout,coin->bundlescount-1)) != 0 )
    {
        jaddnum(item,"confirmations",coin->blocks.hwmchain.height - height + 1);
        jaddnum(item,"checkind",checkind);
    }
    if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,coinaddr)) != 0 )
    {
        jaddstr(item,"account",wacct->account);
        jadd(item,"spendable",jtrue());
    } else jadd(item,"spendable",jfalse());
    jadd(item,"unspent",ramchain_unspentjson(up,unspentind));
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
            ramchain = (bp != coin->current) ? &bp->ramchain : &coin->RTramchain;
            if ( (rdata= ramchain->H.data) != 0 )
            {
                numpkinds = rdata->numpkinds;
                PKbits = RAMCHAIN_PTR(rdata,PKoffset);
                P = RAMCHAIN_PTR(rdata,Poffset);
                //PKbits = (void *)(long)((long)rdata + rdata->PKoffset);
                //P = (void *)(long)((long)rdata + rdata->Poffset);
                if ( bp == coin->current )
                    ACCTS = ramchain->A;
                else ACCTS = RAMCHAIN_PTR(rdata,Aoffset);
                //ACCTS = (void *)(long)((long)rdata + rdata->Aoffset);
                if ( (pkind= iguana_sparseaddpk(PKbits,rdata->pksparsebits,rdata->numpksparse,rmd160,P,0,ramchain)) > 0 && pkind < numpkinds )
                {
                    *ramchainp = ramchain;
                    *depositsp = ACCTS[pkind].total;
                    *lastunspentindp = ACCTS[pkind].lastunspentind;
                    //printf("[%d] return pkind.%u of %u P.%p %.8f last.%u ACCTS.%p %p\n",i,pkind,numpkinds,P,dstr(*depositsp),*lastunspentindp,ACCTS,ramchain->A);
                    if ( P != 0 )
                        *p = P[pkind];
                    return(p);
                }
                else if ( pkind != 0 )
                    printf("[%d] not found pkind.%d vs num.%d RT.%d rdata.%p\n",i,pkind,rdata->numpkinds,bp->isRT,rdata);
            } else printf("%s.[%d] error null rdata isRT.%d\n",coin->symbol,i,bp->isRT);
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

int64_t iguana_pkhashbalance(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int64_t *spentp,int64_t *unspents,int32_t *nump,struct iguana_ramchain *ramchain,struct iguana_pkhash *p,uint32_t lastunspentind,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t hdrsi,int32_t lastheight,int32_t minconf,int32_t maxconf)
{
    struct iguana_unspent *U; struct iguana_utxo *U2; struct iguana_spend *S; int32_t max,uheight,spentheight; uint32_t pkind=0,unspentind; int64_t spent = 0,checkval,deposits = 0; struct iguana_txid *T; struct iguana_account *A2; struct iguana_ramchaindata *rdata = 0; int64_t RTspend = 0;
    max = *nump;
    *spentp = *nump = 0;
    if ( 0 && coin->RTramchain_busy != 0 )
    {
        printf("iguana_pkhashbalance: unexpected access when RTramchain_busy\n");
        return(0);
    }
    if ( ramchain->Uextras == 0 || (rdata= ramchain->H.data) == 0 )
    {
        printf("iguana_pkhashbalance: unexpected null spents.%p or rdata.%p\n",ramchain->Uextras,rdata);
        return(0);
    }
    unspentind = lastunspentind;
    U = RAMCHAIN_PTR(rdata,Uoffset);
    T = RAMCHAIN_PTR(rdata,Toffset);
    //U = (void *)(long)((long)rdata + rdata->Uoffset);
    //T = (void *)(long)((long)rdata + rdata->Toffset);
    RTspend = 0;
    if ( lastheight == 0 )
        lastheight = IGUANA_MAXHEIGHT;
    while ( unspentind > 0 )
    {
        uheight = iguana_uheight(coin,ramchain->height,T,rdata->numtxids,&U[unspentind]);
        if ( lastheight <= 0 || uheight < lastheight )
        {
            deposits += U[unspentind].value;
            if ( iguana_spentflag(coin,&RTspend,&spentheight,ramchain,hdrsi,unspentind,lastheight,minconf,maxconf,U[unspentind].value) == 0 )
            {
                if ( *nump < max && unspents != 0 )
                {
                    unspents[*nump << 1] = ((uint64_t)hdrsi << 32) | unspentind;
                    unspents[(*nump << 1) + 1] = U[unspentind].value;
                }
                //printf("%.8f ",dstr(U[unspentind].value));
                (*nump)++;
                if ( array != 0 )
                    jaddi(array,iguana_unspentjson(myinfo,coin,hdrsi,unspentind,T,&U[unspentind],rmd160,coinaddr,pubkey33));
            }
            else
            {
                //printf("-%.8f ",dstr(U[unspentind].value));
                spent += U[unspentind].value;
            }
            if ( p->pkind != U[unspentind].pkind )
                printf("warning: [%d] p->pkind.%u vs U->pkind.%u for u%d\n",hdrsi,p->pkind,U[unspentind].pkind,unspentind);
        }
        pkind = p->pkind;
        unspentind = U[unspentind].prevunspentind;
    }
    if ( lastheight > 0 && (A2= ramchain->A2) != 0 && (U2= ramchain->Uextras) != 0 )
    {
        S = RAMCHAIN_PTR(rdata,Soffset);
        //S = (void *)(long)((long)rdata + rdata->Soffset);
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
        if ( llabs(spent - checkval - RTspend) > SMALLVAL )
            printf("spend %s: [%d] deposits %.8f spent %.8f check %.8f (%.8f) vs A2[%u] %.8f\n",lastheight==IGUANA_MAXHEIGHT?"checkerr":"",hdrsi,dstr(deposits),dstr(spent),dstr(checkval)+dstr(RTspend),dstr(*spentp),pkind,dstr(A2[pkind].total));
    }
    (*spentp) = spent;
    //printf("(%s) spent %.8f, RTspent %.8f deposits %.8f\n",coinaddr,dstr(spent),dstr(RTspend),dstr(deposits));
    return(deposits - spent);
}

int32_t iguana_pkhasharray(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,int64_t *totalp,struct iguana_pkhash *P,int32_t max,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t lastheight,int64_t *unspents,int32_t *numunspentsp,int32_t maxunspents)
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
    for (total=n=i=0; i<max; i++)
    {
        if ( (bp= coin->bundles[i]) == 0 )
            continue;
        if ( lastheight > 0 && bp->bundleheight+bp->n > lastheight )
            break;
        if ( (coin->blocks.hwmchain.height - (bp->bundleheight + bp->n - 1)) > maxconf )
            continue;
        if ( (coin->blocks.hwmchain.height - bp->bundleheight) < minconf )
            break;
        if ( iguana_pkhashfind(coin,&ramchain,&deposits,&lastunspentind,P != 0 ? &P[n] : &_p,rmd160,i,i) != 0 )
        {
            m = maxunspents >> 1;
            p = (P == 0) ? &_p : &P[n];
            if ( (netbalance= iguana_pkhashbalance(myinfo,coin,array,&spent,unspents != 0 ? &unspents[numunspents << 1] : 0,&m,ramchain,p,lastunspentind,rmd160,coinaddr,pubkey33,i,lastheight,minconf,maxconf)) != deposits-spent && lastheight == IGUANA_MAXHEIGHT && minconf == 1 && maxconf > coin->blocks.hwmchain.height )
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

int64_t iguana_unspents(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,uint8_t *rmdarray,int32_t numrmds,int32_t lastheight,int64_t *unspents,int32_t *numunspentsp)
{
    int64_t total=0,sum=0; struct iguana_pkhash *P; uint8_t *addrtypes,*pubkeys; int32_t i,numunspents,maxunspents,flag = 0; char coinaddr[64];
    if ( 0 && coin->RTramchain_busy != 0 )
    {
        printf("iguana_pkhasharray: unexpected access when RTramchain_busy\n");
        return(sum);
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
            iguana_pkhasharray(myinfo,coin,array,minconf,maxconf,&total,P,coin->bundlescount,&rmdarray[i * 20],coinaddr,&pubkeys[33*i],lastheight,&unspents[numunspents << 1],numunspentsp,maxunspents);
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
    return(sum);
}

uint8_t *iguana_rmdarray(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp,cJSON *array,int32_t firsti)
{
    int32_t i,n,flag=0,j=0; char *coinaddr,rmdstr[41]; uint8_t *addrtypes,*rmdarray = 0;
    *numrmdsp = 0;
    if ( array == 0 )
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
                printf("(%s %s) ",coinaddr,rmdstr);
                j++;
            }
        }
        printf("rmdarray[%d]\n",n);
    }
    if ( flag != 0 )
        free_json(array);
    return(rmdarray);
}

int32_t iguana_unspentslists(struct supernet_info *myinfo,struct iguana_info *coin,int64_t *totalp,int64_t *unspents,int32_t max,int64_t required,int32_t minconf,cJSON *addresses)
{
    int64_t remains,total,sum = 0; int32_t i,n,numunspents,numaddrs; uint8_t addrtype,pubkey[65],rmd160[20]; char *coinaddr;
    *totalp = 0;
    if ( (numaddrs= cJSON_GetArraySize(addresses)) == 0 )
        return(0);
    memset(pubkey,0,sizeof(pubkey));
    remains = required * 1.1 + coin->txfee;
    for (i=numunspents=0; i<numaddrs; i++)
    {
        if ( (coinaddr= jstri(addresses,i)) != 0 )
        {
            total = 0;
            n = 0;
            bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
            iguana_pkhasharray(myinfo,coin,0,minconf,coin->longestchain,&total,0,coin->bundlescount,rmd160,coinaddr,pubkey,coin->blocks.hwmchain.height - minconf,unspents,&n,max-1000);
            if ( n > 0 )
            {
                sum += total;
                unspents += (n << 1);
                numunspents += n;
                if ( numunspents > max )
                    break;
            }
        }
    }
    *totalp = sum;
    return(numunspents);
}

int32_t iguana_uvaltxid(struct supernet_info *myinfo,bits256 *txidp,struct iguana_info *coin,int16_t hdrsi,uint32_t unspentind)
{
    struct iguana_bundle *bp; struct iguana_unspent *U,*u; struct iguana_txid *T; struct iguana_ramchain *ramchain;
    if ( (bp= coin->bundles[hdrsi]) == 0 )
        return(-1);
    ramchain = (bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
    U = RAMCHAIN_PTR(ramchain->H.data,Uoffset);
    T = RAMCHAIN_PTR(ramchain->H.data,Toffset);
    if ( unspentind > 0 && unspentind < ramchain->H.data->numunspents )
    {
        u = &U[unspentind];
        if ( u->txidind > 0 && u->txidind < ramchain->H.data->numtxids )
        {
            *txidp = T[u->txidind].txid;
            return(unspentind - T[u->txidind].firstvout);
        }
    }
    return(-1);
}

int64_t iguana_unspentavail(struct iguana_info *coin,uint64_t hdrsi_unspentind,int32_t minconf,int32_t maxconf)
{
    struct iguana_ramchain *ramchain; struct iguana_bundle *bp; int64_t RTspend; int32_t hdrsi,spentheight,spentflag; struct iguana_unspent *U,*u; uint32_t unspentind;
    if ( (bp= coin->bundles[hdrsi_unspentind>>32]) == 0 )
        return(-1);
    hdrsi = (int16_t)(hdrsi_unspentind >> 32);
    unspentind = (uint32_t)hdrsi_unspentind;
    ramchain = (bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
    if ( (spentflag= iguana_spentflag(coin,&RTspend,&spentheight,ramchain,hdrsi,unspentind,0,minconf,maxconf,0)) > 0 )
    {
        printf("[%d].u%d was already spent ht.%d\n",hdrsi,(uint32_t)unspentind,spentheight);
        return(-1);
    }
    else if ( spentflag == 0 )
    {
        U = RAMCHAIN_PTR(ramchain->H.data,Uoffset);
        if ( unspentind > 0 && unspentind < ramchain->H.data->numunspents )
        {
            u = &U[unspentind];
            return(u->value);
        }
        else
        {
            printf("illegal unspentind.%u vs %u [%d]\n",unspentind,ramchain->H.data->numunspents,bp->hdrsi);
            return(-2);
        }
    }
    else return(0);
}
