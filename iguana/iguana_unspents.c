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

#include "iguana777.h"
#include "exchanges/bitcoin.h"

struct iguana_hhutxo *iguana_hhutxofind(struct iguana_info *coin,uint8_t *ubuf,uint16_t spent_hdrsi,uint32_t spent_unspentind)
{
    struct iguana_hhutxo *hhutxo; uint8_t buf[sizeof(spent_unspentind) + sizeof(spent_hdrsi)];
    memcpy(buf,ubuf,sizeof(buf));
    memcpy(&buf[sizeof(spent_unspentind)],(void *)&spent_hdrsi,sizeof(spent_hdrsi));
    memcpy(buf,(void *)&spent_unspentind,sizeof(spent_unspentind));
    HASH_FIND(hh,coin->utxotable,buf,sizeof(buf),hhutxo);
    return(hhutxo);
}

struct iguana_hhaccount *iguana_hhaccountfind(struct iguana_info *coin,uint8_t *pkbuf,uint16_t spent_hdrsi,uint32_t spent_pkind)
{
    struct iguana_hhaccount *hhacct; uint8_t buf[sizeof(spent_pkind) + sizeof(spent_hdrsi)];
    memcpy(buf,pkbuf,sizeof(buf));
    memcpy(&buf[sizeof(spent_pkind)],(void *)&spent_hdrsi,sizeof(spent_hdrsi));
    memcpy(buf,(void *)&spent_pkind,sizeof(spent_pkind));
    HASH_FIND(hh,coin->utxotable,buf,sizeof(buf),hhacct);
    return(hhacct);
}

int32_t iguana_utxoupdate(struct iguana_info *coin,int16_t spent_hdrsi,uint32_t spent_unspentind,uint32_t spent_pkind,uint64_t spent_value,uint32_t spendind,uint32_t fromheight)
{
    struct iguana_hhutxo *hhutxo,*tmputxo; struct iguana_hhaccount *hhacct,*tmpacct;
    uint8_t pkbuf[sizeof(spent_hdrsi) + sizeof(uint32_t)];
    uint8_t ubuf[sizeof(spent_hdrsi) + sizeof(uint32_t)];
    uint8_t buf[sizeof(spent_hdrsi) + sizeof(uint32_t)];
    if ( spent_hdrsi < 0 )
    {
        if ( coin->utxotable != 0 )
        {
            HASH_ITER(hh,coin->utxotable,hhutxo,tmputxo)
            {
                HASH_DEL(coin->utxotable,hhutxo);
                free(hhutxo);
            }
            coin->utxotable = 0;
        }
        if ( coin->accountstable != 0 )
        {
            HASH_ITER(hh,coin->accountstable,hhacct,tmpacct)
            {
                HASH_DEL(coin->accountstable,hhacct);
                free(hhacct);
            }
            coin->accountstable = 0;
        }
        return(0);
    }
    //printf("utxoupdate spenthdrsi.%d pkind.%d %.8f from [%d:%d] spendind.%u\n",spent_hdrsi,spent_pkind,dstr(spent_value),fromheight/coin->chain->bundlesize,fromheight%coin->chain->bundlesize,spendind);
    if ( (hhutxo= iguana_hhutxofind(coin,ubuf,spent_hdrsi,spent_unspentind)) != 0 && hhutxo->u.spentflag != 0 )
    {
        printf("hhutxo.%p spentflag.%d\n",hhutxo,hhutxo->u.spentflag);
        return(-1);
    }
    hhutxo = calloc(1,sizeof(*hhutxo));
    memcpy(buf,ubuf,sizeof(buf));
    HASH_ADD(hh,coin->utxotable,buf,sizeof(buf),hhutxo);
    if ( (hhacct= iguana_hhaccountfind(coin,pkbuf,spent_hdrsi,spent_pkind)) == 0 )
    {
        hhacct = calloc(1,sizeof(*hhacct));
        memcpy(buf,pkbuf,sizeof(buf));
        HASH_ADD(hh,coin->accountstable,buf,sizeof(buf),hhacct);
    }
    //printf("create hhutxo.%p hhacct.%p from.%d\n",hhutxo,hhacct,fromheight);
    hhutxo->u.spentflag = 1;
    hhutxo->u.fromheight = fromheight;
    hhutxo->u.prevunspentind = hhacct->a.lastunspentind;
    hhacct->a.lastunspentind = spent_unspentind;
    hhacct->a.total += spent_value;
    return(0);
}

int32_t iguana_volatileupdate(struct iguana_info *coin,int32_t incremental,struct iguana_ramchain *spentchain,int16_t spent_hdrsi,uint32_t spent_unspentind,uint32_t spent_pkind,uint64_t spent_value,uint32_t spendind,uint32_t fromheight)
{
    struct iguana_account *A2; struct iguana_ramchaindata *rdata; struct iguana_utxo *utxo;
    if ( (rdata= spentchain->H.data) != 0 )
    {
        if ( incremental == 0 )
        {
            A2 = spentchain->A;
            if ( spentchain->Uextras != 0 && A2 != 0 )
            {
                utxo = &spentchain->Uextras[spent_unspentind];
                if ( utxo->spentflag == 0 )
                {
                    utxo->prevunspentind = A2[spent_pkind].lastunspentind;
                    utxo->spentflag = 1;
                    utxo->fromheight = fromheight;
                    A2[spent_pkind].total += spent_value;
                    A2[spent_pkind].lastunspentind = spent_unspentind;
                    return(0);
                } else printf("spent_unspentind[%d] in hdrs.[%d] is spent\n",spent_unspentind,spent_hdrsi);
            } else printf("null ptrs.[%d] u.%u p.%u %.8f from ht.%d s.%u\n",spent_hdrsi,spent_unspentind,spent_pkind,dstr(spent_value),fromheight,spendind);
        }
        else // do the equivalent of historical, ie mark as spent, linked list, balance
        {
            if ( iguana_utxoupdate(coin,spent_hdrsi,spent_unspentind,spent_pkind,spent_value,spendind,fromheight) == 0 )
                return(0);
        }
        printf("iguana_volatileupdate: [%d] spent.(u%u %.8f pkind.%d) double spend? at ht.%d [%d] spendind.%d\n",spent_hdrsi,spent_unspentind,dstr(spent_value),spent_pkind,fromheight,fromheight/coin->chain->bundlesize,spendind);
        exit(-1);
    }
    return(-1);
}

struct iguana_pkhash *iguana_pkhashfind(struct iguana_info *coin,struct iguana_ramchain **ramchainp,int64_t *balancep,uint32_t *lastunspentindp,struct iguana_pkhash *p,uint8_t rmd160[20],int32_t firsti,int32_t endi)
{
    uint8_t *PKbits; struct iguana_pkhash *P; uint32_t pkind,i; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_account *ACCTS;
    *balancep = 0;
    *ramchainp = 0;
    *lastunspentindp = 0;
    for (i=firsti; i<coin->bundlescount&&i<=endi; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            ramchain = &bp->ramchain;
            if ( ramchain->H.data != 0 )
            {
                PKbits = (void *)(long)((long)ramchain->H.data + ramchain->H.data->PKoffset);
                P = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Poffset);
                ACCTS = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Aoffset);
                if ( (pkind= iguana_sparseaddpk(PKbits,ramchain->H.data->pksparsebits,ramchain->H.data->numpksparse,rmd160,P,0)) > 0 && pkind < ramchain->H.data->numpkinds )
                {
                    *ramchainp = ramchain;
                    *balancep = ACCTS[pkind].total;
                    *lastunspentindp = ACCTS[pkind].lastunspentind;
                    *p = P[pkind];
                    return(p);
                } //else printf("not found pkind.%d vs num.%d\n",pkind,ramchain->H.data->numpkinds);
            } else printf("%s.[%d] error null ramchain->H.data\n",coin->symbol,i);
        }
    }
    return(0);
}

char *iguana_bundleaddrs(struct iguana_info *coin,int32_t hdrsi)
{
    uint8_t *PKbits; struct iguana_pkhash *P; uint32_t pkind; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; cJSON *retjson; char rmdstr[41];
    if ( (bp= coin->bundles[hdrsi]) != 0 )
    {
        ramchain = &bp->ramchain;
        if ( ramchain->H.data != 0 )
        {
            retjson = cJSON_CreateArray();
            PKbits = (void *)(long)((long)ramchain->H.data + ramchain->H.data->PKoffset);
            P = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Poffset);
            for (pkind=0; pkind<ramchain->H.data->numpkinds; pkind++,P++)
            {
                init_hexbytes_noT(rmdstr,P->rmd160,20);
                jaddistr(retjson,rmdstr);
            }
            return(jprint(retjson,1));
        }
        //iguana_bundleQ(coin,bp,bp->n);
        return(clonestr("{\"error\":\"no bundle data\"}"));
    } return(clonestr("{\"error\":\"no bundle\"}"));
}

struct iguana_bundle *iguana_externalspent(struct iguana_info *coin,bits256 *prevhashp,uint32_t *unspentindp,struct iguana_ramchain *ramchain,int32_t spend_hdrsi,struct iguana_spend *s)
{
    int32_t prev_vout,height,hdrsi; uint32_t sequenceid,unspentind; char str[65];
    struct iguana_bundle *spentbp=0; struct iguana_txid *T,TX,*tp; bits256 *X; bits256 prev_hash;
    X = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Xoffset);
    T = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Toffset);
    sequenceid = s->sequenceid;
    hdrsi = spend_hdrsi;
    *unspentindp = 0;
    memset(prevhashp,0,sizeof(*prevhashp));
    if ( s->prevout < 0 )
    {
        //printf("n.%d coinbase at spendind.%d firstvin.%d -> firstvout.%d -> unspentind\n",m,spendind,nextT->firstvin,nextT->firstvout);
        //nextT++;
        //m++;
        return(0);
    }
    else
    {
        prev_vout = s->prevout;
        iguana_ramchain_spendtxid(coin,&unspentind,&prev_hash,T,ramchain->H.data->numtxids,X,ramchain->H.data->numexternaltxids,s);
        *prevhashp = prev_hash;
        *unspentindp = unspentind;
        if ( unspentind == 0 )
        {
            if ( (tp= iguana_txidfind(coin,&height,&TX,prev_hash,spend_hdrsi-1)) != 0 )
            {
                *unspentindp = unspentind = TX.firstvout + ((prev_vout > 0) ? prev_vout : 0);
                hdrsi = height / coin->chain->bundlesize;
                //printf("%s height.%d firstvout.%d prev.%d ->U%d\n",bits256_str(str,prev_hash),height,TX.firstvout,prev_vout,unspentind);
            }
            else
            {
                printf("cant find prev_hash.(%s) for bp.[%d]\n",bits256_str(str,prev_hash),spend_hdrsi);
            }
        }
    }
    if ( hdrsi > spend_hdrsi || (spentbp= coin->bundles[hdrsi]) == 0 )
        printf("illegal hdrsi.%d when [%d] spentbp.%p\n",hdrsi,spend_hdrsi,spentbp);//, getchar();
    //else if ( spentbp->ramchain.spents[unspentind].ind != 0 || hdrsi < 0 )
    //   printf("DOUBLE SPEND? U%d %p bp.[%d] unspentind.%u already has %u, no room\n",unspentind,&spentbp->ramchain.spents[unspentind],hdrsi,unspentind,spentbp->ramchain.spents[unspentind].ind);//, getchar();
    else if ( unspentind == 0 || unspentind >= spentbp->ramchain.H.data->numunspents )
        printf("illegal unspentind.%d vs max.%d spentbp.%p[%d]\n",unspentind,spentbp->ramchain.H.data->numunspents,spentbp,hdrsi);//, getchar();
    else return(spentbp);
    return(0);
}

cJSON *iguana_unspentjson(struct iguana_info *coin,int32_t hdrsi,uint32_t unspentind,struct iguana_txid *T,struct iguana_unspent *up,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33)
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
    struct iguana_waccount *wacct; struct iguana_txid TX; int32_t height,ind; char scriptstr[8192],asmstr[sizeof(scriptstr)+1024]; cJSON *item;
    item = cJSON_CreateObject();
    jaddbits256(item,"txid",T[up->txidind].txid);
    jaddnum(item,"vout",up->vout);
    jaddstr(item,"address",coinaddr);
    if ( (wacct= iguana_waddressfind(coin,&ind,coinaddr)) != 0 )
        jaddstr(item,"account",wacct->account);
    if ( iguana_scriptget(coin,scriptstr,asmstr,sizeof(scriptstr),hdrsi,unspentind,T[up->txidind].txid,up->vout,rmd160,up->type,pubkey33) != 0 )
        jaddstr(item,"scriptPubKey",scriptstr);
    jaddnum(item,"amount",dstr(up->value));
    if ( iguana_txidfind(coin,&height,&TX,T[up->txidind].txid,coin->bundlescount-1) != 0 )
        jaddnum(item,"confirmations",coin->longestchain - height);
    return(item);
}

int64_t iguana_pkhashbalance(struct iguana_info *coin,cJSON *array,int64_t *spentp,int32_t *nump,struct iguana_ramchain *ramchain,struct iguana_pkhash *p,uint32_t lastunspentind,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t hdrsi)
{
    struct iguana_unspent *U; uint32_t unspentind; int64_t balance = 0; struct iguana_txid *T;
    *spentp = *nump = 0;
    if ( ramchain->Uextras == 0 )
    {
        printf("iguana_pkhashbalance: unexpected null spents\n");
        return(0);
    }
    unspentind = lastunspentind;
    U = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Uoffset);
    T = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Toffset);
    while ( unspentind > 0 )
    {
        (*nump)++;
        printf("%s u.%d %.8f\n",jprint(iguana_unspentjson(coin,hdrsi,unspentind,T,&U[unspentind],rmd160,coinaddr,pubkey33),1),unspentind,dstr(U[unspentind].value));
        if ( ramchain->Uextras[unspentind].spentflag == 0 )
        {
            balance += U[unspentind].value;
            if ( array != 0 )
                jaddi(array,iguana_unspentjson(coin,hdrsi,unspentind,T,&U[unspentind],rmd160,coinaddr,pubkey33));
        } else (*spentp) += U[unspentind].value;
        unspentind = U[unspentind].prevunspentind;
    }
    return(balance);
}

int32_t iguana_pkhasharray(struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,int64_t *totalp,struct iguana_pkhash *P,int32_t max,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33)
{
    int32_t i,n,m; int64_t spent,balance,netbalance,total; uint32_t lastunspentind; struct iguana_ramchain *ramchain;
    for (total=i=n=0; i<max && i<coin->bundlescount; i++)
    {
        if ( iguana_pkhashfind(coin,&ramchain,&balance,&lastunspentind,&P[n],rmd160,i,i) != 0 )
        {
            if ( (netbalance= iguana_pkhashbalance(coin,array,&spent,&m,ramchain,&P[n],lastunspentind,rmd160,coinaddr,pubkey33,i)) != balance-spent )
            {
                printf("pkhash balance mismatch from m.%d check %.8f vs %.8f spent %.8f [%.8f]\n",m,dstr(netbalance),dstr(balance),dstr(spent),dstr(balance)-dstr(spent));
            }
            else
            {
                //P[n].firstunspentind = lastunspentind;
                total += netbalance;
                n++;
            }
        }
        //printf("%d: balance %.8f, lastunspent.%u\n",i,dstr(balance),lastunspentind);
    }
    //printf("n.%d max.%d\n",n,max);
    *totalp = total;
    return(n);
}

void iguana_unspents(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,uint8_t *rmdarray,int32_t numrmds)
{
    int64_t total,sum=0; struct iguana_pkhash *P; uint8_t *addrtypes,*pubkeys; int32_t i,flag = 0; char coinaddr[64];
    if ( rmdarray == 0 )
        rmdarray = iguana_walletrmds(myinfo,coin,&numrmds), flag++;
    addrtypes = &rmdarray[numrmds * 20], pubkeys = &rmdarray[numrmds * 21];
    P = calloc(coin->bundlescount,sizeof(*P));
    for (i=0; i<numrmds; i++)
    {
        bitcoin_address(coinaddr,addrtypes[i],&rmdarray[i * 20],20);
        iguana_pkhasharray(coin,array,minconf,maxconf,&total,P,coin->bundlescount,&rmdarray[i * 20],coinaddr,&pubkeys[33*i]);
        printf("%s %.8f\n",coinaddr,dstr(total));
        sum += total;
    }
    printf("sum %.8f\n",dstr(sum));
    free(P);
    if ( flag != 0 )
        free(rmdarray);
}

uint8_t *iguana_rmdarray(struct iguana_info *coin,int32_t *numrmdsp,cJSON *array,int32_t firsti)
{
    int32_t i,n,j=0; char *coinaddr; uint8_t *addrtypes,*rmdarray = 0;
    *numrmdsp = 0;
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        *numrmdsp = n - firsti;
        rmdarray = calloc(1,(n-firsti) * 21);
        addrtypes = &rmdarray[(n-firsti) * 20];
        for (i=firsti; i<n; i++)
        {
            if ( (coinaddr= jstr(jitem(array,i),0)) != 0 )
            {
                bitcoin_addr2rmd160(&addrtypes[j],&rmdarray[20 * j],coinaddr);
                j++;
            }
        }
    }
    return(rmdarray);
}

int32_t iguana_spendvectors(struct iguana_info *coin,struct iguana_bundle *bp)
{
    static uint64_t total,emitted;
    int32_t spendind,n,txidind,errs=0,emit=0,i,j,k,retval = -1; long fsize;
    uint32_t spent_unspentind,spent_pkind,now; struct iguana_ramchaindata *rdata;
    struct iguana_bundle *spentbp; struct iguana_blockRO *B; FILE *fp; char fname[1024],str[65];
    bits256 prevhash,zero,sha256; struct iguana_unspent *u,*spentU;  struct iguana_txid *T;
    struct iguana_spend *S,*s; struct iguana_spendvector *ptr; struct iguana_ramchain *ramchain;
    ramchain = &bp->ramchain;
    //printf("iguana_spendvectors gen.%d ramchain data.%p\n",bp->bundleheight,ramchain->H.data);
    if ( (rdata= ramchain->H.data) == 0 || (n= rdata->numspends) < 1 )
        return(0);
    B = (void *)(long)((long)rdata + rdata->Boffset);
    S = (void *)(long)((long)rdata + rdata->Soffset);
    T = (void *)(long)((long)rdata + rdata->Toffset);
    if ( ramchain->Xspendinds != 0 )
    {
        //printf("iguana_spendvectors: already have Xspendinds[%d]\n",ramchain->numXspends);
        return(0);
    }
    ptr = mycalloc('x',sizeof(*ptr),n);
    total += n;
    //printf("start UTXOGEN.%d max.%d ptr.%p\n",bp->bundleheight,n,ptr);
    txidind = spendind = rdata->firsti;
    iguana_ramchain_prefetch(coin,ramchain);
    for (i=0; i<bp->n; i++)
    {
        if ( txidind != B[i].firsttxidind || spendind != B[i].firstvin )
        {
            printf("utxogen: txidind %u != %u B[%d].firsttxidind || spendind %u != %u B[%d].firstvin\n",txidind,B[i].firsttxidind,i,spendind,B[i].firstvin,i);
            myfree(ptr,sizeof(*ptr) * n);
            return(-1);
        }
        for (j=0; j<B[i].txn_count && errs==0; j++,txidind++)
        {
            now = (uint32_t)time(NULL);
            if ( txidind != T[txidind].txidind || spendind != T[txidind].firstvin )
            {
                printf("utxogen: txidind %u != %u nextT[txidind].firsttxidind || spendind %u != %u nextT[txidind].firstvin\n",txidind,T[txidind].txidind,spendind,T[txidind].firstvin);
                myfree(ptr,sizeof(*ptr) * n);
                return(-1);
            }
            for (k=0; k<T[txidind].numvins && errs==0; k++,spendind++)
            {
                s = &S[spendind];
                u = 0;
                if ( s->external != 0 && s->prevout >= 0 )
                {
                    if ( (spentbp= iguana_externalspent(coin,&prevhash,&spent_unspentind,ramchain,bp->hdrsi,s)) != 0 && spentbp->ramchain.H.data != 0 )
                    {
                        if ( spentbp == bp )
                        {
                            char str[65];
                            printf("unexpected spendbp: height.%d bp.[%d] U%d <- S%d.[%d] [ext.%d %s prev.%d]\n",bp->bundleheight+i,spentbp->hdrsi,spent_unspentind,spendind,bp->hdrsi,s->external,bits256_str(str,prevhash),s->prevout);
                            errs++;
                        }
                        if ( now > spentbp->lastprefetch+10 )
                        {
                            printf("prefetch[%d] from.[%d] lag.%d\n",spentbp->hdrsi,bp->hdrsi,now - spentbp->lastprefetch);
                            iguana_ramchain_prefetch(coin,&spentbp->ramchain);
                            spentbp->lastprefetch = now;
                        }
                        spentU = (void *)(long)((long)spentbp->ramchain.H.data + spentbp->ramchain.H.data->Uoffset);
                        u = &spentU[spent_unspentind];
                        if ( (spent_pkind= u->pkind) != 0 && spent_pkind < spentbp->ramchain.H.data->numpkinds )
                        {
                            
                            if ( (ptr[emit].unspentind= spent_unspentind) != 0 && spentbp->hdrsi < bp->hdrsi )
                            {
                                ptr[emit].hdrsi = spentbp->hdrsi;
                                ptr[emit].pkind = spent_pkind;
                                ptr[emit].value = u->value;
                                ptr[emit].bundlei = i;
                                //ptr[emit].txi = j;
                                //printf("(%d u%d).%d ",spentbp->hdrsi,unspentind,emit);
                                emit++;
                            }
                            else
                            {
                                printf("spendvectors: null unspentind for spendind.%d hdrsi.%d [%d]\n",spendind,spentbp->hdrsi,bp->hdrsi);
                                errs++;
                            }
                        }
                        else
                        {
                            errs++;
                            printf("spendvectors: unresolved spendind.%d hdrsi.%d\n",spendind,bp->hdrsi);
                            break;
                        }
                    }
                }
            }
        }
    }
    if ( txidind != bp->ramchain.H.data->numtxids )
    {
        printf("numtxid.%d != bp numtxids %d\n",txidind,bp->ramchain.H.data->numtxids);
        errs++;
    }
    if ( spendind != bp->ramchain.H.data->numspends )
    {
        printf("spendind.%d != bp numspends %d\n",spendind,bp->ramchain.H.data->numspends);
        errs++;
    }
    if ( errs == 0 && emit >= 0 )
    {
        emitted += emit;
        memset(zero.bytes,0,sizeof(zero));
        sprintf(fname,"DB/%s/spends/%s.%d",coin->symbol,bits256_str(str,bp->hashes[0]),bp->bundleheight);
        vcalc_sha256(0,sha256.bytes,(void *)ptr,(int32_t)(sizeof(*ptr) * emit));
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            if ( fwrite(sha256.bytes,1,sizeof(sha256),fp) != sizeof(sha256) )
                printf("error writing hash for %ld -> (%s)\n",sizeof(*ptr) * emit,fname);
            else if ( fwrite(ptr,sizeof(*ptr),emit,fp) != emit )
                printf("error writing %d of %d -> (%s)\n",emit,n,fname);
            else retval = 0;
            fsize = ftell(fp);
            fclose(fp);
            if ( iguana_Xspendmap(coin,ramchain,bp) < 0 )
            {
                printf("error mapping Xspendmap.(%s)\n",fname);
                retval = -1;
            }
            //int32_t i; for (i=0; i<ramchain->numXspends; i++)
            //    printf("(%d u%d) ",ramchain->Xspendinds[i].hdrsi,ramchain->Xspendinds[i].ind);
            //printf("filesize %ld Xspendptr.%p %p num.%d\n",fsize,ramchain->Xspendptr,ramchain->Xspendinds,ramchain->numXspends);
        } else printf("Error creating.(%s)\n",fname);
    }
    if ( ptr != 0 )
        myfree(ptr,sizeof(*ptr) * n);
    printf("utxo %d spendinds.[%d] errs.%d [%.2f%%] emitted.%d %s of %d\n",spendind,bp->hdrsi,errs,100.*(double)emitted/(total+1),emit,mbstr(str,sizeof(*ptr) * emit),n);
    if ( errs != 0 )
        exit(-1);
    return(-errs);
}

int32_t iguana_balancegen(struct iguana_info *coin,struct iguana_bundle *bp,int32_t startheight,int32_t endheight)
{
    uint32_t spent_unspentind,spent_pkind,txidind,h,i,j,k,now; uint64_t spent_value;
    struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata;
    struct iguana_spendvector *spend; struct iguana_unspent *spentU,*u;
    struct iguana_txid *T; struct iguana_blockRO *B; struct iguana_bundle *spentbp;
    int32_t spent_hdrsi,spendind,n,errs=0,emit=0; struct iguana_spend *S,*s;
    ramchain = &bp->ramchain;
    if ( (rdata= ramchain->H.data) == 0 || (n= ramchain->H.data->numspends) < 1 )
        return(-1);
    S = (void *)(long)((long)rdata + rdata->Soffset);
    B = (void *)(long)((long)rdata + rdata->Boffset);
    T = (void *)(long)((long)rdata + rdata->Toffset);
    if ( ramchain->Xspendinds == 0 )
    {
        printf("iguana_balancegen.%d: no Xspendinds[%d]\n",bp->hdrsi,ramchain->numXspends);
        return(-1);
    }
    iguana_ramchain_prefetch(coin,ramchain);
    printf("BALANCEGEN.%d hdrs.%d\n",bp->bundleheight,bp->hdrsi);
    txidind = spendind = rdata->firsti;
    for (i=0; i<bp->n; i++)
    {
        //printf("hdrs.[%d] B[%d] 1st txidind.%d txn_count.%d firstvin.%d firstvout.%d\n",bp->hdrsi,i,B[i].firsttxidind,B[i].txn_count,B[i].firstvin,B[i].firstvout);
        if ( txidind != B[i].firsttxidind || spendind != B[i].firstvin )
        {
            printf("balancegen: txidind %u != %u B[%d].firsttxidind || spendind %u != %u B[%d].firstvin errs.%d\n",txidind,B[i].firsttxidind,i,spendind,B[i].firstvin,i,errs);
            return(-1);
        }
        for (j=0; j<B[i].txn_count && errs==0; j++,txidind++)
        {
            now = (uint32_t)time(NULL);
            if ( txidind != T[txidind].txidind || spendind != T[txidind].firstvin )
            {
                printf("balancegen: txidind %u != %u T[txidind].firsttxidind || spendind %u != %u T[txidind].firstvin errs.%d\n",txidind,T[txidind].txidind,spendind,T[txidind].firstvin,errs);
                return(-1);
            }
            //printf("txidind.%d txi.%d numvins.%d spendind.%d\n",txidind,j,T[txidind].numvins,spendind);
            for (k=0; k<T[txidind].numvins && errs==0; k++,spendind++)
            {
                s = &S[spendind];
                h = spent_hdrsi = -1;
                spent_value = 0;
                spent_unspentind = spent_pkind = 0;
                if ( s->external != 0 && s->prevout >= 0 )
                {
                    if ( emit >= ramchain->numXspends )
                        errs++;
                    else
                    {
                        spend = &ramchain->Xspendinds[emit];
                        spent_value = spend->value;
                        spent_pkind = spend->pkind;
                        spent_unspentind = spend->unspentind;
                        spent_hdrsi = spend->hdrsi;
                        h = spend->bundlei + (spent_hdrsi * coin->chain->bundlesize);
                        emit++;
                    }
                }
                else if ( s->prevout >= 0 )
                {
                    h = bp->bundleheight + i;
                    spent_hdrsi = bp->hdrsi;
                    if ( s->spendtxidind != 0 && s->spendtxidind < rdata->numtxids )
                    {
                        spent_unspentind = T[s->spendtxidind].firstvout + s->prevout;
                        spentU = (void *)(long)((long)rdata + rdata->Uoffset);
                        u = &spentU[spent_unspentind];
                        if ( (spent_pkind= u->pkind) != 0 && spent_pkind < rdata->numpkinds )
                            spent_value = u->value;
                        //printf("txidind.%d 1st.%d prevout.%d\n",txidind,T[txidind].firstvout,s->prevout);
                    }
                    else
                    {
                        printf("iguana_balancegen [%d] txidind overflow %u vs %u\n",bp->hdrsi,s->spendtxidind,rdata->numtxids);
                        errs++;
                    }
                }
                else continue;
                if ( spent_unspentind > 0 && spent_pkind > 0 && (spentbp= coin->bundles[spent_hdrsi]) != 0 )
                {
                    if ( iguana_volatileupdate(coin,0,&spentbp->ramchain,spent_hdrsi,spent_unspentind,spent_pkind,spent_value,spendind,h) < 0 )
                        errs++;
                }
                else
                {
                    errs++;
                    printf("iguana_balancegen: error with unspentind.%d [%d]\n",spent_unspentind,spent_hdrsi);
                }
            }
        }
    }
    if ( txidind != bp->ramchain.H.data->numtxids )
    {
        printf("numtxid.%d != bp numtxids %d\n",txidind,bp->ramchain.H.data->numtxids);
        errs++;
    }
    if ( spendind != bp->ramchain.H.data->numspends )
    {
        printf("spendind.%d != bp numspends %d\n",spendind,bp->ramchain.H.data->numspends);
        errs++;
    }
    if ( emit != ramchain->numXspends )
    {
        printf("iguana_balancegen: emit %d != %d ramchain->numXspends\n",emit,ramchain->numXspends);
        errs++;
    }
    printf(">>>>>>>> balances.%d done errs.%d spendind.%d\n",bp->hdrsi,errs,n);
    return(-errs);
}

int32_t iguana_RTutxo(struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_ramchain *RTramchain,int32_t bundlei)
{
    struct iguana_txid *T; int32_t height,spendind,txidind,j,k; bits256 prevhash;
    struct iguana_bundle *spentbp; struct iguana_unspent *spentU,*u;
    struct iguana_ramchaindata *RTdata,*rdata;
    uint32_t spent_unspentind; struct iguana_blockRO *B; struct iguana_spend *S,*s;
    if ( (RTdata= RTramchain->H.data) == 0 || RTdata->numspends < 1 )
    {
        printf("iguana_RTutxo null data or no spends %p\n",RTramchain->H.data);
        return(-1);
    }
    B = (void *)(long)((long)RTdata + RTdata->Boffset);
    S = (void *)(long)((long)RTdata + RTdata->Soffset);
    T = (void *)(long)((long)RTdata + RTdata->Toffset);
    txidind = B[bundlei].firsttxidind;
    spendind = B[bundlei].firstvin;
    height = bp->bundleheight + bundlei;
    for (j=0; j<B[bundlei].txn_count; j++,txidind++)
    {
        //printf("RTutxo.[%d:%d] txn_count.%d\n",bp->hdrsi,bundlei,B[bundlei].txn_count);
        if ( txidind != T[txidind].txidind || spendind != T[txidind].firstvin )
        {
            printf("RTutxogen: txidind %u != %u nextT[txidind].firsttxidind || spendind %u != %u nextT[txidind].firstvin\n",txidind,T[txidind].txidind,spendind,T[txidind].firstvin);
            return(-1);
        }
        for (k=0; k<T[txidind].numvins; k++,spendind++)
        {
            s = &S[spendind];
            if ( s->external != 0 && s->prevout >= 0 )
            {
                if ( (spentbp= iguana_externalspent(coin,&prevhash,&spent_unspentind,RTramchain,bp->hdrsi,s)) == 0 || spent_unspentind == 0 || spent_unspentind >= spentbp->ramchain.H.data->numunspents || spentbp->hdrsi < 0 || spentbp->hdrsi >= bp->hdrsi || spentbp == bp )
                {
                    char str[65];
                    printf("RTutxo: unexpected spendbp: height.%d bp.[%d] U%d <- S%d.[%d] [ext.%d %s prev.%d]\n",height,spentbp->hdrsi,spent_unspentind,spendind,bp->hdrsi,s->external,bits256_str(str,prevhash),s->prevout);
                    return(-1);
                }
                rdata = spentbp->ramchain.H.data;
            }
            else if ( s->prevout >= 0 )
            {
                spentbp = bp;
                rdata = RTramchain->H.data;
                if ( s->spendtxidind != 0 && s->spendtxidind < RTdata->numtxids )
                {
                    spent_unspentind = T[s->spendtxidind].firstvout + s->prevout;
                    //printf("txidind.%d 1st.%d prevout.%d\n",txidind,T[txidind].firstvout,s->prevout);
                }
                else
                {
                    printf("RTutxo txidind overflow %u vs %d\n",s->spendtxidind,RTdata->numtxids);
                    return(-1);
                }
            }
            else continue; // coinbase always already spent
            if ( spentbp != 0 && rdata != 0 && spent_unspentind != 0 && spent_unspentind < rdata->numunspents )
            {
                spentU = (void *)(long)((long)rdata + rdata->Uoffset);
                u = &spentU[spent_unspentind];
                if ( iguana_volatileupdate(coin,1,spentbp == bp ? RTramchain : &spentbp->ramchain,spentbp->hdrsi,spent_unspentind,u->pkind,u->value,spendind,height) < 0 )
                    return(-1);
            }
            else
            {
                printf("RTutxo error spentbp.%p u.%u vs %d\n",spentbp,spent_unspentind,rdata->numunspents);
                return(-1);
            }
        }
    }
    return(0);
}

void iguana_purgevolatiles(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    if ( ramchain->allocatedA != 0 && ramchain->A != 0 )
        free(ramchain->A);
    ramchain->A = 0;
    if ( ramchain->allocatedU != 0 && ramchain->Uextras != 0 )
        free(ramchain->Uextras);
    ramchain->Uextras = 0;
    if ( ramchain->debitsfileptr != 0 )
    {
        munmap(ramchain->debitsfileptr,ramchain->debitsfilesize);
        ramchain->debitsfileptr = 0;
        ramchain->debitsfilesize = 0;
    }
    if ( ramchain->lastspendsfileptr != 0 )
    {
        munmap(ramchain->lastspendsfileptr,ramchain->lastspendsfilesize);
        ramchain->lastspendsfileptr = 0;
        ramchain->lastspendsfilesize = 0;
    }
}

int32_t iguana_mapvolatiles(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    int32_t iter,numhdrsi,err = -1; char fname[1024]; bits256 balancehash;
    for (iter=0; iter<2; iter++)
    {
        sprintf(fname,"DB/%s%s/accounts/debits.%d",iter==0?"ro/":"",coin->symbol,ramchain->H.data->height);
        if ( (ramchain->debitsfileptr= OS_mapfile(fname,&ramchain->debitsfilesize,0)) != 0 && ramchain->debitsfilesize == sizeof(int32_t) + sizeof(bits256) + sizeof(*ramchain->A) * ramchain->H.data->numpkinds )
        {
            ramchain->from_roA = (iter == 0);
            numhdrsi = *(int32_t *)ramchain->debitsfileptr;
            memcpy(balancehash.bytes,(void *)((long)ramchain->debitsfileptr + sizeof(numhdrsi)),sizeof(balancehash));
            if ( coin->balanceswritten == 0 )
            {
                coin->balanceswritten = numhdrsi;
                coin->balancehash = balancehash;
            }
            if ( numhdrsi == coin->balanceswritten || memcmp(balancehash.bytes,coin->balancehash.bytes,sizeof(balancehash)) == 0 )
            {
                ramchain->A = (void *)((long)ramchain->debitsfileptr + sizeof(numhdrsi) + sizeof(bits256));
                sprintf(fname,"DB/%s%s/accounts/lastspends.%d",iter==0?"ro/":"",coin->symbol,ramchain->H.data->height);
                if ( (ramchain->lastspendsfileptr= OS_mapfile(fname,&ramchain->lastspendsfilesize,0)) != 0 && ramchain->lastspendsfilesize == sizeof(int32_t) + sizeof(bits256) + sizeof(*ramchain->Uextras) * ramchain->H.data->numunspents )
                {
                    numhdrsi = *(int32_t *)ramchain->lastspendsfileptr;
                    memcpy(balancehash.bytes,(void *)((long)ramchain->lastspendsfileptr + sizeof(numhdrsi)),sizeof(balancehash));
                    if ( numhdrsi == coin->balanceswritten || memcmp(balancehash.bytes,coin->balancehash.bytes,sizeof(balancehash)) == 0 )
                    {
                        ramchain->Uextras = (void *)((long)ramchain->lastspendsfileptr + sizeof(numhdrsi) + sizeof(bits256));
                        ramchain->from_roU = (iter == 0);
                        err = 0;
                    } else printf("ramchain map error2 balanceswritten %d vs %d hashes %x %x\n",coin->balanceswritten,numhdrsi,coin->balancehash.uints[0],balancehash.uints[0]);
                } else printf("ramchain map error3 %s\n",fname);
            } else printf("ramchain map error balanceswritten %d vs %d hashes %x %x\n",coin->balanceswritten,numhdrsi,coin->balancehash.uints[0],balancehash.uints[0]);
        }
        if ( err == 0 )
        {
            //printf("mapped extra.%s\n",fname);
            break;
        }
        iguana_purgevolatiles(coin,ramchain);
    }
    return(err);
}

void iguana_allocvolatile(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    if ( ramchain != 0 && ramchain->H.data != 0 )
    {
        if ( ramchain->allocatedA == 0 )
        {
            ramchain->A = calloc(sizeof(*ramchain->A),ramchain->H.data->numpkinds + 16);
            ramchain->allocatedA = sizeof(*ramchain->A) * ramchain->H.data->numpkinds;
        }
        if ( ramchain->allocatedU == 0 )
        {
            ramchain->Uextras = calloc(sizeof(*ramchain->Uextras),ramchain->H.data->numunspents + 16);
            ramchain->allocatedU = sizeof(*ramchain->Uextras) * ramchain->H.data->numunspents;
        }
        if ( ramchain->debitsfileptr != 0 )
        {
            memcpy(ramchain->A,(void *)((long)ramchain->debitsfileptr + sizeof(int32_t) + sizeof(bits256)),sizeof(*ramchain->A) * ramchain->H.data->numpkinds);
            munmap(ramchain->debitsfileptr,ramchain->debitsfilesize);
            ramchain->debitsfileptr = 0;
            ramchain->debitsfilesize = 0;
        }
        if ( ramchain->lastspendsfileptr != 0 )
        {
            memcpy(ramchain->Uextras,(void *)((long)ramchain->lastspendsfileptr + sizeof(int32_t) + sizeof(bits256)),sizeof(*ramchain->Uextras) * ramchain->H.data->numunspents);
            munmap(ramchain->lastspendsfileptr,ramchain->lastspendsfilesize);
            ramchain->lastspendsfileptr = 0;
            ramchain->lastspendsfilesize = 0;
        }
    } else printf("illegal ramchain.%p\n",ramchain);
}

void iguana_truncatebalances(struct iguana_info *coin)
{
    int32_t i; struct iguana_bundle *bp;
    for (i=0; i<coin->balanceswritten; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            bp->balancefinish = 0;
            iguana_purgevolatiles(coin,&bp->ramchain);
        }
    }
    coin->balanceswritten = 0;
}

int32_t iguana_volatileinit(struct iguana_info *coin)
{
    bits256 balancehash; struct iguana_utxo *Uptr; struct iguana_account *Aptr;
    struct sha256_vstate vstate; int32_t i,from_ro,numpkinds,numunspents; struct iguana_bundle *bp;
    uint32_t crc,filecrc; FILE *fp; char crcfname[512],str[65],str2[65],buf[2048];
    from_ro = 1;
    for (i=0; i<coin->balanceswritten; i++)
    {
        if ( (bp= coin->bundles[i]) == 0 || bp->emitfinish <= 1 || bp->utxofinish <= 1 )
        {
            printf("hdrsi.[%d] emitfinish.%u utxofinish.%u\n",i,bp->emitfinish,bp->utxofinish);
            break;
        }
        if ( bp->ramchain.from_ro == 0 || bp->ramchain.from_roX == 0 || bp->ramchain.from_roA == 0 || bp->ramchain.from_roU == 0 )
            from_ro = 0;
    }
    if ( i != coin->balanceswritten )
    {
        printf("TRUNCATE balances written.%d -> %d\n",coin->balanceswritten,i);
        iguana_truncatebalances(coin);
    }
    else
    {
        vupdate_sha256(balancehash.bytes,&vstate,0,0);
        filecrc = 0;
        sprintf(crcfname,"DB/%s/balancecrc.%d",coin->symbol,coin->balanceswritten);
        if ( (fp= fopen(crcfname,"rb")) != 0 )
        {
            if ( fread(&filecrc,1,sizeof(filecrc),fp) != sizeof(filecrc) )
                filecrc = 0;
            else if ( fread(&balancehash,1,sizeof(balancehash),fp) != sizeof(balancehash) )
                filecrc = 0;
            else if ( memcmp(&balancehash,&coin->balancehash,sizeof(balancehash)) != 0 )
                filecrc = 0;
            fclose(fp);
        }
        if ( filecrc != 0 )
            printf("have filecrc.%08x for %s milli.%.0f\n",filecrc,bits256_str(str,balancehash),OS_milliseconds());
        if ( from_ro == 0 )
        {
            if ( filecrc == 0 )
                vupdate_sha256(balancehash.bytes,&vstate,0,0);
            for (i=crc=0; i<coin->balanceswritten; i++)
            {
                numpkinds = numunspents = 0;
                Aptr = 0, Uptr = 0;
                if ( (bp= coin->bundles[i]) != 0 && bp->ramchain.H.data != 0 && (numpkinds= bp->ramchain.H.data->numpkinds) > 0 && (numunspents= bp->ramchain.H.data->numunspents) > 0 && (Aptr= bp->ramchain.A) != 0 && (Uptr= bp->ramchain.Uextras) != 0 )
                {
                    if ( filecrc == 0 )
                    {
                        vupdate_sha256(balancehash.bytes,&vstate,(void *)Aptr,sizeof(*Aptr)*numpkinds);
                        vupdate_sha256(balancehash.bytes,&vstate,(void *)Uptr,sizeof(*Uptr)*numunspents);
                    }
                    crc = calc_crc32(crc,(void *)Aptr,(int32_t)(sizeof(*Aptr) * numpkinds));
                    crc = calc_crc32(crc,(void *)Uptr,(int32_t)(sizeof(*Uptr) * numunspents));
                } else printf("missing hdrs.[%d] data.%p num.(%u %d) %p %p\n",i,bp->ramchain.H.data,numpkinds,numunspents,Aptr,Uptr);
            }
        } else crc = filecrc;
        printf("millis %.0f from_ro.%d written.%d crc.%08x/%08x balancehash.(%s) vs (%s)\n",OS_milliseconds(),from_ro,coin->balanceswritten,crc,filecrc,bits256_str(str,balancehash),bits256_str(str2,coin->balancehash));
        if ( (filecrc != 0 && filecrc != crc) || memcmp(balancehash.bytes,coin->balancehash.bytes,sizeof(balancehash)) != 0 )
        {
            printf("balancehash or crc mismatch\n");
            iguana_truncatebalances(coin);
        }
        else
        {
            printf("MATCHED balancehash numhdrsi.%d crc.%08x\n",coin->balanceswritten,crc);
            if ( (fp= fopen(crcfname,"wb")) != 0 )
            {
                if ( fwrite(&crc,1,sizeof(crc),fp) != sizeof(crc) || fwrite(&balancehash,1,sizeof(balancehash),fp) != sizeof(balancehash) )
                    printf("error writing.(%s)\n",crcfname);
                fclose(fp);
            }
        }
    }
    coin->RTheight = coin->balanceswritten * coin->chain->bundlesize;
    iguana_bundlestats(coin,buf);
    return(coin->balanceswritten);
}

void iguana_RTramchainfree(struct iguana_info *coin)
{
    iguana_utxoupdate(coin,-1,0,0,0,0,-1); // free hashtables
    coin->RTheight = coin->balanceswritten * coin->chain->bundlesize;
    iguana_ramchain_free(coin,&coin->RTramchain,1);
}

void iguana_RTramchainalloc(struct iguana_info *coin,struct iguana_bundle *bp)
{
    uint32_t i,changed = 0; struct iguana_ramchain *dest = &coin->RTramchain; struct iguana_blockRO *B;
    if ( dest->H.data != 0 )
    {
        i = 0;
        if ( coin->RTheight != bp->bundleheight + dest->H.data->numblocks )
            changed++;
        else
        {
            B = (void *)(long)((long)dest->H.data + dest->H.data->Boffset);
            for (i=0; i<dest->H.data->numblocks; i++)
                if ( bits256_cmp(B[i].hash2,bp->hashes[i]) != 0 )
                {
                    char str[65],str2[65]; printf("mismatched hash2 at %d %s vs %s\n",bp->bundleheight+i,bits256_str(str,B[i].hash2),bits256_str(str2,bp->hashes[i]));
                    changed++;
                    break;
                }
        }
        if ( changed != 0 )
        {
            printf("RTramchain changed %d bundlei.%d | coin->RTheight %d != %d bp->bundleheight +  %d coin->RTramchain.H.data->numblocks\n",coin->RTheight,i,coin->RTheight,bp->bundleheight,dest->H.data->numblocks);
            //coin->RTheight = coin->balanceswritten * coin->chain->bundlesize;
            iguana_RTramchainfree(coin);
        }
    }
    if ( coin->RTramchain.H.data == 0 )
    {
        //printf("ALLOC RTramchain\n");
        iguana_ramchainopen(coin,dest,&coin->RTmem,&coin->RThashmem,bp->bundleheight,bp->hashes[0]);
        dest->H.txidind = dest->H.unspentind = dest->H.spendind = dest->pkind = dest->H.data->firsti;
        dest->externalind = dest->H.stacksize = 0;
        dest->H.scriptoffset = 1;
    }
}

int32_t iguana_realtime_update(struct iguana_info *coin)
{
    struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; int32_t bundlei,err,n,flag=0;
    struct iguana_block *block=0; struct iguana_blockRO *B; struct iguana_ramchain *dest=0,blockR;
    long filesize; void *ptr; char str[65],fname[1024];
    if ( (bp= coin->current) != 0 && bp->hdrsi == coin->longestchain/coin->chain->bundlesize && bp->hdrsi == coin->balanceswritten && coin->RTheight >= bp->bundleheight && coin->RTheight < bp->bundleheight+bp->n )
    {
        iguana_RTramchainalloc(coin,bp);
        while ( (rdata= coin->RTramchain.H.data) != 0 && coin->RTheight <= coin->blocks.hwmchain.height)
        {
            dest = &coin->RTramchain;
            B = (void *)(long)((long)rdata + rdata->Boffset);
            bundlei = (coin->RTheight % coin->chain->bundlesize);
            if ( (block= bp->blocks[bundlei]) != 0 && bits256_nonz(block->RO.prev_block) != 0 )
            {
                iguana_blocksetcounters(coin,block,dest);
                //coin->blocks.RO[bp->bundleheight+bundlei] = block->RO;
                B[bundlei] = block->RO;
                if ( (ptr= iguana_bundlefile(coin,fname,&filesize,bp,bundlei)) != 0 )
                {
                    if ( iguana_mapchaininit(coin,&blockR,bp,bundlei,block,ptr,filesize) == 0 )
                    {
                        if ( (err= iguana_ramchain_iterate(coin,dest,&blockR,bp)) != 0 || bits256_cmp(blockR.H.data->firsthash2,block->RO.hash2) != 0 )
                        {
                            printf("ERROR [%d:%d] %s vs ",bp->hdrsi,bundlei,bits256_str(str,block->RO.hash2));
                            printf("mapped.%s\n",bits256_str(str,blockR.H.data->firsthash2));
                            if ( (block= bp->blocks[bundlei]) != 0 )
                            {
                                block->queued = 0;
                                block->fpipbits = 0;
                                bp->issued[bundlei] = 0;
                                block->issued = 0;
                                OS_removefile(fname,0);
                            }
                            iguana_RTramchainfree(coin);
                            return(-1);
                        }
                        flag++;
                        if ( iguana_RTutxo(coin,bp,dest,bundlei) < 0 )
                        {
                            printf("RTutxo error -> RTramchainfree\n");
                            iguana_RTramchainfree(coin);
                            return(-1);
                        }
                        coin->RTheight++;
                        printf(">>>> RT.%d hwm.%d L.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld\n",coin->RTheight,coin->blocks.hwmchain.height,coin->longestchain,dest->H.txidind,dest->H.unspentind,dest->H.spendind,dest->pkind,dest->externalind,(long)dest->H.data->allocsize);
                        coin->RTramchain.H.data->numblocks = bundlei + 1;
                    }
                    else
                    {
                        printf("error mapchaininit\n");
                        iguana_ramchain_free(coin,&blockR,1);
                        return(-1);
                    }
                }
                else
                {
                    //printf("no fileptr for RTheight.%d\n",coin->RTheight);
                    return(-1);
                }
            }
            else
            {
                if ( block == 0 )
                    printf("no blockptr.%p for RTheight.%d\n",block,coin->RTheight);
                else
                {
                    block->queued = 0;
                    block->fpipbits = 0;
                    bp->issued[bundlei] = 0;
                    block->issued = 0;
                }
                return(-1);
            }
        }
    }
    if ( dest != 0 && flag != 0 )
    {
        n = 0;
        while ( block != 0 )
        {
            if ( bits256_cmp(iguana_blockhash(coin,coin->RTheight-n-1),block->RO.hash2) != 0 )
            {
                printf("blockhash error at %d\n",coin->RTheight-n-1);
                break;
            }
            block = iguana_blockfind(coin,block->RO.prev_block);
            n++;
            if ( coin->RTgenesis != 0 && n >= bp->n )
                break;
        }
        if ( coin->RTgenesis == 0 && n == coin->RTheight )
        {
            printf("RTgenesis verified\n");
            coin->RTgenesis = (uint32_t)time(NULL);
        }
        printf(">>>> RT.%d:%d hwm.%d L.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld\n",coin->RTheight,n,coin->blocks.hwmchain.height,coin->longestchain,dest->H.txidind,dest->H.unspentind,dest->H.spendind,dest->pkind,dest->externalind,(long)dest->H.data->allocsize);
    }
    return(0);
}

int32_t iguana_balanceflush(struct iguana_info *coin,int32_t refhdrsi,int32_t purgedist)
{
    int32_t hdrsi,numpkinds,iter,numhdrsi,numunspents,err; struct iguana_bundle *bp;
    char fname[1024],fname2[1024],destfname[1024]; bits256 balancehash; FILE *fp,*fp2;
    struct iguana_utxo *Uptr; struct iguana_account *Aptr; struct sha256_vstate vstate;
    vupdate_sha256(balancehash.bytes,&vstate,0,0);
    for (hdrsi=0; hdrsi<coin->bundlescount; hdrsi++)
        if ( (bp= coin->bundles[hdrsi]) == 0 || bp->balancefinish <= 1 || bp->ramchain.H.data == 0 || bp->ramchain.A == 0 || bp->ramchain.Uextras == 0 )
            break;
    if ( hdrsi <= coin->balanceswritten || hdrsi < refhdrsi )
        return(0);
    numhdrsi = hdrsi;
    vupdate_sha256(balancehash.bytes,&vstate,0,0);
    for (iter=0; iter<3; iter++)
    {
        for (hdrsi=0; hdrsi<numhdrsi; hdrsi++)
        {
            Aptr = 0;
            Uptr = 0;
            numunspents = 0;
            numpkinds = 0;
            if ( (bp= coin->bundles[hdrsi]) != 0 && bp->ramchain.H.data != 0 && (numpkinds= bp->ramchain.H.data->numpkinds) > 0 && (numunspents= bp->ramchain.H.data->numunspents) > 0 && (Aptr= bp->ramchain.A) != 0 && (Uptr= bp->ramchain.Uextras) != 0 )
            {
                sprintf(fname,"accounts/%s/debits.%d",coin->symbol,bp->bundleheight);
                sprintf(fname2,"accounts/%s/lastspends.%d",coin->symbol,bp->bundleheight);
                if ( iter == 0 )
                {
                    vupdate_sha256(balancehash.bytes,&vstate,(void *)Aptr,sizeof(*Aptr)*numpkinds);
                    vupdate_sha256(balancehash.bytes,&vstate,(void *)Uptr,sizeof(*Uptr)*numunspents);
                }
                else if ( iter == 1 )
                {
                    if ( (fp= fopen(fname,"wb")) != 0 && (fp2= fopen(fname2,"wb")) != 0 )
                    {
                        err = -1;
                        if ( fwrite(&numhdrsi,1,sizeof(numhdrsi),fp) == sizeof(numhdrsi) && fwrite(&numhdrsi,1,sizeof(numhdrsi),fp2) == sizeof(numhdrsi) && fwrite(balancehash.bytes,1,sizeof(balancehash),fp) == sizeof(balancehash) && fwrite(balancehash.bytes,1,sizeof(balancehash),fp2) == sizeof(balancehash) )
                        {
                            if ( fwrite(Aptr,sizeof(*Aptr),numpkinds,fp) == numpkinds )
                            {
                                if ( fwrite(Uptr,sizeof(*Uptr),numunspents,fp2) == numunspents )
                                {
                                    //bp->dirty = 0;
                                    err = 0;
                                    //free(bp->ramchain.A), bp->ramchain.A = 0;
                                    //free(bp->ramchain.Uextras), bp->ramchain.Uextras = 0;
                                    printf("[%d] of %d saved (%s) and (%s)\n",hdrsi,numhdrsi,fname,fname2);
                                }
                            }
                        }
                        if ( err != 0 )
                        {
                            printf("balanceflush.%s error iter.%d hdrsi.%d\n",coin->symbol,iter,hdrsi);
                            fclose(fp);
                            fclose(fp2);
                            return(-1);
                        }
                        fclose(fp), fclose(fp2);
                    }
                    else
                    {
                        printf("error opening %s or %s %p\n",fname,fname2,fp);
                        if ( fp != 0 )
                            fclose(fp);
                    }
                }
                else if ( iter == 2 )
                {
                    sprintf(destfname,"DB/%s/accounts/debits.%d",coin->symbol,bp->bundleheight);
                    if ( OS_copyfile(fname,destfname,1) < 0 )
                    {
                        printf("balances error copying (%s) -> (%s)\n",fname,destfname);
                        return(-1);
                    }
                    sprintf(destfname,"DB/%s/accounts/lastspends.%d",coin->symbol,bp->bundleheight);
                    if ( OS_copyfile(fname2,destfname,1) < 0 )
                    {
                        printf("balances error copying (%s) -> (%s)\n",fname2,destfname);
                        return(-1);
                    }
                    printf("%s %s\n",fname,destfname);
                    /*if ( hdrsi > numhdrsi-purgedist && numhdrsi >= purgedist )
                     {
                     sprintf(destfname,"DB/%s/accounts/debits_%d.%d",coin->symbol,numhdrsi-purgedist,bp->bundleheight);
                     OS_removefile(destfname,0);
                     sprintf(destfname,"DB/%s/accounts/lastspends_%d.%d",coin->symbol,numhdrsi-purgedist,bp->bundleheight);
                     OS_removefile(destfname,0);
                     }*/
                }
            }
            else
            {
                printf("balanceflush iter.%d error loading [%d] Aptr.%p Uptr.%p numpkinds.%u numunspents.%u\n",iter,hdrsi,Aptr,Uptr,numpkinds,numunspents);
                return(-1);
            }
        }
    }
    coin->balancehash = balancehash;
    coin->balanceswritten = numhdrsi;
    for (hdrsi=0; hdrsi<numhdrsi; hdrsi++)
        if ( (bp= coin->bundles[hdrsi]) == 0 )
        {
            if ( bp->ramchain.A != 0 )
            {
                free(bp->ramchain.A);
                bp->ramchain.A = 0;
                bp->ramchain.allocatedA = 0;
            }
            if ( bp->ramchain.Uextras != 0 )
            {
                free(bp->ramchain.Uextras);
                bp->ramchain.Uextras = 0;
                bp->ramchain.allocatedU = 0;
            }
            if ( iguana_mapvolatiles(coin,&bp->ramchain) != 0 )
                printf("error mapping bundle.[%d]\n",hdrsi);
        }
    char str[65]; printf("BALANCES WRITTEN for %d bundles %s\n",coin->balanceswritten,bits256_str(str,coin->balancehash));
    coin->balanceswritten = iguana_volatileinit(coin);
    iguana_RTramchainfree(coin);
    return(coin->balanceswritten);
}

int32_t iguana_balancecalc(struct iguana_info *coin,struct iguana_bundle *bp,int32_t startheight,int32_t endheight)
{
    uint32_t starttime,j=0,flag = 0; struct iguana_bundle *prevbp;
    if ( bp->balancefinish > 1 )
    {
        printf("make sure DB files have this bp.%d\n",bp->hdrsi);
        iguana_validateQ(coin,bp);
        return(flag);
    }
    if ( bp != 0 && coin != 0 && (bp->hdrsi == 0 || (prevbp= coin->bundles[bp->hdrsi-1]) != 0) )
    {
#ifdef IGUANA_SERIALIZE_BALANCEGEN
        for (j=0; j<coin->bundlescount-1; j++)
        {
            if ( (prevbp= coin->bundles[j]) == 0 || prevbp->utxofinish <= 1 )
            {
                j = -1;
                break;
            }
        }
#endif
        if ( j != -1 )
        {
            for (j=0; j<bp->hdrsi; j++)
            {
                if ( (prevbp= coin->bundles[j]) == 0 || prevbp->utxofinish <= 1 || prevbp->balancefinish <= 1 )
                {
                    j = -1;
                    break;
                }
            }
        }
        // printf("B [%d] j.%d u.%u b.%u\n",bp->hdrsi,j,bp->utxofinish,bp->balancefinish);
        if ( bp->bundleheight+bp->n < coin->blocks.hwmchain.height && bp->utxofinish > 1 && bp->balancefinish <= 1 && (bp->hdrsi == 0 || bp->hdrsi == j) )
        {
            starttime = (uint32_t)time(NULL);
            for (j=0; j<=bp->hdrsi; j++)
                iguana_allocvolatile(coin,&coin->bundles[j]->ramchain);
            if ( iguana_balancegen(coin,bp,startheight,endheight) < 0 )
            {
                printf("GENERATE BALANCES ERROR ht.%d\n",bp->bundleheight);
                exit(-1);
            }
            bp->balancefinish = (uint32_t)time(NULL);
            printf("GENERATED BALANCES for ht.%d duration %d seconds\n",bp->bundleheight,bp->balancefinish - (uint32_t)starttime);
            bp->queued = 0;
            iguana_validateQ(coin,bp);
            if ( bp->hdrsi >= coin->longestchain/coin->chain->bundlesize-1 && bp->hdrsi >= coin->balanceswritten )
            {
                iguana_balanceflush(coin,bp->hdrsi,3);
                printf("balanceswritten.%d flushed bp->hdrsi %d vs %d coin->longestchain/coin->chain->bundlesize\n",coin->balanceswritten,bp->hdrsi,coin->longestchain/coin->chain->bundlesize);
            }
            flag++;
        }
        else
        {
            //printf("third case.%d utxo.%u balance.%u prev.%u\n",bp->hdrsi,bp->utxofinish,bp->balancefinish,prevbp!=0?prevbp->utxofinish:-1);
            coin->pendbalances--;
            iguana_balancesQ(coin,bp);
        }
    }
    return(flag);
}

int32_t iguana_bundlevalidate(struct iguana_info *coin,struct iguana_bundle *bp)
{
    if ( bp->validated <= 1 )
    {
        bp->validated = (uint32_t)time(NULL);
        //printf("VALIDATE.%d %u\n",bp->bundleheight,bp->validated);
    }
    return(0);
}