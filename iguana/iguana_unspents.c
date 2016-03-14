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
                    *lastunspentindp = ACCTS[pkind].lastind;
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

struct iguana_bundle *iguana_spent(struct iguana_info *coin,bits256 *prevhashp,uint32_t *unspentindp,struct iguana_ramchain *ramchain,int32_t spend_hdrsi,struct iguana_spend *s)
{
    int32_t prev_vout,height,hdrsi; uint32_t sequenceid,unspentind; char str[65];
    struct iguana_bundle *spentbp=0; struct iguana_txid *T,TX,*tp; bits256 *X; bits256 prev_hash;
    X = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Xoffset);
    T = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Toffset);
    sequenceid = s->sequenceid;
    hdrsi = spend_hdrsi;
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
                unspentind = TX.firstvout + ((prev_vout > 0) ? prev_vout : 0);
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

int32_t iguana_spentsinit(struct iguana_info *coin,struct iguana_bundleind *spents,struct iguana_bundle *bp,struct iguana_ramchain *ramchain)
{
    int32_t spendind,n,max,hdrsi,errs,flag; uint32_t unspentind; struct iguana_bundle *spentbp;
    struct iguana_spend *S; bits256 prevhash;
    S = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Soffset);
    max = ramchain->H.data->numunspents;
    n = ramchain->H.data->numspends;
    for (spendind=1,errs=0; spendind<n; spendind++)
    {
        flag = 0;
        hdrsi = bp->hdrsi;
        if ( (spentbp= iguana_spent(coin,&prevhash,&unspentind,ramchain,bp->hdrsi,&S[spendind])) != 0 )
        {
            spentbp->ramchain.spents[unspentind].ind = spendind;
            spentbp->ramchain.spents[unspentind].hdrsi = bp->hdrsi;
            flag = 1;
            if ( S[spendind].external == 0 && spentbp != bp )
                printf("spentsinit unexpected spendbp: %p bp.[%d] U%d <- S%d.[%d] [%p %p %p]\n",&spentbp->ramchain.spents[unspentind],hdrsi,unspentind,spendind,bp->hdrsi,coin->bundles[0],coin->bundles[1],coin->bundles[2]);
        }
        else if ( S[spendind].prevout < 0 )
            flag = 1;
        else printf("unresolved spendind.%d hdrsi.%d\n",spendind,bp->hdrsi);
        if ( flag == 0 )
            errs++;
    }
    printf("processed %d spendinds for bp.[%d] -> errs.%d\n",spendind,bp->hdrsi,errs);
    return(-errs);
}

// if file exists and is valid, load and then process only the incremental
long iguana_spentsfile(struct iguana_info *coin,int32_t n)
{
    int32_t i,iter,allocated = 0; long filesize,total,count; struct iguana_bundleind *spents = 0; struct iguana_ramchain *ramchain; char fname[1024]; struct iguana_bundle *bp; FILE *fp;
    fname[0] = 0;
    for (total=iter=0; iter<2; iter++)
    {
        for (count=i=0; i<n; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
            {
                ramchain = &bp->ramchain;
                if ( ramchain->H.data != 0 )
                {
                    if ( iter == 1 )
                    {
                        ramchain->spents = &spents[count];
                        //printf("bp.[%d] count.%ld %p\n",i,count,ramchain->spents);
                        if ( allocated != 0 && iguana_spentsinit(coin,spents,bp,ramchain) < 0 )
                        {
                            printf("error initializing spents bp.%d\n",i);
                            exit(-1);
                        }
                    }
                    count += ramchain->H.data->numunspents;
                } else break;
            } else return(-1);
        }
        if ( i < n )
            n = (i + 1);
        sprintf(fname,"DB/%s/spents_%d.%ld",coin->symbol,n,count);
        printf("%s total unspents.%ld\n",fname,count);
        if ( iter == 0 )
        {
            total = count;
            if ( (spents= OS_filestr(&filesize,fname)) == 0 )
                spents = calloc(total,sizeof(*spents)), allocated = 1;
        }
        else if ( total != count )
            printf("%s total.%ld != count.%ld\n",fname,total,count);
    }
    if ( allocated != 0 && fname[0] != 0 && (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(spents,total,sizeof(*spents),fp);
        fclose(fp);
    }
    return(total);
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
    if ( ramchain->spents == 0 )
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
        if ( ramchain->spents[unspentind].ind == 0 )
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

int32_t iguana_utxogen(struct iguana_info *coin,struct iguana_bundle *bp)
{
    static uint64_t total,emitted;
    int32_t spendind,n,errs=0,emit=0; uint32_t unspentind; struct iguana_bundle *spentbp;
    FILE *fp; char fname[1024],str[65],dirname[128]; int32_t hdrsi,retval = -1; bits256 prevhash,zero,sha256;
    struct iguana_spend *S,*s; struct iguana_bundleind *ptr; struct iguana_ramchain *ramchain;
    ramchain = &bp->ramchain;
    printf("UTXO gen.%d ramchain data.%p\n",bp->bundleheight,ramchain->H.data);
    if ( ramchain->H.data == 0 || (n= ramchain->H.data->numspends) < 1 )
        return(0);
    S = (void *)(long)((long)ramchain->H.data + ramchain->H.data->Soffset);
    if ( ramchain->Xspendinds != 0 )
    {
        //printf("iguana_utxogen: already have Xspendinds[%d]\n",ramchain->numXspends);
        return(0);
    }
    ptr = mycalloc('x',sizeof(*ptr),n);
    total += n;
    //printf("start UTXOGEN.%d max.%d ptr.%p\n",bp->bundleheight,n,ptr);
    for (spendind=ramchain->H.data->firsti; spendind<n; spendind++)
    {
        s = &S[spendind];
        if ( s->external != 0 && s->prevout >= 0 )
        {
            if ( (spentbp= iguana_spent(coin,&prevhash,&unspentind,ramchain,bp->hdrsi,s)) != 0 )
            {
                ptr[emit].ind = unspentind;
                ptr[emit].hdrsi = spentbp->hdrsi;
                emit++;
                //spentbp->ramchain.spents[unspentind].ind = spendind;
                //spentbp->ramchain.spents[unspentind].hdrsi = bp->hdrsi;
                if ( spentbp == bp )
                {
                    char str[65];
                    printf("unexpected spendbp: %p bp.[%d] U%d <- S%d.[%d] [ext.%d %s prev.%d]\n",&spentbp->ramchain.spents[unspentind],spentbp->hdrsi,unspentind,spendind,bp->hdrsi,s->external,bits256_str(str,prevhash),s->prevout);
                    errs++;
                }
            } else printf("unresolved spendind.%d hdrsi.%d\n",spendind,bp->hdrsi);
        }
    }
    if ( errs == 0 && emit >= 0 )
    {
        emitted += emit;
        memset(zero.bytes,0,sizeof(zero));
        sprintf(dirname,"DB/%s/utxo",coin->symbol);
        vcalc_sha256(0,sha256.bytes,(void *)ptr,(int32_t)(sizeof(*ptr) * emit));
        if ( iguana_peerfname(coin,&hdrsi,dirname,fname,0,bp->hashes[0],zero,bp->n) >= 0 )
        {
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                if ( fwrite(sha256.bytes,1,sizeof(sha256),fp) != sizeof(sha256) )
                    printf("error writing hash for %ld -> (%s)\n",sizeof(*ptr) * emit,fname);
                else if ( fwrite(ptr,sizeof(*ptr),emit,fp) != emit )
                    printf("error writing %d of %d -> (%s)\n",emit,n,fname);
                else retval = 0;
                fclose(fp);
                if ( iguana_Xspendmap(coin,ramchain,bp) < 0 )
                {
                    printf("error mapping Xspendmap.(%s)\n",fname);
                    retval = -1;
                }
                //printf("filesize %ld Xspendptr.%p %p num.%d\n",ftell(fp),ramchain->Xspendptr,ramchain->Xspendinds,ramchain->numXspends);
            } else printf("Error creating.(%s)\n",fname);
        } else printf("error getting utxo fname\n");
    }
    myfree(ptr,sizeof(*ptr) * n);
    printf("utxo %d spendinds.[%d] errs.%d [%.2f%%] emitted.%d %s of %d | ",spendind,bp->hdrsi,errs,100.*(double)emitted/(total+1),emit,mbstr(str,sizeof(*ptr) * emit),n);
    return(-errs);
}

int32_t iguana_balancegen(struct iguana_info *coin,struct iguana_bundle *bp)
{
    printf("BALANCEGEN.%d\n",bp->bundleheight);
    return(0);
}

int32_t iguana_bundlevalidate(struct iguana_info *coin,struct iguana_bundle *bp)
{
    printf("VALIDATE.%d\n",bp->bundleheight);
    return(0);
}