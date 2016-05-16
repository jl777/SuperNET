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

struct iguana_hhutxo *iguana_hhutxofind(struct iguana_info *coin,uint64_t uval)
{
    struct iguana_hhutxo *hhutxo;
    HASH_FIND(hh,coin->utxotable,&uval,sizeof(uval),hhutxo);
    return(hhutxo);
}

struct iguana_hhaccount *iguana_hhaccountfind(struct iguana_info *coin,uint64_t pval)
{
    struct iguana_hhaccount *hhacct;
    HASH_FIND(hh,coin->accountstable,&pval,sizeof(pval),hhacct);
    return(hhacct);
}

int32_t iguana_utxoupdate(struct iguana_info *coin,int16_t spent_hdrsi,uint32_t spent_unspentind,uint32_t spent_pkind,uint64_t spent_value,uint32_t spendind,uint32_t fromheight)
{
    struct iguana_hhutxo *hhutxo,*tmputxo; struct iguana_hhaccount *hhacct,*tmpacct; uint64_t uval,pval;
    if ( spent_hdrsi < 0 )
    {
        printf(">>>>>>>>>>> RESET UTXO HASH <<<<<<<<<\n");
        if ( coin->utxotable != 0 )
        {
            HASH_ITER(hh,coin->utxotable,hhutxo,tmputxo)
            {
                hhutxo->u.lockedflag = 0;
                hhutxo->u.spentflag = 0;
                hhutxo->u.fromheight = 0;
                hhutxo->u.prevunspentind = 0;
            }
        }
        if ( coin->accountstable != 0 )
        {
            HASH_ITER(hh,coin->accountstable,hhacct,tmpacct)
            {
                hhacct->a.lastunspentind = 0;
                hhacct->a.total = 0;
            }
        }
        return(0);
    }
    uval = ((uint64_t)spent_hdrsi << 32) | spent_unspentind;
    pval = ((uint64_t)spent_hdrsi << 32) | spent_pkind;
    if ( (hhutxo= iguana_hhutxofind(coin,uval)) != 0 && hhutxo->u.spentflag != 0 )
    {
        printf("hhutxo.%p spentflag.%d\n",hhutxo,hhutxo->u.spentflag);
        return(-1);
    }
    hhutxo = calloc(1,sizeof(*hhutxo));
    hhutxo->uval = uval;
    HASH_ADD_KEYPTR(hh,coin->utxotable,&hhutxo->uval,sizeof(hhutxo->uval),hhutxo);
    if ( (hhacct= iguana_hhaccountfind(coin,pval)) == 0 )
    {
        hhacct = calloc(1,sizeof(*hhacct));
        hhacct->pval = pval;
        HASH_ADD_KEYPTR(hh,coin->accountstable,&hhacct->pval,sizeof(hhacct->pval),hhacct);
    }
    //printf("create hhutxo.%p hhacct.%p from.%d\n",hhutxo,hhacct,fromheight);
    hhutxo->u.spentflag = 1;
    hhutxo->u.lockedflag = 0;
    hhutxo->u.fromheight = fromheight;
    hhutxo->u.prevunspentind = hhacct->a.lastunspentind;
    hhacct->a.lastunspentind = spent_unspentind;
    hhacct->a.total += spent_value;
    return(0);
}

struct iguana_utxo iguana_utxofind(struct iguana_info *coin,int16_t spent_hdrsi,uint32_t spent_unspentind,int32_t *RTspendflagp,int32_t lockflag)
{
    uint64_t val,uval; struct iguana_hhutxo *hhutxo; struct iguana_utxo utxo; struct iguana_ramchain *ramchain; struct iguana_bundle *bp;
    *RTspendflagp = 0;
    memset(&utxo,0,sizeof(utxo));
    if ( (bp= coin->bundles[spent_hdrsi]) == 0 )
        return(utxo);
    ramchain = (bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
    val = ((uint64_t)spent_hdrsi << 32) | spent_unspentind;
    if ( spent_unspentind > 0 && spent_unspentind < ramchain->H.data->numunspents )
    {
        if ( ramchain->Uextras != 0 )
        {
            utxo = ramchain->Uextras[spent_unspentind];
            if ( lockflag != 0 )
            {
                if ( (hhutxo= iguana_hhutxofind(coin,val)) == 0 )
                {
                    uval = ((uint64_t)spent_hdrsi << 32) | spent_unspentind;
                    if ( (hhutxo= iguana_hhutxofind(coin,uval)) != 0 && hhutxo->u.spentflag != 0 )
                    {
                        printf("iguana_hhutxofind warning: hhutxo.%p spentflag.%d\n",hhutxo,hhutxo->u.spentflag);
                        memset(&utxo,0,sizeof(utxo));
                        return(utxo);
                    }
                    hhutxo = calloc(1,sizeof(*hhutxo));
                    hhutxo->uval = uval;
                    HASH_ADD_KEYPTR(hh,coin->utxotable,&hhutxo->uval,sizeof(hhutxo->uval),hhutxo);
                }
            }
        }
        if ( ramchain->Uextras == 0 || utxo.spentflag == 0 )
        {
            //printf("check hhutxo [%d] u%u %p\n",spent_hdrsi,spent_unspentind,iguana_hhutxofind(coin,((uint64_t)202<<32)|3909240));
            if ( (hhutxo= iguana_hhutxofind(coin,val)) != 0 )
            {
                if ( lockflag != 0 )
                {
                    if ( hhutxo->u.lockedflag == 0 )
                        hhutxo->u.lockedflag = 1;
                    else printf("iguana_hhutxofind warning: locking already locked [%d].%u\n",spent_hdrsi,spent_unspentind);
                } else hhutxo->u.lockedflag = 0;
                utxo = hhutxo->u;
                if ( utxo.spentflag != 0 || utxo.lockedflag != 0 )
                    *RTspendflagp = 1;
            }
        }
    } else printf("illegal unspentind.%u vs %u hdrs.%d\n",spent_unspentind,ramchain->H.data->numunspents,spent_hdrsi);
    return(utxo);
}

int32_t iguana_spentflag(struct iguana_info *coin,int64_t *RTspendp,int32_t *spentheightp,struct iguana_ramchain *ramchain,int16_t spent_hdrsi,uint32_t spent_unspentind,int32_t height,int32_t minconf,int32_t maxconf,uint64_t amount)
{
    uint32_t numunspents; int32_t RTspentflag; struct iguana_utxo utxo; uint64_t confs,RTspend = 0;
    *spentheightp = 0;
    numunspents = ramchain->H.data->numunspents;
    utxo = iguana_utxofind(coin,spent_hdrsi,spent_unspentind,&RTspentflag,0);
    if ( RTspentflag != 0 )
        *RTspendp = (amount == 0) ? coin->txfee : amount;
    if ( utxo.spentflag != 0 && utxo.fromheight == 0 )
    {
        printf("illegal unspentind.%u vs %u hdrs.%d zero fromheight?\n",spent_unspentind,numunspents,spent_hdrsi);
        return(-1);
    }
    //printf("[%d] u%u %.8f, spentheight.%d vs height.%d spentflag.%d\n",spent_hdrsi,spent_unspentind,dstr(amount),utxo.fromheight,height,utxo.spentflag);
    *spentheightp = utxo.fromheight;
    if ( (confs= coin->blocks.hwmchain.height - utxo.fromheight) >= minconf && confs < maxconf && (height <= 0 || utxo.fromheight < height) )
    {
        (*RTspendp) += RTspend;
        if ( utxo.spentflag != 0 )
            return(1);
        else if ( utxo.lockedflag != 0 )
            return(-1);
        else return(0);
    }
    return(0);
}

int32_t iguana_volatileupdate(struct iguana_info *coin,int32_t incremental,struct iguana_ramchain *spentchain,int16_t spent_hdrsi,uint32_t spent_unspentind,uint32_t spent_pkind,uint64_t spent_value,uint32_t spendind,uint32_t fromheight)
{
    struct iguana_account *A2; struct iguana_ramchaindata *rdata; struct iguana_utxo *utxo;
    if ( (rdata= spentchain->H.data) != 0 )
    {
        if ( incremental == 0 )
        {
            if ( spentchain->Uextras == 0 || spentchain->A2 == 0 )
                iguana_volatilesmap(coin,spentchain);
            if ( spentchain->Uextras != 0 && (A2= spentchain->A2) != 0 )
            {
                utxo = &spentchain->Uextras[spent_unspentind];
                if ( utxo->spentflag == 0 )
                {
                    if ( 0 && fromheight/coin->chain->bundlesize >= coin->current->hdrsi )
                        printf("iguana_volatileupdate.%d: [%d] spent.(u%u %.8f pkind.%d) fromht.%d [%d] spendind.%d\n",incremental,spent_hdrsi,spent_unspentind,dstr(spent_value),spent_pkind,fromheight,fromheight/coin->chain->bundlesize,spendind);
                    utxo->prevunspentind = A2[spent_pkind].lastunspentind;
                    utxo->spentflag = 1;
                    utxo->fromheight = fromheight;
                    A2[spent_pkind].total += spent_value;
                    A2[spent_pkind].lastunspentind = spent_unspentind;
                    return(0);
                }
                else
                {
                    printf("from.%d spent_unspentind[%d] in hdrs.[%d] is spent fromht.%d %.8f\n",fromheight,spent_unspentind,spent_hdrsi,utxo->fromheight,dstr(spent_value));
                }
            } else printf("null ptrs.[%d] u.%u p.%u %.8f from ht.%d s.%u\n",spent_hdrsi,spent_unspentind,spent_pkind,dstr(spent_value),fromheight,spendind);
        }
        else // do the equivalent of historical, ie mark as spent, linked list, balance
        {
            //double startmillis = OS_milliseconds(); static double totalmillis; static int32_t utxon;
            if ( iguana_utxoupdate(coin,spent_hdrsi,spent_unspentind,spent_pkind,spent_value,spendind,fromheight) == 0 )
            {
                /*totalmillis += (OS_milliseconds() - startmillis);
                 if ( (++utxon % 100000) == 0 )
                 printf("ave utxo[%d] %.2f micros total %.2f seconds\n",utxon,(1000. * totalmillis)/utxon,totalmillis/1000.);*/
                return(0);
            }
        }
        printf("iguana_volatileupdate.%d: [%d] spent.(u%u %.8f pkind.%d) double spend? at ht.%d [%d] spendind.%d (%p %p)\n",incremental,spent_hdrsi,spent_unspentind,dstr(spent_value),spent_pkind,fromheight,fromheight/coin->chain->bundlesize,spendind,spentchain->Uextras,spentchain->A2);
        if ( coin->current != 0 && fromheight >= coin->current->bundleheight )
            coin->RTdatabad = 1;
        else
        {
            printf("from.%d vs current.%d\n",fromheight,coin->current->bundleheight);
            iguana_bundleremove(coin,fromheight/coin->chain->bundlesize,0);
        }
        if ( coin->current != 0 && spent_hdrsi != coin->current->hdrsi )
            iguana_bundleremove(coin,spent_hdrsi,0);
        exit(-1);
    } else printf("volatileupdate error null rdata [%d]\n",spentchain->height/coin->current->bundleheight);
    return(-1);
}

void iguana_volatilesalloc(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t copyflag)
{
    int32_t i; struct iguana_utxo *U2; struct iguana_account *A2; struct iguana_ramchaindata *rdata = 0;
    if ( ramchain != 0 && (rdata= ramchain->H.data) != 0 && (coin->current == 0 || coin->current->bundleheight > ramchain->height) )
    {
        //printf("volatilesalloc.[%d] %p %p\n",ramchain->height/coin->chain->bundlesize,ramchain->debitsfileptr,ramchain->lastspendsfileptr);
        if ( ramchain->allocatedA2 == 0 )
        {
            ramchain->A2 = calloc(sizeof(*ramchain->A2),rdata->numpkinds + 16);
            ramchain->allocatedA2 = sizeof(*ramchain->A2) * rdata->numpkinds;
        }
        if ( ramchain->allocatedU2 == 0 )
        {
            ramchain->Uextras = calloc(sizeof(*ramchain->Uextras),rdata->numunspents + 16);
            ramchain->allocatedU2 = sizeof(*ramchain->Uextras) * rdata->numunspents;
        }
        if ( ramchain->debitsfileptr != 0 )
        {
            if ( copyflag != 0 )
            {
                A2 = (void *)((long)ramchain->debitsfileptr + sizeof(int32_t) + 2*sizeof(bits256));
                if ( ramchain->debitsfilesize != sizeof(int32_t) + 2*sizeof(bits256) + sizeof(*A2)*rdata->numpkinds )
                    printf("A2 size mismatch %ld != %d\n",ramchain->debitsfilesize,(int32_t)(sizeof(int32_t) + 2*sizeof(bits256) + sizeof(*A2)*rdata->numpkinds));
                for (i=0; i<rdata->numpkinds; i++)
                    ramchain->A2[i] = A2[i];
            }
            munmap(ramchain->debitsfileptr,ramchain->debitsfilesize);
            ramchain->debitsfileptr = 0;
            ramchain->debitsfilesize = 0;
        }
        if ( ramchain->lastspendsfileptr != 0 )
        {
            if ( copyflag != 0 )
            {
                U2 = (void *)((long)ramchain->lastspendsfileptr + sizeof(int32_t) + 2*sizeof(bits256));
                if ( ramchain->lastspendsfilesize != sizeof(int32_t) + 2*sizeof(bits256) + sizeof(*U2)*rdata->numunspents )
                    printf("U2 size mismatch %ld != %d\n",ramchain->lastspendsfilesize,(int32_t)(sizeof(int32_t) + 2*sizeof(bits256) + sizeof(*U2)*rdata->numunspents));
                for (i=0; i<rdata->numunspents; i++)
                    ramchain->Uextras[i] = U2[i];
            }
            munmap(ramchain->lastspendsfileptr,ramchain->lastspendsfilesize);
            ramchain->lastspendsfileptr = 0;
            ramchain->lastspendsfilesize = 0;
        }
    } else printf("illegal ramchain.%p rdata.%p\n",ramchain,rdata);
}

void iguana_volatilespurge(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    if ( ramchain != 0 )
    {
        //printf("volatilespurge.[%d] (%p %p) %p %p\n",ramchain->height/coin->chain->bundlesize,ramchain->A2,ramchain->Uextras,ramchain->debitsfileptr,ramchain->lastspendsfileptr);
        if ( ramchain->allocatedA2 != 0 && ramchain->A2 != 0 && ramchain->A2 != ramchain->debitsfileptr+sizeof(bits256)*2+sizeof(int32_t) )
            free(ramchain->A2);
        if ( ramchain->allocatedU2 != 0 && ramchain->Uextras != 0 && ramchain->Uextras != ramchain->lastspendsfileptr+sizeof(bits256)*2+sizeof(int32_t) )
            free(ramchain->Uextras);
        ramchain->A2 = 0;
        ramchain->Uextras = 0;
        ramchain->allocatedA2 = ramchain->allocatedU2 = 0;
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
}

int32_t iguana_volatilesmap(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    int32_t iter,numhdrsi,err = -1; char fname[1024]; bits256 balancehash,allbundles; struct iguana_ramchaindata *rdata;
    if ( (rdata= ramchain->H.data) == 0 )
    {
        if ( ramchain->height > 0 )
            printf("volatilesmap.[%d] no rdata\n",ramchain->height/coin->chain->bundlesize);
        return(-1);
    }
    if ( ramchain->debitsfileptr != 0 && ramchain->lastspendsfileptr != 0 )
        return(0);
    for (iter=0; iter<2; iter++)
    {
        sprintf(fname,"%s/%s%s/accounts/debits.%d",GLOBAL_DBDIR,iter==0?"ro/":"",coin->symbol,ramchain->height);
        if ( (ramchain->debitsfileptr= OS_mapfile(fname,&ramchain->debitsfilesize,0)) != 0 && ramchain->debitsfilesize == sizeof(int32_t) + 2*sizeof(bits256) + sizeof(*ramchain->A2) * ramchain->H.data->numpkinds )
        {
            ramchain->from_roA = (iter == 0);
            numhdrsi = *(int32_t *)ramchain->debitsfileptr;
            memcpy(balancehash.bytes,(void *)((long)ramchain->debitsfileptr + sizeof(numhdrsi)),sizeof(balancehash));
            memcpy(allbundles.bytes,(void *)((long)ramchain->debitsfileptr + sizeof(numhdrsi) + sizeof(balancehash)),sizeof(allbundles));
            if ( coin->balanceswritten == 0 )
            {
                coin->balanceswritten = numhdrsi;
                coin->balancehash = balancehash;
                coin->allbundles = allbundles;
            }
            if ( numhdrsi == coin->balanceswritten && memcmp(balancehash.bytes,coin->balancehash.bytes,sizeof(balancehash)) == 0 && memcmp(allbundles.bytes,coin->allbundles.bytes,sizeof(allbundles)) == 0 )
            {
                ramchain->A2 = (void *)((long)ramchain->debitsfileptr + sizeof(numhdrsi) + 2*sizeof(bits256));
                sprintf(fname,"%s/%s%s/accounts/lastspends.%d",GLOBAL_DBDIR,iter==0?"ro/":"",coin->symbol,ramchain->height);
                if ( (ramchain->lastspendsfileptr= OS_mapfile(fname,&ramchain->lastspendsfilesize,0)) != 0 && ramchain->lastspendsfilesize == sizeof(int32_t) + 2*sizeof(bits256) + sizeof(*ramchain->Uextras) * ramchain->H.data->numunspents )
                {
                    numhdrsi = *(int32_t *)ramchain->lastspendsfileptr;
                    memcpy(balancehash.bytes,(void *)((long)ramchain->lastspendsfileptr + sizeof(numhdrsi)),sizeof(balancehash));
                    memcpy(allbundles.bytes,(void *)((long)ramchain->lastspendsfileptr + sizeof(numhdrsi) + sizeof(balancehash)),sizeof(allbundles));
                    if ( numhdrsi == coin->balanceswritten && memcmp(balancehash.bytes,coin->balancehash.bytes,sizeof(balancehash)) == 0 && memcmp(allbundles.bytes,coin->allbundles.bytes,sizeof(allbundles)) == 0 )
                    {
                        ramchain->Uextras = (void *)((long)ramchain->lastspendsfileptr + sizeof(numhdrsi) + 2*sizeof(bits256));
                        ramchain->from_roU = (iter == 0);
                        //printf("volatilesmap.[%d] %p %p\n",ramchain->height/coin->chain->bundlesize,ramchain->debitsfileptr,ramchain->lastspendsfileptr);
                        err = 0;
                    } else printf("ramchain map error2 balanceswritten %d vs %d hashes %x %x\n",coin->balanceswritten,numhdrsi,coin->balancehash.uints[0],balancehash.uints[0]);
                } else printf("ramchain map error3 %s\n",fname);
            }
            else
            {
                printf("ramchain.[%d] map error balanceswritten %d vs %d hashes %x %x\n",ramchain->H.data->height,coin->balanceswritten,numhdrsi,coin->balancehash.uints[0],balancehash.uints[0]);
                err++;
                OS_removefile(fname,0);
            }
        }
        if ( err == 0 )
            return(0);
    }
    //printf("couldnt map [%d]\n",ramchain->height/coin->chain->bundlesize);
    iguana_volatilespurge(coin,ramchain);
    return(err);
}
