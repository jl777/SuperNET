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
#include "exchanges777.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_schnorr.h"
#include "secp256k1/include/secp256k1_rangeproof.h"

const char *Hardcoded_coins[][3] = { { "BTC", "bitcoin", "0" }, { "BTCD", "BitcoinDark", "129" },  { "VPN", "VPNcoin", "129" }, { "LTC", "litecoin", "129" } , { "endmarker", "", "" } };

struct iguana_info *iguana_coinfind(char *symbol)
{
    struct iguana_info *coin=0; uint32_t symbolcrc; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    while ( myinfo->allcoins_being_added != 0 )
    {
        printf("wait for coinadd to complete, OK if rare\n");
        sleep(1);
    }
    symbolcrc = calc_crc32(0,symbol,(int32_t)strlen(symbol));
    //portable_mutex_lock(&myinfo->allcoins_mutex);
        HASH_FIND(hh,myinfo->allcoins,&symbolcrc,sizeof(coin->symbolcrc),coin);
    //portable_mutex_unlock(&myinfo->allcoins_mutex);
    return(coin);
}

struct iguana_info *iguana_coinadd(char *symbol,char *name,cJSON *argjson,int32_t virtcoin)
{
    struct iguana_info *coin; uint32_t symbolcrc; char *privatechain; int32_t j; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (coin= iguana_coinfind(symbol)) == 0 )
    {
        if ( (coin= iguana_coinfind(symbol)) == 0 )
        {
            myinfo->allcoins_being_added = 1;
            coin = mycalloc('C',1,sizeof(*coin));
            coin->blockspacesize = IGUANA_MAXPACKETSIZE + 8192;
            coin->blockspace = calloc(1,coin->blockspacesize);
            if ( virtcoin != 0 || ((privatechain= jstr(argjson,"geckochain")) != 0 && privatechain[0] != 0) )
            {
                myinfo->allcoins_numvirts++;
                coin->virtualchain = 1;
            }
            else
            {
                coin->chain = iguana_chainfind((char *)symbol,argjson,1);
                coin->peers = calloc(1,sizeof(*coin->peers));
                for (j=0; j<IGUANA_MAXPEERS; j++)
                {
                    coin->peers->active[j].usock = -1;
                    strcpy(coin->peers->active[j].coinname,name);
                    strcpy(coin->peers->active[j].symbol,symbol);
                }
            }
            if ( (coin->protocol= juint(argjson,"protocol")) == 0 )
                coin->protocol = IGUANA_PROTOCOL_BITCOIN;
            coin->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            secp256k1_pedersen_context_initialize(coin->ctx);
            secp256k1_rangeproof_context_initialize(coin->ctx);
            strcpy(coin->name,name);
            strcpy(coin->symbol,symbol);
            iguana_initcoin(coin,argjson);
            basilisk_functions(coin,coin->protocol);
            printf("ADD ALLCOINS.(%s) name.(%s) size %ld numvirts.%d\n",symbol,name,sizeof(*coin),myinfo->allcoins_numvirts);
            coin->symbolcrc = symbolcrc = calc_crc32(0,symbol,(int32_t)strlen(symbol));
            //portable_mutex_lock(&myinfo->allcoins_mutex);
                HASH_ADD(hh,myinfo->allcoins,symbolcrc,sizeof(coin->symbolcrc),coin);
            //portable_mutex_unlock(&myinfo->allcoins_mutex);
            struct iguana_info *virt,*tmp;
            HASH_ITER(hh,myinfo->allcoins,virt,tmp)
            {
                printf("%s ",virt->symbol);
            }
            printf("allcoins\n");
            myinfo->allcoins_being_added = 0;
        }
        if ( (coin= iguana_coinfind(symbol)) == 0 )
            printf("error finding justadded.(%s)\n",symbol);
    }
    return(coin);
}

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    //coin->blocks.ptrs = myrealloc('W',coin->blocks.ptrs,coin->blocks.ptrs==0?0:coin->blocks.maxbits * sizeof(*coin->blocks.ptrs),numitems * sizeof(*coin->blocks.ptrs));
    //coin->blocks.RO = myrealloc('W',coin->blocks.RO,coin->blocks.RO==0?0:coin->blocks.maxbits * sizeof(*coin->blocks.RO),numitems * sizeof(*coin->blocks.RO));
    //printf("realloc waitingbits.%d -> %d\n",coin->blocks.maxbits,numitems);
    //coin->blocks.maxbits = numitems;
}

static int _decreasing_double(const void *a,const void *b)
{
#define double_a (*(double *)a)
#define double_b (*(double *)b)
	if ( double_b > double_a )
		return(1);
	else if ( double_b < double_a )
		return(-1);
	return(0);
#undef double_a
#undef double_b
}

static int32_t revsortds(double *buf,uint32_t num,int32_t size)
{
	qsort(buf,num,size,_decreasing_double);
	return(0);
}

double iguana_metric(struct iguana_peer *addr,uint32_t now,double decay)
{
    int32_t duration; double metric = addr->recvblocks * addr->recvtotal;
    addr->recvblocks *= decay;
    addr->recvtotal *= decay;
    if ( now >= addr->ready && addr->ready != 0 )
        duration = (now - addr->ready + 1);
    else duration = 1;
    if ( metric < SMALLVAL && duration > 300 )
        metric = 0.001;
    else metric /= duration;
    return(metric);
}

int32_t iguana_peermetrics(struct supernet_info *myinfo,struct iguana_info *coin)
{
    int32_t i,ind,n; double *sortbuf,sum; uint32_t now; struct iguana_peer *addr,*slowest = 0;
    //printf("peermetrics\n");
    sortbuf = mycalloc('s',coin->MAXPEERS,sizeof(double)*2);
    coin->peers->mostreceived = 0;
    now = (uint32_t)time(NULL);
    for (i=n=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers->active[i];
        if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 || addr->ipbits == 0 )
            continue;
        addr->pendblocks >>= 1;
        addr->pendhdrs >>= 1;
        if ( addr->recvblocks > coin->peers->mostreceived )
            coin->peers->mostreceived = addr->recvblocks;
        //printf("[%.0f %.0f] ",addr->recvblocks,addr->recvtotal);
        sortbuf[n*2 + 0] = iguana_metric(addr,now,.995);
        sortbuf[n*2 + 1] = i;
        n++;
    }
    if ( n > 0 )
    {
        revsortds(sortbuf,n,sizeof(double)*2);
        portable_mutex_lock(&coin->peers_mutex);
        for (sum=i=0; i<n; i++)
        {
            if ( i < coin->MAXPEERS )
            {
                coin->peers->topmetrics[i] = sortbuf[i*2];
                ind = (int32_t)sortbuf[i*2 +1];
                coin->peers->ranked[i] = &coin->peers->active[ind];
                if ( sortbuf[i*2] > SMALLVAL && (double)i/n > .8 && (time(NULL) - addr->ready) > 77 )
                    slowest = coin->peers->ranked[i];
                //printf("(%.5f %s) ",sortbuf[i*2],coin->peers->ranked[i]->ipaddr);
                coin->peers->ranked[i]->rank = i + 1;
                sum += coin->peers->topmetrics[i];
            }
        }
        coin->peers->numranked = n;
        portable_mutex_unlock(&coin->peers_mutex);
        //printf("NUMRANKED.%d\n",n);
        if ( i > 0 )
        {
            coin->peers->avemetric = (sum / i);
            if ( i >= 7*(coin->MAXPEERS/8) && slowest != 0 )
            {
                printf("prune slowest peer.(%s) numranked.%d MAXpeers->%d\n",slowest->ipaddr,n,coin->MAXPEERS);
                slowest->dead = 1;
            }
        }
    }
    myfree(sortbuf,coin->MAXPEERS * sizeof(double) * 2);
    return(coin->peers->mostreceived);
}

void *iguana_kviAddriterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    char ipaddr[64]; int32_t i; FILE *fp = (FILE *)(long)args; struct iguana_peer *addr; struct iguana_iAddr *iA = value;
    if ( fp != 0 && iA != 0 && iA->numconnects > 0 && iA->lastconnect > time(NULL)-IGUANA_RECENTPEER )
    {
        for (i=0; i<coin->peers->numranked; i++)
            if ( (addr= coin->peers->ranked[i]) != 0 && addr->ipbits == iA->ipbits )
                break;
        if ( i == coin->peers->numranked )
        {
            expand_ipbits(ipaddr,iA->ipbits);
            fprintf(fp,"%s\n",ipaddr);
        }
    }
    return(0);
}

uint32_t iguana_updatemetrics(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char fname[512],tmpfname[512],oldfname[512],ipaddr[64]; int32_t i,j; struct iguana_peer *addr,*tmpaddr; FILE *fp;
    iguana_peermetrics(myinfo,coin);
    sprintf(fname,"%s/%s_peers.txt",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(fname);
    sprintf(oldfname,"%s/%s_oldpeers.txt",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(oldfname);
    sprintf(tmpfname,"%s/%s/peers.txt",GLOBAL_TMPDIR,coin->symbol), OS_compatible_path(tmpfname);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        for (i=0; i<coin->peers->numranked; i++)
        {
            if ( (addr= coin->peers->ranked[i]) != 0 && addr->relayflag != 0 && strcmp(addr->ipaddr,"127.0.0.1") != 0 )
            {
                for (j=0; j<coin->peers->numranked; j++)
                {
                    if ( i != j && (tmpaddr= coin->peers->ranked[j]) != 0 && (uint32_t)addr->ipbits == (uint32_t)tmpaddr->ipbits )
                        break;
                }
                if ( j == coin->peers->numranked )
                {
                    expand_ipbits(ipaddr,(uint32_t)addr->ipbits);
                    fprintf(fp,"%s\n",ipaddr);
                    if ( 0 && addr->msgcounts.verack == 0 )
                    {
                        printf("iguana_sendblockreq (%s) addrind.%d hasn't verack'ed yet\n",addr->ipaddr,addr->addrind);
                        iguana_send_version(coin,addr,coin->myservices);
                    }
                }
            }
        }
        if ( ftell(fp) > OS_filesize(fname) )
        {
            printf("new peers.txt %ld vs (%s) %ld (%s)\n",ftell(fp),fname,(long)OS_filesize(fname),GLOBAL_CONFSDIR);
            fclose(fp);
            OS_renamefile(fname,oldfname);
            OS_copyfile(tmpfname,fname,1);
        } else fclose(fp);
    }
    else
    {
        printf("iguana_updatemetrics: couldnt create.(%s)\n",tmpfname);
        return(0);
    }
    return((uint32_t)time(NULL));
}

void iguana_emitQ(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_helper *ptr;
    ptr = mycalloc('i',1,sizeof(*ptr));
    ptr->allocsize = sizeof(*ptr);
    ptr->coin = coin;
    ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
    ptr->type = 'E';
    ptr->starttime = (uint32_t)time(NULL);
    //printf("%s EMIT.%d[%d] emitfinish.%u\n",coin->symbol,ptr->hdrsi,bp->n,bp->emitfinish);
    queue_enqueue("emitQ",&emitQ,&ptr->DL,0);
}

void iguana_bundleQ(struct iguana_info *coin,struct iguana_bundle *bp,int32_t timelimit)
{
    struct iguana_helper *ptr;
    if ( 0 && bp->queued == 0 && bp->emitfinish <= 1 && iguana_bundleready(coin,bp,0) == bp->n )
        printf("bundle.[%d] is ready\n",bp->hdrsi);
    bp->queued = (uint32_t)time(NULL);
    ptr = mycalloc('i',1,sizeof(*ptr));
    ptr->allocsize = sizeof(*ptr);
    ptr->coin = coin;
    ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
    ptr->type = 'B';
    ptr->starttime = (uint32_t)time(NULL);
    ptr->timelimit = timelimit;
    coin->numbundlesQ++;
    if ( 0 && bp->hdrsi > 170 )
        printf("%s %p bundle.%d[%d] ht.%d emitfinish.%u\n",coin->symbol,bp,ptr->hdrsi,bp->n,bp->bundleheight,bp->emitfinish);
    queue_enqueue("bundlesQ",&bundlesQ,&ptr->DL,0);
}

void iguana_validateQ(struct iguana_info *coin,struct iguana_bundle *bp)
{
    /*struct iguana_helper *ptr;
    //if ( bp->validated <= 1 )
    {
        ptr = mycalloc('i',1,sizeof(*ptr));
        ptr->allocsize = sizeof(*ptr);
        ptr->coin = coin;
        ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
        ptr->type = 'V';
        ptr->starttime = (uint32_t)time(NULL);
        ptr->timelimit = 0;
        bp->validated = 1;
        //printf("VALIDATE Q %s bundle.%d[%d] utxofinish.%u balancefinish.%u\n",coin->symbol,ptr->hdrsi,bp->n,bp->utxofinish,bp->balancefinish);
        queue_enqueue("validateQ",&validateQ,&ptr->DL,0);
    }*/
}

int32_t iguana_emitfinished(struct iguana_info *coin,int32_t queueincomplete)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( bp->emitfinish > 1 )
                n++;
            else if ( bp->emitfinish == 0  && bp->queued == 0 )
                iguana_bundleQ(coin,bp,1000);
        }
    }
    return(n);
}

int32_t iguana_utxofinished(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->utxofinish > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_convertfinished(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->converted > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_balancefinished(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->balancefinish > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_validated(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->validated > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_helperA(struct supernet_info *myinfo,struct iguana_info *coin,int32_t helperid,struct iguana_bundle *bp,int32_t convertflag)
{
    int32_t retval,num = 0;
    if ( bp == 0 )
    {
        printf("iguana_helperA unexpected null bp\n");
        return(-1);
    }
    //printf("helperid.%d validate gen utxo.[%d] utxofinish.%u\n",helperid,bp->hdrsi,bp->utxofinish);
    if ( strcmp("BTC",coin->symbol) == 0 || iguana_bundlevalidate(coin,bp,0) == bp->n ) //
    {
        retval = 0;
        if ( bp->utxofinish > 1 || (retval= iguana_spendvectors(myinfo,coin,bp,&bp->ramchain,0,bp->n,convertflag,0)) >= 0 )
        {
            if ( retval > 0 )
            {
                printf("GENERATED UTXO.%d for ht.%d duration %d seconds\n",bp->hdrsi,bp->bundleheight,(uint32_t)time(NULL) - bp->startutxo);
                num++;
            }
            bp->utxofinish = (uint32_t)time(NULL);
        } else printf("UTXO gen.[%d] utxo error\n",bp->hdrsi);
    }
    else
    {
        printf("error validating.[%d], restart iguana\n",bp->hdrsi);
        exit(-1);
    }
    return(num);
}

int32_t iguana_helperB(struct iguana_info *coin,int32_t helperid,struct iguana_bundle *bp,int32_t convertflag)
{
    if ( bp == 0 )
    {
        printf("iguana_helperB unexpected null bp\n");
        return(-1);
    }
    if ( bp != coin->current )
    {
        iguana_ramchain_prefetch(coin,&bp->ramchain,7);
        if ( convertflag == 0 )
        {
            bp->converted = 1;
            iguana_convert(coin,helperid,bp,0,0);
        }
        bp->converted = (uint32_t)time(NULL);
        return(1);
    }
    return(0);
}

void iguana_update_balances(struct iguana_info *coin)
{
    int32_t i,hdrsi,max; struct iguana_bundle *bp;
    max = coin->bundlescount;
    if ( coin->bundles[max-1] != 0 && coin->bundles[max-1]->emitfinish <= 1 )
        max--;
    if ( iguana_balancefinished(coin) < max && iguana_spendvectorsaves(coin) == 0 )
    {
        if ( 1 || coin->origbalanceswritten <= 1 )
            hdrsi = 0;
        else hdrsi = coin->origbalanceswritten;
        for (i=0; i<max; i++)
            if ( (bp= coin->bundles[i]) != 0 && bp != coin->current )
            {
                iguana_volatilespurge(coin,&bp->ramchain);
                iguana_volatilesalloc(coin,&bp->ramchain,i < hdrsi);
            }
        for (; hdrsi<max; hdrsi++)
        {
            if ( (bp= coin->bundles[hdrsi]) != 0 )
            {
                //iguana_ramchain_prefetch(coin,&bp->ramchain,3);
                if ( iguana_balancegen(coin,0,bp,0,coin->chain->bundlesize-1,0) == 0 )
                    bp->balancefinish = (uint32_t)time(NULL);
            }
        }
        if ( max != coin->origbalanceswritten )
        {
            coin->balanceflush = max+1;
            while ( coin->balanceflush != 0 )
                sleep(3);
        } else printf("skip flush when max.%d and orig.%d\n",max,coin->origbalanceswritten);
    }
}

int32_t iguana_utxogen(struct supernet_info *myinfo,struct iguana_info *coin,int32_t helperid,int32_t convertflag)
{
    int32_t hdrsi,n,i,max,incr,num = 0; struct iguana_bundle *bp;
    //if ( helperid != 0 )
    //    return(0);
    if ( coin->spendvectorsaved > 1 )
    {
        printf("skip utxogen as spendvectorsaved.%u\n",coin->spendvectorsaved);
        return(0);
    }
    printf("helperid.%d start utxogen\n",helperid);
    if ( (incr= IGUANA_NUMHELPERS) > 8 )
        incr = 8;
    //if ( 1 || coin->PREFETCHLAG > 0 ) // data issues on slow systems
    //    incr = 1;
    max = coin->bundlescount;
    if ( coin->bundles[max-1] != 0 && coin->bundles[max-1]->emitfinish <= 1 )
        max--;
    if ( helperid < incr )
    {
        for (hdrsi=helperid; hdrsi<max; hdrsi+=incr)
            num += iguana_helperA(myinfo,coin,helperid,coin->bundles[hdrsi],convertflag);
    }
    while ( (n= iguana_utxofinished(coin)) < max )
    {
        printf("helperid.%d utxofinished.%d vs %d\n",helperid,n,max);
        sleep(IGUANA_NUMHELPERS+3);
    }
    if ( helperid < incr )
    {
        for (hdrsi=helperid; hdrsi<max; hdrsi+=incr)
            num += iguana_helperB(coin,helperid,coin->bundles[hdrsi],convertflag);
    }
    while ( (n= iguana_convertfinished(coin)) < max )
    {
        //printf("helperid.%d convertfinished.%d vs max %d bundlescount.%d\n",helperid,n,max,coin->bundlescount);
        sleep(IGUANA_NUMHELPERS+3);
    }
    if ( helperid == 0 )
    {
        iguana_update_balances(coin);
        if ( 1 )
        {
            for (i=0; i<max; i++)
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    iguana_volatilespurge(coin,&bp->ramchain);
                    iguana_volatilesmap(coin,&bp->ramchain);
                }
        }
    }
    while ( iguana_balancefinished(coin) < max || coin->balanceflush != 0 )
        sleep(3);
    //printf("helper.%d check validates\n",helperid);
    //incr = IGUANA_NUMHELPERS;
    //incr = 1;
    if ( helperid < incr )
    {
        for (hdrsi=helperid; hdrsi<max; hdrsi+=incr)
        {
            if ( (bp= coin->bundles[hdrsi]) == 0 )
                break;
            if ( iguana_bundlevalidate(coin,bp,0) != bp->n )
            {
                printf("validate.[%d] error. refresh page or restart iguana and it should regenerate\n",bp->hdrsi);
                exit(-1);
            } // else printf("%s helperid.%d validated.[%d]\n",coin->symbol,helperid,hdrsi);
        }
    }
    while ( iguana_validated(coin) < max || iguana_utxofinished(coin) < max || iguana_balancefinished(coin) < max )
    {
        printf("%s helperid.%d waiting for spendvectorsaved.%u v.%d u.%d b.%d vs max.%d\n",coin->symbol,helperid,coin->spendvectorsaved,iguana_validated(coin),iguana_utxofinished(coin),iguana_balancefinished(coin),max);
        sleep(IGUANA_NUMHELPERS+3);
    }
    if ( helperid == 0 )
    {
        coin->spendvectorsaved = (uint32_t)time(NULL);
        coin->spendvalidated = 0;
        printf("%s UTXOGEN spendvectorsaved <- %u\n",coin->symbol,coin->spendvectorsaved);
    }
    else
    {
        while ( coin->spendvectorsaved <= 1 )
            sleep(IGUANA_NUMHELPERS+3);
    }
    printf("%s helper.%d helperdone\n",coin->symbol,helperid);
    return(num);
}

void iguana_helper(void *arg)
{
    static uint64_t helperidbits;
    cJSON *argjson=0; int32_t iter,n,j,polltimeout,type,helperid=rand(),flag,allcurrent,idle=0;
    struct iguana_helper *ptr; struct iguana_info *coin,*tmp; struct OS_memspace MEM,*MEMB; struct iguana_bundle *bp; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    helperid %= 64;
    if ( arg != 0 && (argjson= cJSON_Parse(arg)) != 0 )
        helperid = juint(argjson,"helperid");
    if ( ((1 << helperid) & helperidbits) != 0 )
    {
        printf("SKIP duplicate helper.%d\n",helperid);
        return;
    }
    helperidbits |= (1 << helperid);
    if ( IGUANA_NUMHELPERS < 2 )
        type = 3;
    else type = (1 << (helperid % 2));
    if ( argjson != 0 )
        free_json(argjson);
    printf("HELPER.%d started arg.(%s) type.%d\n",helperid,(char *)(arg!=0?arg:0),type);
    memset(&MEM,0,sizeof(MEM));
    MEMB = mycalloc('b',IGUANA_MAXBUNDLESIZE,sizeof(*MEMB));
    sleep(2);
    while ( 1 )
    {
        //printf("helperid.%d top of loop\n",helperid);
        flag = 0;
        //iguana_jsonQ(); cant do this here
        allcurrent = 1;
        polltimeout = 100;
        //portable_mutex_lock(&myinfo->allcoins_mutex);
        HASH_ITER(hh,myinfo->allcoins,coin,tmp)
        {
            if ( coin->spendvectorsaved == 1 )
                iguana_utxogen(myinfo,coin,helperid,0);
            else if ( coin->spendvectorsaved > 1 && (coin->spendvalidated & (1 << helperid)) == 0 )
            {
                //printf("%s spendvectorsaved.%u helperid.%d validate\n",coin->symbol,coin->spendvectorsaved,helperid);
                for (j=helperid; j<coin->bundlescount-1; j+=IGUANA_NUMHELPERS)
                    if ( (bp= coin->bundles[j]) != 0 )
                        iguana_bundlevalidate(coin,bp,0);
                coin->spendvalidated |= (1 << helperid);
                //printf("DONE %s spendvectorsaved.%u helperid.%d validate\n",coin->symbol,coin->spendvectorsaved,helperid);
            }
        }
        //portable_mutex_unlock(&myinfo->allcoins_mutex);
        n = queue_size(&bundlesQ);
        for (iter=0; iter<n; iter++)
        {
            if ( (ptr= queue_dequeue(&bundlesQ,0)) != 0 )
            {
                idle = 0;
                coin = ptr->coin;
                if ( (bp= ptr->bp) != 0 && coin != 0 )
                {
                    if ( coin->polltimeout < polltimeout )
                        polltimeout = coin->polltimeout;
                    if ( coin->current != 0 && coin->current->hdrsi != coin->bundlescount-1 )
                        allcurrent = 0;
                    //printf("[%d] bundleQ size.%d lag.%ld\n",bp->hdrsi,queue_size(&bundlesQ),time(NULL) - bp->nexttime);
                    coin->numbundlesQ--;
                    if ( coin->started != 0 && (bp->nexttime == 0 || time(NULL) > bp->nexttime) && coin->active != 0 )
                    {
                        flag += iguana_bundleiters(myinfo,ptr->coin,&MEM,MEMB,bp,ptr->timelimit,IGUANA_DEFAULTLAG);
                    }
                    else
                    {
                        //printf("skip.[%d] nexttime.%u lag.%ld coin->active.%d\n",bp->hdrsi,bp->nexttime,time(NULL)-bp->nexttime,coin->active);
                        allcurrent--;
                        iguana_bundleQ(coin,bp,1000);
                    }
                }
                else //if ( coin->active != 0 )
                    printf("helper missing param? %p %p %u\n",ptr->coin,bp,ptr->timelimit);
                myfree(ptr,ptr->allocsize);
            } else break;
        }
        if ( queue_size(&bundlesQ) > 1 )
            allcurrent = 0;
        if ( flag != 0 )
            usleep(polltimeout * 100 + 1);
        else if ( allcurrent > 0 )
        {
            //printf("bundlesQ allcurrent\n");
            usleep(polltimeout * 10000);
        }
        else usleep(polltimeout * 5000);
    }
}

void iguana_callcoinstart(struct supernet_info *myinfo,struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t bundlei; bits256 zero; char dirname[512],*symbol;
    iguana_rwiAddrind(coin,0,0,0);
    //for (i=0; i<sizeof(*coin->chain); i++)
    //    printf("%02x",((uint8_t *)coin->chain)[i]);
    char str[65]; printf(" netmagic.%08x init.(%s) maxpeers.%d maxrecvcache.%s services.%llx MAXMEM.%s polltimeout.%d cache.%d pend.(%d -> %d)\n",*(uint32_t *)coin->chain->netmagic,coin->symbol,coin->MAXPEERS,mbstr(str,coin->MAXRECVCACHE),(long long)coin->myservices,mbstr(str,coin->MAXMEM),coin->polltimeout,coin->enableCACHE,coin->startPEND,coin->endPEND);
    symbol = coin->symbol;
    sprintf(dirname,"%s/ro",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/ro/%s",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/purgeable/%s",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/validated",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/accounts",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/spends",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/vouts",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    if ( coin->VALIDATEDIR[0] != 0 )
    {
        sprintf(dirname,"%s",coin->VALIDATEDIR), OS_ensure_directory(dirname);
        sprintf(dirname,"%s/%s",coin->VALIDATEDIR,symbol), OS_ensure_directory(dirname);
    }
    sprintf(dirname,"%s/%s",GLOBAL_TMPDIR,symbol), OS_ensure_directory(dirname);
    iguana_coinstart(coin,coin->initialheight,coin->mapflags);
    coin->chain->minconfirms = coin->minconfirms;
    coin->started = coin;
    coin->startutc = (uint32_t)time(NULL);
    memset(zero.bytes,0,sizeof(zero));
    if ( (bp= iguana_bundlecreate(coin,&bundlei,0,*(bits256 *)coin->chain->genesis_hashdata,zero,1)) != 0 )
        bp->bundleheight = 0;
    iguana_datachain_scan(myinfo,coin,CRYPTO777_RMD160);
}

void iguana_coinloop(void *arg)
{
    struct supernet_info *myinfo; int32_t flag,i,n; bits256 zero; uint32_t now; struct iguana_info *coin,**coins = arg;
    myinfo = SuperNET_MYINFO(0);
    n = (int32_t)(long)coins[0];
    coins++;
    coin = coins[0];
    printf("begin coinloop[%d] %s\n",n,coin->symbol);
    memset(zero.bytes,0,sizeof(zero));
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                if ( coin->peers == 0 )
                {
                    printf("FATAL lack of peers struct\n");
                    exit(-1);
                    iguana_launchpeer(coin,"127.0.0.1");
                }
                if ( coin->virtualchain == 0 )
                {
                    if ( coin->MAXPEERS > IGUANA_MAXPEERS )
                        coin->MAXPEERS = IGUANA_MAXPEERS;
                    if ( coin->MAXPEERS > 1 && coin->MAXPEERS < IGUANA_MINPEERS )
                        coin->MAXPEERS = IGUANA_MAXPEERS;
#ifdef __PNACL__
                    if ( coin->MAXPEERS > 64 )
                        coin->MAXPEERS = 64;
#endif
                }
                if ( coin->started == 0 && coin->active != 0 )
                {
                    iguana_callcoinstart(myinfo,coin);
                }
                now = (uint32_t)time(NULL);
                coin->idletime = 0;
                if ( coin->started != 0 && coin->active != 0 )
                {
                    // printf("%s numranked.%d isRT.%d numsaved.%d M.%d L.%d numverified.%d hdrsi.%d\n",coin->symbol,coin->peers->numranked,coin->isRT,coin->numsaved,coin->blocks.hwmchain.height,coin->longestchain,coin->numverified,coin->current!=0?coin->current->hdrsi:-1);
                    if ( coin->peers->numranked > 4 && coin->isRT == 0 && now > coin->startutc+77 && coin->numsaved >= (coin->longestchain/coin->chain->bundlesize)*coin->chain->bundlesize && coin->blocks.hwmchain.height >= coin->longestchain-30 )
                    {
                        fprintf(stderr,">>>>>>> %s isRT blockrecv.%d.%d\n",coin->symbol,coin->blocksrecv,coin->longestchain);
                        coin->isRT = 1;
                        if ( coin->polltimeout > 100 )
                            coin->polltimeout = 100;
                        if ( coin->MAXPEERS > IGUANA_MINPEERS )
                            coin->MAXPEERS = IGUANA_MINPEERS;
                    }
                    /*if ( coin->isRT != 0 && coin->current != 0 && coin->numverified >= coin->current->hdrsi )
                    {
                        //static int32_t saved;
                        //if ( saved++ == 0 )
                        //    iguana_coinflush(coin,1);
                    }*/
                    if ( coin->bindsock >= 0 )
                    {
                        if ( coin->MAXPEERS > 1 && coin->peers->numranked < IGUANA_MAXPEERS/2 && now > coin->lastpossible+10 )
                        {
                            //fprintf(stderr,"check possible\n");
                            if ( coin->peers->numranked > 0 && (now % 60) == 0 )
                                iguana_send_ping(myinfo,coin,coin->peers->ranked[rand() % coin->peers->numranked]);
                            coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                        }
                    }
                    else
                    {
                        if ( coin->MAXPEERS > 1 && coin->peers->numranked < ((7*coin->MAXPEERS)>>3) && now > coin->lastpossible+10 )
                        {
                            if ( coin->peers->numranked > 0 && (now % 60) == 0 )
                                iguana_send_ping(myinfo,coin,coin->peers->ranked[rand() % coin->peers->numranked]);
                            coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                        }
                    }
                    if ( coin->MAXPEERS > 1 && now > coin->peers->lastmetrics+10 )
                    {
                        coin->peers->lastmetrics = iguana_updatemetrics(myinfo,coin); // ranks peers
                    }
                    //if ( coin->longestchain+10000 > coin->blocks.maxbits )
                    //    iguana_recvalloc(coin,coin->longestchain + 100000);
                    if ( coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 || coin->MAXPEERS == 1 )
                    {
                        flag += iguana_processrecv(myinfo,coin);
                        if ( strcmp(coin->symbol,"BTCD") == 0 && coin->RTheight > 0 && coin->RTheight > coin->chain->bundlesize )
                        {
                            int32_t hdrsi,nonz,errs; struct iguana_pkhash *refP; struct iguana_bundle *bp;
                            hdrsi = (coin->RTheight / coin->chain->bundlesize) - 1;
                            if ( (bp= coin->bundles[hdrsi]) != 0 && bp->weights == 0 )
                                bp->weights = iguana_PoS_weights(myinfo,coin,&refP,&bp->supply,&bp->numweights,&nonz,&errs,bp->bundleheight);
                        }
                    }
                    iguana_jsonQ();
                } //else if ( strcmp(coin->symbol,"BTC") == 0 )
                  //  printf("skip %s\n",coin->symbol);
                coin->idletime = (uint32_t)time(NULL);
            }
        }
        //printf("%s flag.%d isRT.%d polltimeout.%d numranked.%d\n",coin->symbol,flag,coin->isRT,coin->polltimeout,coin->peers->numranked);
        if ( flag == 0 && coin->isRT == 0 && coin->peers != 0 )
            usleep(coin->polltimeout*1000 + (coin->peers->numranked == 0)*1000000);
        else if ( coin->current != 0 && coin->current->hdrsi == coin->longestchain/coin->chain->bundlesize )
            usleep(coin->polltimeout*1000 + 90000 + (coin->peers->numranked == 0)*1000000);
        else usleep(coin->polltimeout*1000);
    }
}

void iguana_coinargs(char *symbol,int64_t *maxrecvcachep,int32_t *minconfirmsp,int32_t *maxpeersp,int32_t *initialheightp,uint64_t *servicesp,int32_t *maxrequestsp,int32_t *maxbundlesp,cJSON *json)
{
    if ( (*maxrecvcachep= j64bits(json,"maxrecvcache")) != 0 )
        *maxrecvcachep *= 1024 * 1024 * 1024L;
    *minconfirmsp = juint(json,"minconfirms");
    *maxpeersp = juint(json,"maxpeers");
    *maxrequestsp = juint(json,"maxrequests");
    *maxbundlesp = juint(json,"maxbundles");
    if ( (*initialheightp= juint(json,"initialheight")) == 0 )
        *initialheightp = (strcmp(symbol,"BTC") == 0) ? 400000 : 100000;
    *servicesp = j64bits(json,"services");
}

void iguana_nameset(char name[64],char *symbol,cJSON *json)
{
    if ( strcmp("BTC",symbol) == 0 )
        strcpy(name,"Bitcoin");
    else if ( strcmp("BTCD",symbol) == 0 )
        strcpy(name,"BitcoinDark");
    else
    {
        name[0] = 0;
        if ( json != 0 )
            safecopy(name,jstr(json,"name"),64);
        if ( name[0] == 0 )
            strcpy(name,symbol);
    }
}

struct iguana_info *iguana_setcoin(char *symbol,void *launched,int32_t maxpeers,int64_t maxrecvcache,uint64_t services,int32_t initialheight,int32_t maphash,int32_t minconfirms,int32_t maxrequests,int32_t maxbundles,cJSON *json,int32_t virtcoin)
{
    struct iguana_chain *iguana_createchain(cJSON *json);
    struct iguana_info *coin; int32_t j,m,mult,maxval,mapflags; char name[64]; cJSON *peers;
    mapflags = IGUANA_MAPRECVDATA | maphash*IGUANA_MAPTXIDITEMS | maphash*IGUANA_MAPPKITEMS | maphash*IGUANA_MAPBLOCKITEMS | maphash*IGUANA_MAPPEERITEMS;
    iguana_nameset(name,symbol,json);
    if ( (coin= iguana_coinfind(symbol)) == 0 )
        coin = iguana_coinadd(symbol,name,json,virtcoin);
    //printf("ensure directories maxval.%d mult.%d start.%d end.%d\n",maxval,mult,coin->startPEND,coin->endPEND);
    mult = (strcmp("BTC",coin->symbol) != 0) ? 8 : 32;
    maxval = IGUANA_MAXPENDBUNDLES;
    if ( coin->virtualchain == 0 )
    {
        if ( (coin->MAXPEERS= maxpeers) <= 0 )
            coin->MAXPEERS = (strcmp(symbol,"BTC") == 0) ? 128 : 64;
        if ( (coin->MAXRECVCACHE= maxrecvcache) == 0 )
            coin->MAXRECVCACHE = IGUANA_MAXRECVCACHE;
        if ( (coin->MAXPENDINGREQUESTS= maxrequests) <= 0 )
            coin->MAXPENDINGREQUESTS = (strcmp(symbol,"BTC") == 0) ? IGUANA_MAXPENDINGREQUESTS : IGUANA_PENDINGREQUESTS;
        if ( jobj(json,"prefetchlag") != 0 )
            coin->PREFETCHLAG = jint(json,"prefetchlag");
        else if ( strcmp("BTC",coin->symbol) == 0 )
            coin->PREFETCHLAG = 13;
        else coin->PREFETCHLAG = -1;
        if ( (coin->MAXSTUCKTIME= juint(json,"maxstuck")) == 0 )
            coin->MAXSTUCKTIME = _IGUANA_MAXSTUCKTIME;
        if ( (coin->startPEND= juint(json,"startpend")) == 0 )
        {
            if ( strcmp("BTCD",coin->symbol) == 0 )
                coin->startPEND = 500;
            else coin->startPEND = IGUANA_MAXPENDBUNDLES*mult;
        }
        if ( coin->startPEND > maxval*mult )
            coin->startPEND = maxval*mult;
        else if ( coin->startPEND < 2 )
            coin->startPEND = 2;
        coin->MAXBUNDLES = coin->startPEND;
        if ( (coin->endPEND= juint(json,"endpend")) == 0 )
        {
            if ( strcmp("BTCD",coin->symbol) == 0 )
                coin->endPEND = 500;
            else coin->endPEND = IGUANA_MINPENDBUNDLES*mult;
        }
        if ( coin->endPEND > maxval*mult )
            coin->endPEND = maxval*mult;
        else if ( coin->endPEND < 2 )
            coin->endPEND = 2;
#ifdef __PNACL__
        coin->startPEND =  coin->endPEND = 1;
#endif
    } else coin->MAXPEERS = 0;
    coin->myservices = services;
    coin->initialheight = initialheight;
    coin->mapflags = mapflags;
    coin->protocol = IGUANA_PROTOCOL_BITCOIN;
    if ( (coin->txfee= jdouble(json,"txfee") * SATOSHIDEN) == 0 )
        coin->txfee = 10000;
    if ( (coin->txfee_perkb= j64bits(json,"txfee_perkb")) < coin->txfee/8 )
        coin->txfee_perkb = coin->txfee / 8;
    coin->MAXMEM = juint(json,"RAM");
    if ( coin->MAXMEM == 0 )
        coin->MAXMEM = IGUANA_DEFAULTRAM;
    coin->MAXMEM *= (1024L * 1024 * 1024);
    coin->enableCACHE = (strcmp("BTCD",coin->symbol) == 0);
    if ( jobj(json,"cache") != 0 )
        coin->enableCACHE = juint(json,"cache");
    if ( (coin->polltimeout= juint(json,"poll")) <= 0 )
        coin->polltimeout = IGUANA_DEFAULT_POLLTIMEOUT;
    coin->active = juint(json,"active");
    if ( (coin->minconfirms = minconfirms) == 0 )
        coin->minconfirms = (strcmp(symbol,"BTC") == 0) ? 3 : 10;
    if ( coin->chain == 0 && (coin->chain= iguana_createchain(json)) == 0 )
    {
        printf("cant initialize chain.(%s)\n",jstr(json,0));
        strcpy(coin->name,"illegalcoin");
        coin->symbol[0] = 0;
        return(0);
    }
    if ( jobj(json,"RELAY") != 0 )
        coin->RELAYNODE = juint(json,"RELAY");
    else coin->RELAYNODE = (strcmp(coin->symbol,"BTCD") == 0);
    if ( jobj(json,"VALIDATE") != 0 )
        coin->VALIDATENODE = juint(json,"VALIDATE");
    else coin->VALIDATENODE = (strcmp(coin->symbol,"BTCD") == 0);
    if ( coin->VALIDATENODE != 0 || coin->RELAYNODE != 0 )
        SuperNET_MYINFO(0)->IAMRELAY++;
#ifdef __PNACL
    coin->VALIDATENODE = coin->RELAYNODE = 0;
#endif
    if ( jobj(json,"validatedir") != 0 )
        safecopy(coin->VALIDATEDIR,jstr(json,"validatedir"),sizeof(coin->VALIDATEDIR));
    else strcpy(coin->VALIDATEDIR,GLOBAL_VALIDATEDIR);
    if ( (peers= jarray(&m,json,"peers")) != 0 )
    {
        for (j=0; j<m; j++)
        {
            printf("%s ",jstr(jitem(peers,j),0));
            iguana_possible_peer(coin,jstr(jitem(peers,j),0));
        }
        printf("addnodes.%d\n",m);
    }
    char str[65];
    if ( coin->virtualchain == 0 )
        printf("pend.(%d -> %d) MAXMEM.%s enablecache.%d VALIDATEDIR.(%s) VALIDATE.%d RELAY.%d\n",coin->startPEND,coin->endPEND,mbstr(str,coin->MAXMEM),coin->enableCACHE,coin->VALIDATEDIR,coin->VALIDATENODE,coin->RELAYNODE);
    return(coin);
}

int32_t iguana_launchcoin(struct supernet_info *myinfo,char *symbol,cJSON *json,int32_t virtcoin)
{
    int32_t maxpeers,maphash,initialheight,minconfirms,maxrequests,maxbundles; char name[64]; int64_t maxrecvcache; uint64_t services; struct iguana_info **coins,*coin;
    if ( symbol == 0 )
        return(-1);
    if ( (coin= iguana_coinfind(symbol)) != 0 )
        return(0);
    iguana_nameset(name,symbol,json);
    printf("launchcoin.%s name.%s\n",symbol,name);
    if ( (coin= iguana_coinadd(symbol,name,json,virtcoin)) == 0 )
        return(-1);
    if ( myinfo->rpcsymbol[0] == 0 || iguana_coinfind(myinfo->rpcsymbol) == 0 )
        strcpy(myinfo->rpcsymbol,symbol);
    if ( coin->launched == 0 )
    {
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,&maxrequests,&maxbundles,json);
        coins = mycalloc('A',1+1,sizeof(*coins));
        if ( (coin= iguana_setcoin(symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,maxrequests,maxbundles,json,virtcoin)) != 0 )
        {
            coins[0] = (void *)((long)1);
            coins[1] = coin;
            printf("launch.%p coinloop for.%s services.%llx started.%p peers.%p\n",coin,coin->symbol,(long long)services,coin->started,coin->peers);
            coin->launched = iguana_launch(coin,"iguana_coinloop",iguana_coinloop,coins,IGUANA_PERMTHREAD);
            coin->active = 1;
            coin->started = 0;
            if ( strcmp("BTCD",coin->symbol) == 0 )
            {
                char *str;
                if ( (str= basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits("78.47.196.146"),GENESIS_PUBKEY)) != 0 )
                    free(str);
                if ( (str= basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits("5.9.102.210"),GENESIS_PUBKEY)) != 0 )
                    free(str);
            }
            return(1);
        }
        else
        {
            printf("launchcoin: couldnt initialize.(%s)\n",symbol);
            myfree(coins,sizeof(*coins) * 2);
            return(-1);
        }
    }
    return(0);
}

void iguana_coins(void *arg)
{
    struct iguana_info **coins,*coin; char *jsonstr,*symbol; cJSON *array,*item,*json;
    int32_t i,n,maxpeers,maphash,initialheight,minconfirms,maxrequests,maxbundles;
    int64_t maxrecvcache; uint64_t services; struct vin_info V; struct supernet_info *myinfo;
    myinfo = SuperNET_MYINFO(0);
    memset(&V,0,sizeof(V));
    if ( (jsonstr= arg) != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (array= jarray(&n,json,"coins")) == 0 )
        {
            if ( (symbol= jstr(json,"coin")) != 0 && strncmp(symbol,"BTC",3) == 0 )
            {
                coins = mycalloc('A',1+1,sizeof(*coins));
                if ( (coins[1]= iguana_setcoin(symbol,coins,0,0,0,0,0,0,0,0,json,0)) != 0 )
                {
                    _iguana_calcrmd160(coins[1],&V);
                    coins[0] = (void *)((long)1);
                    iguana_coinloop(coins);
                }
                else
                {
                    printf("iguana_coins: couldnt initialize.(%s)\n",symbol);
                    return;
                }
            } else printf("no coins[] array in JSON.(%s) only BTCD and BTC can be quicklaunched\n",jsonstr);
            free_json(json);
            return;
        }
        coins = mycalloc('A',n+1,sizeof(*coins));
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (symbol= jstr(item,"name")) == 0 || strlen(symbol) > 8 )
            {
                printf("skip strange coin.(%s)\n",symbol);
                continue;
            }
            iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,&maxrequests,&maxbundles,item);
            coins[1 + i] = coin = iguana_setcoin(symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,maxrequests,maxbundles,item,0);
            if ( coin == 0 )
            {
                printf("iguana_coins: couldnt initialize.(%s)\n",symbol);
                return;
            }
        }
        coins[0] = (void *)((long)n);
        iguana_coinloop(coins);
    }
}

char *busdata_sync(uint32_t *noncep,char *jsonstr,char *broadcastmode,char *destNXTaddr)
{
    printf("busdata_sync.(%s)\n",jsonstr);
    return(0);
}
