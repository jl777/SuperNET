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

void iguana_initQ(queue_t *Q,char *name)
{
    char *tst,*str = "need to init each Q when single threaded";
    memset(Q,0,sizeof(*Q));
    strcpy(Q->name,name);
    queue_enqueue(name,Q,queueitem(str),1);
    if ( (tst= queue_dequeue(Q,1)) != 0 )
        free_queueitem(tst);
}

void iguana_initQs(struct iguana_info *coin)
{
    int32_t i;
    iguana_initQ(&coin->acceptQ,"acceptQ");
    iguana_initQ(&coin->hdrsQ,"hdrsQ");
    iguana_initQ(&coin->blocksQ,"blocksQ");
    iguana_initQ(&coin->priorityQ,"priorityQ");
    iguana_initQ(&coin->possibleQ,"possibleQ");
    iguana_initQ(&coin->cacheQ,"cacheQ");
    iguana_initQ(&coin->recvQ,"recvQ");
    for (i=0; i<IGUANA_MAXPEERS; i++)
        iguana_initQ(&coin->peers.active[i].sendQ,"addrsendQ");
}

void iguana_initpeer(struct iguana_info *coin,struct iguana_peer *addr,uint64_t ipbits)
{
    memset(addr,0,sizeof(*addr));
    addr->ipbits = ipbits;
    addr->usock = -1;
    expand_ipbits(addr->ipaddr,(uint32_t)addr->ipbits);
    //addr->pending = (uint32_t)time(NULL);
    strcpy(addr->symbol,coin->symbol);
    strcpy(addr->coinstr,coin->name);
    iguana_initQ(&addr->sendQ,"addrsendQ");
}

void iguana_initcoin(struct iguana_info *coin,cJSON *argjson)
{
    int32_t i; char dirname[1024];
    sprintf(dirname,"%s/%s",GLOBAL_TMPDIR,coin->symbol), OS_portable_path(dirname);
    portable_mutex_init(&coin->peers_mutex);
    portable_mutex_init(&coin->blocks_mutex);
    iguana_meminit(&coin->blockMEM,"blockMEM",coin->blockspace,sizeof(coin->blockspace),0);
    iguana_initQs(coin);
    coin->bindsock = -1;
    OS_randombytes((unsigned char *)&coin->instance_nonce,sizeof(coin->instance_nonce));
    coin->startutc = (uint32_t)time(NULL);
    while ( time(NULL) == coin->startutc )
        usleep(1);
    coin->startutc++;
    printf("start.%u\n",coin->startutc);
    coin->startmillis = OS_milliseconds(), coin->starttime = tai_now(coin->startmillis);
    coin->avetime = 1 * 100;
    //coin->R.maxrecvbundles = IGUANA_INITIALBUNDLES;
    for (i=0; i<IGUANA_MAXPEERS; i++)
        coin->peers.active[i].usock = -1;
}

bits256 iguana_genesis(struct iguana_info *coin,struct iguana_chain *chain)
{
    struct iguana_block block,*ptr; struct iguana_msgblock msg; bits256 hash2; char str[65],str2[65]; uint8_t buf[1024]; int32_t height;
    if ( chain->genesis_hex == 0 )
    {
        printf("no genesis_hex for %s\n",coin->symbol);
        memset(hash2.bytes,0,sizeof(hash2));
        return(hash2);
    }
    decode_hex(buf,(int32_t)strlen(chain->genesis_hex)/2,(char *)chain->genesis_hex);
    hash2 = bits256_doublesha256(0,buf,sizeof(struct iguana_msgblockhdr));
    iguana_rwblock(0,&hash2,buf,&msg);
    if  ( memcmp(hash2.bytes,chain->genesis_hashdata,sizeof(hash2)) != 0 )
    {
        bits256_str(str,hash2);
        printf("genesis mismatch? calculated %s vs %s\n",str,bits256_str(str2,*(bits256 *)chain->genesis_hashdata));
        //hash2 = bits256_conv("00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99");
                             
        //memset(hash2.bytes,0,sizeof(hash2));
        //return(hash2);
    }
    bits256_str(str,hash2);
    printf("genesis.(%s) len.%d hash.%s\n",chain->genesis_hex,(int32_t)sizeof(msg.H),str);
    iguana_blockconv(&block,&msg,hash2,0);
    block.RO.txn_count = 1;
    block.RO.numvouts = 1;
    iguana_gotdata(coin,0,0);
    if ( (ptr= iguana_blockhashset("genesis0",coin,0,hash2,1)) != 0 )
    {
        iguana_blockcopy(coin,ptr,&block);
        ptr->mainchain = 1;
        ptr->height = 0;
        coin->blocks.RO[0] = block.RO;
        if ( (height= iguana_chainextend(coin,ptr)) == 0 )
        {
            block = *ptr;
            coin->blocks.recvblocks = coin->blocks.issuedblocks = 1;
        }
        else printf("genesis block doesnt validate for %s ht.%d\n",coin->symbol,height);
    } else printf("couldnt hashset genesis\n");
    if ( coin->blocks.hwmchain.height != 0 || fabs(coin->blocks.hwmchain.PoW - block.PoW) > SMALLVAL || memcmp(coin->blocks.hwmchain.RO.hash2.bytes,hash2.bytes,sizeof(hash2)) != 0 )
    {
        printf("%s genesis values mismatch hwmheight.%d %.15f %.15f %s\n",coin->name,coin->blocks.hwmchain.height,coin->blocks.hwmchain.PoW,block.PoW,bits256_str(str,coin->blocks.hwmchain.RO.hash2));
        getchar();
    }
    int32_t bundlei = -2;
    static const bits256 zero;
    iguana_bundlecreate(coin,&bundlei,0,hash2,zero,1);
    _iguana_chainlink(coin,iguana_blockfind("genesis",coin,hash2));
    return(hash2);
}

int32_t iguana_savehdrs(struct iguana_info *coin)
{
    char fname[512],shastr[65],tmpfname[512],tmpfname2[512],str2[65],str[65],oldfname[512];
    bits256 sha256all; FILE *fp,*fp2; struct iguana_bundle *bp; int32_t hdrsi,n,retval = 0;
    n = coin->blocks.hwmchain.height + 1;
    sprintf(tmpfname,"%s/%s/hdrs.txt",GLOBAL_TMPDIR,coin->symbol), OS_compatible_path(tmpfname);
    sprintf(tmpfname2,"%s/%s/hdrs.h",GLOBAL_TMPDIR,coin->symbol), OS_compatible_path(tmpfname);
    sprintf(oldfname,"%s/%s_oldhdrs.txt",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(oldfname);
    sprintf(fname,"%s/%s_hdrs.txt",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(fname);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        if ( (fp2= fopen(tmpfname2,"w")) != 0 )
            fprintf(fp2,"char *%s_hdrs[][4] = {\n",coin->symbol);
        fprintf(fp,"%d\n",n);
        for (hdrsi=0; hdrsi<coin->bundlescount; hdrsi++)
        {
            if ( (bp= coin->bundles[hdrsi]) != 0 && bp->numhashes >= bp->n )
            {
                shastr[0] = 0;
                if ( bits256_nonz(bp->allhash) == 0 )
                {
                    vcalc_sha256(shastr,sha256all.bytes,bp->hashes[0].bytes,sizeof(*bp->hashes) * coin->chain->bundlesize);
                    bp->allhash = sha256all;
                }
                else
                {
                    sha256all = bp->allhash;
                    bits256_str(shastr,bp->allhash);
                }
                fprintf(fp,"%d %s %s %s\n",bp->bundleheight,bits256_str(str,bp->hashes[0]),shastr,bits256_str(str2,bp->hashes[1]));
                if ( fp2 != 0 )
                    fprintf(fp2,"{ \"%d\", \"%s\", \"%s\", \"%s\"},\n",bp->bundleheight,bits256_str(str,bp->hashes[0]),shastr,bits256_str(str2,bp->hashes[1]));
            }
            else
            {
                if ( bp != 0 && bits256_nonz(bp->hashes[0]) != 0 )
                {
                    fprintf(fp,"%d %s\n",bp->bundleheight,bits256_str(str,bp->hashes[0]));
                    if ( fp2 != 0 )
                        fprintf(fp2,"{ \"%d\", \"%s\", \"%s\", \"%s\"},\n",bp->bundleheight,bits256_str(str,bp->hashes[0]),"","");
                }
                break;
            }
        }
        //printf("compare hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)OS_filesize(fname));
        if ( (long)ftell(fp) > OS_filesize(fname) )
        {
            printf("new hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)OS_filesize(fname));
            fclose(fp);
            OS_renamefile(fname,oldfname);
            OS_copyfile(tmpfname,fname,1);
        } else fclose(fp);
        if ( fp2 != 0 )
        {
            fprintf(fp2,"};\n");
            fclose(fp2);
        }
    }
    else
    {
        printf("iguana_savehdrs: couldnt create.(%s)\n",tmpfname);
        return(-1);
    }
    return(retval);
}

int32_t iguana_bundleinitmap(struct iguana_info *coin,struct iguana_bundle *bp,int32_t height,bits256 hash2,bits256 hash1)
{
    char str[65];  struct iguana_block *block;
    bp->bundleheight = height;
    if ( bits256_nonz(hash1) != 0 )
    {
        if ( (block= iguana_blockhashset("inithash1",coin,height+1,hash1,1)) != 0 )
        {
            iguana_bundlehashadd(coin,bp,1,block);
            block->mainchain = 1;
        }
    }
    if ( height == 0 && coin->current == 0 )
        coin->current = coin->bundles[0] = bp;
    if ( (block= iguana_blockfind("parse",coin,hash2)) != 0 )
        block->mainchain = 1, block->height = height;
    if ( iguana_bundleload(coin,&bp->ramchain,bp,2) != 0 )
    {
        if ( coin->current != 0 && coin->current->hdrsi+1 == bp->hdrsi )
            coin->current = bp;
        bp->emitfinish = (uint32_t)time(NULL) + 1;
        //printf("[%d %u] ",bp->hdrsi,bp->emitfinish);
        return(0);
    }
    else
    {
        init_hexbytes_noT(str,hash2.bytes,sizeof(hash2));
        bp->emitfinish = 0;
        iguana_blockQ("init",coin,bp,0,hash2,1);
        //printf("init reqhdrs.%d\n",bp->bundleheight);
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
        memset(&hash2,0,sizeof(hash2));
        bp->emitfinish = 0;
        return(-1);
    }
}

void iguana_parseline(struct iguana_info *coin,int32_t iter,FILE *fp)
{
    int32_t j,k,m,c,flag,bundlei,lastheight,height = -1; char checkstr[1024],line[1024];
    struct iguana_peer *addr; struct iguana_bundle *bp; bits256 allhash,hash2,hash1,zero,lastbundle;
    memset(&zero,0,sizeof(zero));
    lastbundle = zero;
    if ( coin->MAXPEERS > IGUANA_MAXPEERS )
        coin->MAXPEERS = IGUANA_MAXPEERS;
    if ( iter == 1 && 0 )
    {
        int32_t i; FILE *fp; char fname[512]; struct iguana_blockRO blockRO;
        sprintf(fname,"blocks.%s",coin->symbol), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            for (i=0; i<100000000; i++)
            {
                if ( fread(&blockRO,1,sizeof(blockRO),fp) != sizeof(blockRO) )
                    break;
                if ( i > (coin->blocks.maxbits - 1000) )
                    iguana_recvalloc(coin,i + 100000);
                coin->blocks.RO[i] = blockRO;
                char str[65];
                if ( bits256_nonz(blockRO.hash2) > 0 )
                    printf("init.%d %s\n",i,bits256_str(str,blockRO.hash2));
            }
            fclose(fp);
            printf("validate.%d blocks that were read in\n",i);
        }
    }
    m = flag = 0;
    allhash = zero;
    memset(line,0,sizeof(line));
    while ( fgets(line,sizeof(line),fp) > 0 )
    {
        j = (int32_t)strlen(line) - 1;
        line[j] = 0;
        //printf("parse line.(%s) maxpeers.%d\n",line,coin->MAXPEERS);
        if ( iter == 0 )
        {
            if ( m < coin->MAXPEERS-3 )//&& m < 77.7 )
            {
                if ( 0 && m == 0 )
                {
                    addr = &coin->peers.active[m++];
                    iguana_initpeer(coin,addr,(uint32_t)calc_ipbits("127.0.0.1"));
                    //printf("call initpeer.(%s)\n",addr->ipaddr);
                    iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
                }
#ifndef IGUANA_DISABLEPEERS
                addr = &coin->peers.active[m++];
                iguana_initpeer(coin,addr,(uint32_t)calc_ipbits(line));
                //printf("call initpeer.(%s)\n",addr->ipaddr);
                iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
#endif
            }
        }
        else
        {
            lastheight = height = -1;
            if ( coin->bundlescount > 0 && (bp= coin->bundles[coin->bundlescount - 1]) != 0 )
                lastheight = bp->bundleheight, lastbundle = bp->hashes[0];
            for (k=height=0; k<j-1; k++)
            {
                if ( (c= line[k]) == ' ' )
                    break;
                else if ( c >= '0' && c <= '9' )
                    height = (height * 10) + (line[k] - '0');
                else break;
            }
            if ( line[k] == ' ' )
            {
                decode_hex(hash2.bytes,sizeof(hash2),line+k+1);
                //printf("line.(%s) k.%d (%c)(%c)(%d)\n",line,k,line[k+63],line[k+64],line[k+65]);
                if ( height >= 0 && bits256_nonz(hash2) != 0 )
                {
                    if ( (bp= iguana_bundlecreate(coin,&bundlei,height,hash2,zero,0)) != 0 )
                    {
                        //printf("created bundle.%d\n",bp->hdrsi);
                        lastbundle = hash2;
                    }
                }
                if ( line[k + 65] != 0 && line[k+65] != '\n'  && line[k+65] != '\r' )
                {
                    if ( height > (coin->blocks.maxbits - 1000) )
                        iguana_recvalloc(coin,height + 100000);
                    decode_hex(allhash.bytes,sizeof(allhash),line+k+1 + 64 + 1);
                    init_hexbytes_noT(checkstr,allhash.bytes,sizeof(allhash));
                    //printf("parseline: k.%d %d height.%d m.%d bundlesize.%d (%s) check.(%s)\n",k,line[k],height,m,coin->chain->bundlesize,&line[k+1+65],checkstr);// + strlen(line+k+1)]);
                    if ( strncmp(checkstr,line+k+1 + 64 + 1,64) == 0 )
                    {
                        init_hexbytes_noT(checkstr,hash2.bytes,sizeof(hash2));
                        if ( strlen(line+k+1 + 2*64 + 2) == sizeof(hash1)*2 )
                            decode_hex(hash1.bytes,sizeof(hash1),line+k+1 + 2*64 + 2);
                        else memset(hash1.bytes,0,sizeof(hash1));
                        //char str[65],str2[65]; printf(">>>> bundle.%d got (%s)/(%s) allhash.(%s)\n",height,bits256_str(str,hash1),checkstr,bits256_str(str2,allhash));
                        if ( (bp= iguana_bundlecreate(coin,&bundlei,height,hash2,allhash,0)) != 0 )
                        {
                            if ( bits256_cmp(allhash,bp->allhash) != 0 )
                            {
                                printf("mismatched allhash.[%d]\n",bp->hdrsi);
                                bp->allhash = allhash;
                            }
                            if ( height >= lastheight )
                            {
                                if ( iguana_bundleinitmap(coin,bp,height,hash2,hash1) == 0 )
                                    lastbundle = hash2, lastheight = height;
                            }
                        }
                    }
                }
            }
        }
        memset(line,0,sizeof(line));
    }
    if ( iter == 1 && bits256_nonz(lastbundle) != 0 )
    {
        printf("parseline ht.%d\n",lastheight);
        iguana_initfinal(coin,lastbundle);
    }
}

void iguana_ramchainpurge(struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_ramchain *ramchain)
{
    iguana_ramchain_free(coin,ramchain,1);
}

void iguana_bundlepurge(struct iguana_info *coin,struct iguana_bundle *bp)
{
    int32_t i; static const bits256 zero;
    iguana_ramchainpurge(coin,bp,&bp->ramchain);
    if ( bp->speculative != 0 )
    {
        for (i=0; i<bp->n; i++)
            if ( bp->speculativecache[i] != 0 )
            {
                myfree(bp->speculativecache[i],*(int32_t *)bp->speculativecache[i]);
                bp->speculativecache[i] = 0;
            }
        myfree(bp->speculative,sizeof(*bp->speculative) * bp->numspec);
    }
    bp->numspec = 0;
    bp->speculative = 0;
    memset(bp->hashes,0,sizeof(bp->hashes));
    memset(bp->issued,0,sizeof(bp->issued));
    bp->prevbundlehash2 = bp->nextbundlehash2 = bp->allhash = zero;
}

void iguana_blockpurge(struct iguana_info *coin,struct iguana_block *block)
{
    if ( block->req != 0 )
    {
        printf("purge req inside block\n");
        myfree(block->req,block->req->allocsize);
    }
    free(block);
}

void iguana_blockspurge(struct iguana_info *coin)
{
    struct iguana_block *block,*tmp;
    if ( 1 && coin->blocks.hash != 0 )
    {
        HASH_ITER(hh,coin->blocks.hash,block,tmp)
        {
            HASH_DEL(coin->blocks.hash,block);
            iguana_blockpurge(coin,block);
        }
        coin->blocks.hash = 0;
    }
    if ( coin->blocks.RO != 0 )
    {
        myfree(coin->blocks.RO,coin->blocks.maxbits * sizeof(*coin->blocks.RO));
        coin->blocks.RO = 0;
    }
    coin->blocks.maxbits = coin->blocks.maxblocks = coin->blocks.initblocks = coin->blocks.hashblocks = coin->blocks.issuedblocks = coin->blocks.recvblocks = coin->blocks.emitblocks = coin->blocks.parsedblocks = coin->blocks.dirty = 0;
    memset(&coin->blocks.hwmchain,0,sizeof(coin->blocks.hwmchain));
}

void iguana_coinpurge(struct iguana_info *coin)
{
    int32_t i,saved; struct iguana_bundle *bp; char *hashstr; struct iguana_bundlereq *req; struct iguana_blockreq *breq; struct iguana_helper *ptr;
    saved = coin->active, coin->active = 0;
    coin->started = 0;
    while ( coin->idletime == 0 && coin->emitbusy > 0 )
    {
        printf("coinpurge.%s waiting for idle %lu emitbusy.%d\n",coin->symbol,time(NULL),coin->emitbusy);
        sleep(1);
    }
    coin->RTgenesis = 0;
    while ( (ptr= queue_dequeue(&bundlesQ,0)) != 0 )
        myfree(ptr,ptr->allocsize);
    if ( 1 )
    {
        while ( (hashstr= queue_dequeue(&coin->hdrsQ,1)) != 0 )
            free_queueitem(hashstr);
        while ( (breq= queue_dequeue(&coin->blocksQ,0)) != 0 )
            myfree(breq,sizeof(*breq));
        while ( (breq= queue_dequeue(&coin->priorityQ,0)) != 0 )
            myfree(breq,sizeof(*breq));
        while ( (req= queue_dequeue(&coin->cacheQ,0)) != 0 )
            myfree(req,req->allocsize);
        while ( (req= queue_dequeue(&coin->recvQ,0)) != 0 )
        {
            if ( req->blocks != 0 )
                myfree(req->blocks,sizeof(*req->blocks) * req->n), req->blocks = 0;
            if ( req->hashes != 0 )
                myfree(req->hashes,sizeof(*req->hashes) * req->n), req->hashes = 0;
            myfree(req,req->allocsize);
        }
    }
    iguana_RTramchainfree(coin,coin->current);
    coin->bundlescount = 0;
    for (i=0; i<coin->bundlescount; i++)
        if ( (bp= coin->bundles[i]) != 0 )
            iguana_bundlepurge(coin,bp);
    coin->current = coin->lastpending = 0;
    memset(coin->bundles,0,sizeof(coin->bundles));
    iguana_blockspurge(coin);
    coin->active = saved;
}

struct iguana_info *iguana_coinstart(struct iguana_info *coin,int32_t initialheight,int32_t mapflags)
{
    FILE *fp; char fname[512],*symbol; int32_t iter; long fpos; bits256 lastbundle; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    coin->sleeptime = 10000;
    symbol = coin->symbol;
    if ( iguana_peerslotinit(coin,&coin->internaladdr,IGUANA_MAXPEERS,calc_ipbits("127.0.0.1:7777")) < 0 )
    {
        printf("iguana_coinstart: error creating peerslot\n");
        return(0);
    }
    if ( initialheight < coin->chain->bundlesize*10 )
        initialheight = coin->chain->bundlesize*10;
    iguana_recvalloc(coin,initialheight);
    if ( coin->longestchain == 0 )
        coin->longestchain = 1;
    memset(&coin->blocks.hwmchain,0,sizeof(coin->blocks.hwmchain));
    coin->blocks.hwmchain.height = 0;
    printf("%s MYSERVICES.%llx\n",coin->symbol,(long long)coin->myservices);
    if ( (coin->myservices & NODE_NETWORK) != 0 && coin->peers.acceptloop == 0 && coin->peers.localaddr == 0 )
    {
        coin->peers.acceptloop = malloc(sizeof(pthread_t));
        if ( OS_thread_create(coin->peers.acceptloop,NULL,(void *)iguana_acceptloop,(void *)coin) != 0 )
        {
            free(coin->peers.acceptloop);
            coin->peers.acceptloop = 0;
            printf("error launching accept thread for port.%u\n",coin->chain->portp2p);
        }
    }
    if ( coin->rpcloop == 0 )
    {
        myinfo->rpcport = coin->chain->rpcport;
        coin->rpcloop = malloc(sizeof(pthread_t));
        if ( OS_thread_create(coin->rpcloop,NULL,(void *)iguana_rpcloop,(void *)myinfo) != 0 )
        {
            free(coin->rpcloop);
            coin->rpcloop = 0;
            printf("error launching rpcloop for %s port.%u\n",coin->symbol,coin->chain->rpcport);
        }
    }
    //coin->firstblock = coin->blocks.parsedblocks + 1;
    iguana_genesis(coin,coin->chain);
    memset(&lastbundle,0,sizeof(lastbundle));
    for (iter=coin->peers.numranked>8; iter<2; iter++)
    {
#ifdef __PNACL__
        if ( iter == 0 )
        {
            char **ipaddrs = 0; int32_t j,num;
            char *BTC_ipaddrs[] = { "5.9.102.210", "130.211.146.81", "1176.9.29.76", "108.58.252.82", "148.251.151.48", "74.207.233.193" };
            char *BTCD_ipaddrs[] = { "5.9.102.210", "89.248.160.236", "89.248.160.237", "89.248.160.238", "89.248.160.239", "89.248.160.240", "89.248.160.241", "89.248.160.242", "89.248.160.243", "89.248.160.244", "89.248.160.245", "78.47.58.62", "67.212.70.88", "94.102.50.69", "50.179.58.158", "194.135.94.30", "109.236.85.42", "104.236.127.154", "68.45.147.145", "37.59.14.7", "78.47.115.250", "188.40.138.8", "62.75.143.120", "82.241.71.230", "217.23.6.2", "73.28.172.128", "45.55.149.34", "192.0.242.54", "81.181.155.53", "91.66.185.97", "85.25.217.233", "144.76.239.66", "95.80.9.112", "80.162.193.118", "173.65.129.85", "2.26.173.58", "78.14.250.69", "188.226.253.77", "58.107.67.39", "124.191.37.212", "176.226.137.238", "69.145.25.85", "24.168.14.28", "73.201.180.47", "76.188.171.53", "63.247.147.166", "121.108.241.247", "36.74.36.125", "106.186.119.171", "188.166.91.37", "223.134.228.208", "89.248.160.244", "178.33.209.212", "71.53.156.38", "88.198.10.165", "24.117.221.0", "74.14.104.57", "158.69.27.82", "110.174.129.213", "75.130.163.51" };
            if ( strcmp(coin->symbol,"BTCD") == 0 )
                ipaddrs = BTCD_ipaddrs, num = (int32_t)(sizeof(BTCD_ipaddrs)/sizeof(*BTCD_ipaddrs));
            else if ( strcmp(coin->symbol,"BTC") == 0 )
                ipaddrs = BTC_ipaddrs, num = (int32_t)(sizeof(BTC_ipaddrs)/sizeof(*BTC_ipaddrs));
            if ( ipaddrs != 0 )
            {
                for (j=0; j<num; j++)
                {
                    //printf("%s ",ipaddrs[j]);
                    if ( 0 && j < IGUANA_MINPEERS )
                        iguana_launchpeer(coin,ipaddrs[j]);
                    else iguana_possible_peer(coin,ipaddrs[j]);
                }
            }
        }
        else
        {
#include "confs/BTCD_hdrs.h"
            if ( strcmp(coin->symbol,"BTCD") == 0 )
            {
                bits256 hash2,allhash,hash1; int32_t bundlei,i,nonz,height; struct iguana_bundle *bp;
                for (i=nonz=0; i<sizeof(BTCD_hdrs)/sizeof(*BTCD_hdrs); i++)
                {
                    height = atoi(BTCD_hdrs[i][0]);
                    if ( height > (coin->blocks.maxbits - 1000) )
                        iguana_recvalloc(coin,height + 100000);
                    hash2 = bits256_conv(BTCD_hdrs[i][1]);
                    if ( BTCD_hdrs[i][2][0] != 0 )
                        allhash = bits256_conv(BTCD_hdrs[i][2]);
                    if ( BTCD_hdrs[i][3][0] != 0 )
                        hash1 = bits256_conv(BTCD_hdrs[i][3]);
                    if ( (bp= iguana_bundlecreate(coin,&bundlei,height,hash2,allhash,0)) != 0 )
                    {
                        if ( iguana_bundleinitmap(coin,bp,height,hash2,hash1) == 0 )
                            lastbundle = hash2, nonz++;
                    }
                }
                printf("H file.[%d] nonz.%d\n",i,nonz);
                //if ( bits256_nonz(lastbundle) != 0 )
                //    iguana_initfinal(coin,lastbundle);
                //break;
            }
        }
#endif
        sprintf(fname,"%s/%s_%s.txt",GLOBAL_CONFSDIR,coin->symbol,(iter == 0) ? "peers" : "hdrs"), OS_compatible_path(fname);
        //sprintf(fname,"confs/%s_%s.txt",coin->symbol,(iter == 0) ? "peers" : "hdrs");
        //sprintf(fname,"tmp/%s/%s.txt",coin->symbol,(iter == 0) ? "peers" : "hdrs");
        OS_compatible_path(fname);
        printf("parsefile.%d %s\n",iter,fname);
        if ( (fp= fopen(fname,"r")) != 0 )
        {
            iguana_parseline(coin,iter,fp);
            fpos = ftell(fp);
            fclose(fp);
        } else fpos = -1;
        printf("done parsefile.%d (%s) size.%ld\n",iter,fname,fpos);
    }
#ifndef IGUANA_DEDICATED_THREADS
    coin->peers.peersloop = iguana_launch("peersloop",iguana_peersloop,coin,IGUANA_PERMTHREAD);
#endif
    printf("started.%s %p active.%d\n",coin->symbol,coin->started,coin->active);
    return(coin);
}
