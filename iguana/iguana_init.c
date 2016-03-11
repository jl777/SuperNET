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
    queue_enqueue(name,Q,queueitem(str),1);
    if ( (tst= queue_dequeue(Q,1)) != 0 )
        free_queueitem(tst);
}

void iguana_initQs(struct iguana_info *coin)
{
    int32_t i;
    iguana_initQ(&coin->acceptQ,"acceptQ");
    iguana_initQ(&coin->bundlesQ,"bundlesQ");
    iguana_initQ(&coin->hdrsQ,"hdrsQ");
    iguana_initQ(&coin->blocksQ,"blocksQ");
    iguana_initQ(&coin->priorityQ,"priorityQ");
    iguana_initQ(&coin->possibleQ,"possibleQ");
    iguana_initQ(&coin->cacheQ,"cacheQ");
    iguana_initQ(&coin->TerminateQ,"TerminateQ");
    for (i=0; i<IGUANA_MAXPEERS; i++)
        iguana_initQ(&coin->peers.active[i].sendQ,"addrsendQ");
}

void iguana_initpeer(struct iguana_info *coin,struct iguana_peer *addr,uint64_t ipbits)
{
    memset(addr,0,sizeof(*addr));
    addr->ipbits = ipbits;
    addr->usock = -1;
    expand_ipbits(addr->ipaddr,addr->ipbits);
    //addr->pending = (uint32_t)time(NULL);
    strcpy(addr->symbol,coin->symbol);
    strcpy(addr->coinstr,coin->name);
    iguana_initQ(&addr->sendQ,"addrsendQ");
}

void iguana_initcoin(struct iguana_info *coin,cJSON *argjson)
{
    int32_t i; char dirname[512];
    //sprintf(dirname,"tmp/%s",coin->symbol), OS_portable_path(dirname);
    //OS_portable_rmdir(dirname,0);
    portable_mutex_init(&coin->peers_mutex);
    portable_mutex_init(&coin->blocks_mutex);
    portable_mutex_init(&coin->scripts_mutex[0]);
    portable_mutex_init(&coin->scripts_mutex[1]);
    iguana_meminit(&coin->blockMEM,"blockMEM",coin->blockspace,sizeof(coin->blockspace),0);
    iguana_initQs(coin);
    coin->bindsock = -1;
    OS_randombytes((unsigned char *)&coin->instance_nonce,sizeof(coin->instance_nonce));
    coin->startutc = (uint32_t)time(NULL);
    while ( time(NULL) == coin->startutc )
        usleep(1);
    coin->startmillis = OS_milliseconds(), coin->starttime = tai_now(coin->startmillis);
    coin->avetime = 1 * 100;
    //coin->R.maxrecvbundles = IGUANA_INITIALBUNDLES;
    for (i=0; i<IGUANA_MAXPEERS; i++)
        coin->peers.active[i].usock = -1;
    // validate blocks
    //for (i=0; i<IGUANA_NUMAPPENDS; i++)
    //    vupdate_sha256(coin->latest.lhashes[i].bytes,&coin->latest.states[i],0,0);
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
    //coin->latest.dep.numtxids =
    block.RO.txn_count = 1;
    block.RO.numvouts = 1;
    iguana_gotdata(coin,0,0);
    if ( (ptr= iguana_blockhashset(coin,0,hash2,1)) != 0 )
    {
        ptr->mainchain = 1;
        iguana_blockcopy(coin,ptr,&block);
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
    static bits256 zero;
    iguana_bundlecreate(coin,&bundlei,0,hash2,zero,1);
    _iguana_chainlink(coin,iguana_blockfind(coin,hash2));
    return(hash2);
}

int32_t iguana_savehdrs(struct iguana_info *coin)
{
    int32_t height,i,n,retval = 0; char fname[512],shastr[65],tmpfname[512],str[65],oldfname[512];
    bits256 hash2,sha256all,*hashes; FILE *fp;
    n = coin->blocks.hwmchain.height + 1;
    hashes = mycalloc('h',coin->chain->bundlesize,sizeof(*hashes));
    sprintf(oldfname,"confs/%s_oldhdrs.txt",coin->symbol), OS_compatible_path(oldfname);
    sprintf(tmpfname,"tmp/%s/hdrs.txt",coin->symbol), OS_compatible_path(tmpfname);
    sprintf(fname,"confs/%s_hdrs.txt",coin->symbol), OS_compatible_path(fname);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        fprintf(fp,"%d\n",n);
        for (height=0; height<=n; height+=coin->chain->bundlesize)
        {
            for (i=0; i<coin->chain->bundlesize; i++)
            {
                hashes[i] = iguana_blockhash(coin,height+i);
                if ( bits256_str(str,hashes[i]) == 0 )
                    break;
            }
            if ( i == coin->chain->bundlesize )
            {
                struct iguana_bundle *bp;
                if ( (bp= coin->bundles[height/coin->chain->bundlesize]) != 0 )
                {
                    if ( bits256_nonz(bp->allhash) == 0 )
                    {
                        vcalc_sha256(shastr,sha256all.bytes,hashes[0].bytes,sizeof(*hashes) * coin->chain->bundlesize);
                        bp->allhash = sha256all;
                    }
                    else
                    {
                        sha256all = bp->allhash;
                        bits256_str(shastr,bp->allhash);
                    }
                }
            } else shastr[0] = 0;
            hash2 = iguana_blockhash(coin,height);
            if ( bits256_nonz(hash2) > 0 )
            {
                fprintf(fp,"%d %s %s\n",height,bits256_str(str,hash2),shastr);
                retval = height;
            }
        }
        //printf("new hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
        if ( ftell(fp) > OS_filesize(fname) )
        {
            printf("new hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)OS_filesize(fname));
            fclose(fp);
            OS_renamefile(fname,oldfname);
            OS_copyfile(tmpfname,fname,1);
        } else fclose(fp);
    }
    myfree(hashes,coin->chain->bundlesize * sizeof(*hashes));
    return(retval);
}

void iguana_parseline(struct iguana_info *coin,int32_t iter,FILE *fp)
{
    int32_t i,j,k,m,c,height,flag,bundlei; char checkstr[1024],line[1024];
    struct iguana_peer *addr; struct iguana_bundle *bp; bits256 allhash,hash2,zero,lastbundle;
    struct iguana_block *block;
    memset(&zero,0,sizeof(zero));
    lastbundle = zero;
    if ( iter == 1 )
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
                    printf("call initpeer.(%s)\n",addr->ipaddr);
                    iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
                }
#ifndef IGUANA_DISABLEPEERS
                addr = &coin->peers.active[m++];
                iguana_initpeer(coin,addr,(uint32_t)calc_ipbits(line));
                printf("call initpeer.(%s)\n",addr->ipaddr);
                iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
#endif
            }
        }
        else
        {
            for (k=height=0; k<j-1; k++)
            {
                if ( (c= line[k]) == ' ' )
                    break;
                else if ( c >= '0' && c <= '9' )
                    height = (height * 10) + (line[k] - '0');
                else break;
            }
            //printf("parseline: k.%d %d height.%d m.%d bundlesize.%d (%s)\n",k,line[k],height,m,coin->chain->bundlesize,&line[k+1+65]);// + strlen(line+k+1)]);
            if ( line[k] == ' ' )
            {
                decode_hex(hash2.bytes,sizeof(hash2),line+k+1);
                if ( line[k+1 + 65] != 0 )
                {
                    if ( height > (coin->blocks.maxbits - 1000) )
                        iguana_recvalloc(coin,height + 100000);
                    decode_hex(allhash.bytes,sizeof(allhash),line+k+1 + 64 + 1);
                    init_hexbytes_noT(checkstr,allhash.bytes,sizeof(allhash));
                    if ( strcmp(checkstr,line+k+1 + 64 + 1) == 0 )
                    {
                        init_hexbytes_noT(checkstr,hash2.bytes,sizeof(hash2));
                        //char str[65],str2[65]; printf(">>>> bundle.%d got (%s)/(%s) allhash.(%s)\n",height,bits256_str(str,hash2),checkstr,bits256_str(str2,allhash));
                        if ( (bp= iguana_bundlecreate(coin,&bundlei,height,hash2,allhash,0)) != 0 )
                        {
                            bp->bundleheight = height;
                            lastbundle = hash2;
                            if ( (block= iguana_blockfind(coin,hash2)) != 0 )
                                block->mainchain = 1, block->height = height;
                            if ( iguana_bundleload(coin,bp) != 0 )
                            {
                                bp->emitfinish = (uint32_t)time(NULL) + 1;
                                //printf("LOADED bundle.%d\n",bp->bundleheight);
                                if ( bp->hdrsi == 0 || coin->bundles[bp->hdrsi-1]->emitfinish != 0 )
                                {
                                    bp->startutxo = (uint32_t)time(NULL);
                                    printf("GENERATE UTXO, verify sigs, etc for ht.%d\n",bp->bundleheight);
                                    iguana_bundleQ(coin,bp,1000);
                                }
                            }
                            else
                            {
                                char str[65];
                                init_hexbytes_noT(str,hash2.bytes,sizeof(hash2));
                                bp->emitfinish = 0;
                                iguana_blockQ(coin,bp,0,hash2,1);
                                queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
                            }
                        }
                    }
                }
            }
        }
    }
    if ( bits256_nonz(lastbundle) > 0 )
    {
        char hashstr[65];
        init_hexbytes_noT(hashstr,lastbundle.bytes,sizeof(bits256));
        printf("req lastbundle.(%s)\n",hashstr);
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
    }
    if ( iter == 1 )
    {
        for (i=0; i<coin->bundlescount; i++)
            if ( coin->bundles[i] == 0 )
                break;
        if ( i > 0 )
        {
            //iguana_spentsfile(coin,i);
        }
    }
}

struct iguana_info *iguana_coinstart(struct iguana_info *coin,int32_t initialheight,int32_t mapflags)
{
    FILE *fp; char fname[512],*symbol; int32_t iter;
    coin->sleeptime = 10000;
    symbol = coin->symbol;
    if ( initialheight < coin->chain->bundlesize*10 )
        initialheight = coin->chain->bundlesize*10;
    iguana_recvalloc(coin,initialheight);
    coin->longestchain = 1;
    coin->blocks.hwmchain.height = 0;
    if ( (coin->myservices & NODE_NETWORK) != 0 )
    {
        printf("MYSERVICES.%llx\n",(long long)coin->myservices);
        coin->peers.acceptloop = malloc(sizeof(pthread_t));
        if ( OS_thread_create(coin->peers.acceptloop,NULL,(void *)iguana_acceptloop,(void *)coin) != 0 )
        {
            free(coin->peers.acceptloop);
            coin->peers.acceptloop = 0;
            printf("error launching accept thread for port.%u\n",coin->chain->portp2p);
        }
    }
    coin->firstblock = coin->blocks.parsedblocks + 1;
    iguana_genesis(coin,coin->chain);
    for (iter=0; iter<2; iter++)
    {
        sprintf(fname,"confs/%s_%s.txt",coin->symbol,(iter == 0) ? "peers" : "hdrs");
        OS_compatible_path(fname);
        printf("parsefile.%d %s\n",iter,fname);
        if ( (fp= fopen(fname,"r")) != 0 )
        {
            iguana_parseline(coin,iter,fp);
            fclose(fp);
        }
        printf("done parsefile.%d\n",iter);
    }
#ifndef IGUANA_DEDICATED_THREADS
    coin->peers.peersloop = iguana_launch("peersloop",iguana_peersloop,coin,IGUANA_PERMTHREAD);
#endif
    if ( 0 && (coin->MAXBUNDLES= coin->bundlescount / 4) < _IGUANA_MAXBUNDLES )
        coin->MAXBUNDLES = _IGUANA_MAXBUNDLES;
    printf("started.%s\n",coin->symbol);
    return(coin);
}
